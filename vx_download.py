#!/usr/bin/env python3
"""Recursive VX-Underground downloader via an existing Chrome CDP session.

Only download materials you are authorized to access and store. Sample archives
are saved as-is; this tool never extracts or executes them.
"""

import argparse
import asyncio
import json
import logging
import os
import sqlite3
import time
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlparse

import httpx
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

BASE = "https://vx-underground.org/"
JS_LIST = r"""display => {
  const directories = [], files = [];
  for (const row of display.querySelectorAll('tr.group')) {
    const button = row.querySelector('button[phx-click]');
    if (button) {
      try {
        for (const [type, data] of JSON.parse(button.getAttribute('phx-click'))) {
          if (type === 'push' && data?.event === 'change-directory' &&
              typeof data?.value?.value === 'string') directories.push(data.value.value);
        }
      } catch (e) {}
    }
    const link = row.querySelector('a[aria-label^="Download "]');
    if (link) files.push({
      name: link.getAttribute('aria-label').replace(/^Download /, ''),
      url: link.href
    });
  }
  return {directories: [...new Set(directories)], files};
}"""


async def navigate_with_retry(page, url, retries=3):
    for attempt in range(retries):
        try:
            await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=60000,
            )
            return

        except PlaywrightTimeoutError:
            if attempt == retries - 1:
                raise

            delay = 5 * (2**attempt)
            print(
                f"[TIMEOUT] {url} "
                f"(попытка {attempt + 1}/{retries}), "
                f"повтор через {delay} с"
            )
            await asyncio.sleep(delay)


def safe_relative(path):
    """Reject absolute paths and traversal, including malicious filenames."""
    path = path.replace("\\", "/")
    parts = PurePosixPath(path).parts
    if (
        not parts
        or any(x in ("..", ".", "") for x in parts)
        or path.startswith("/")
        or "\x00" in path
    ):
        raise ValueError(f"Unsafe path: {path!r}")
    return Path(*parts)


def init_db(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute(
        'CREATE TABLE IF NOT EXISTS folders (path TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT "pending", attempts INTEGER NOT NULL DEFAULT 0, error TEXT)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, size INTEGER, status TEXT NOT NULL DEFAULT "pending", error TEXT)'
    )
    db.commit()
    return db


def enqueue(db, path):
    db.execute("INSERT OR IGNORE INTO folders(path) VALUES (?)", (path,))


def pending_folder(db):
    return db.execute(
        "SELECT path FROM folders WHERE status = 'pending' ORDER BY path LIMIT 1"
    ).fetchone()


async def wait_listing(page, timeout_ms):
    # Nonempty directories have rows; empty directories may have no table at all.
    # Require a connected LiveView and either actual rows or an explicit empty state.
    await page.wait_for_function(
        r"""() => {
      const d = document.querySelector('#file-display');
      if (!d || d.querySelector('[aria-busy="true"]')) return false;
      if (d.querySelector('tr.group')) return true;
      const text = (d.innerText || '').trim();
      const emptyText = /(?:no files|no items|empty directory|directory is empty|folder is empty|no results|папка пуста|каталог пуст)/i;
      if (emptyText.test(text)) return true;
      // Some empty directories render a complete table with zero data rows.
      const tbody = d.querySelector('table tbody');
      if (tbody && !tbody.querySelector('tr') &&
          !d.querySelector('[phx-update="ignore"]')) return true;
      return false;
    }""",
        timeout=timeout_ms,
    )
    await page.wait_for_timeout(150)


async def list_directory(page, folder, timeout_ms):
    await navigate_with_retry(
        page,
        BASE + quote(folder, safe="/"),
    )
    await wait_listing(page, timeout_ms)
    result = await page.locator("#file-display").evaluate(JS_LIST)
    # A redirected / challenged page must not be silently treated as empty.
    expected = urlparse(BASE + quote(folder, safe="/")).path.rstrip("/")
    actual = urlparse(page.url).path.rstrip("/")
    if actual != expected:
        raise RuntimeError(f"Unexpected redirect: {page.url}")
    for child in result["directories"]:
        if not child.startswith(folder) or child == folder:
            raise RuntimeError(f"Unexpected child path {child!r} under {folder!r}")
    return result


async def download(client, url, destination, retries, delay):
    if urlparse(url).hostname != "s3.us-east-005.backblazeb2.com":
        raise ValueError(f"Unexpected download host: {urlparse(url).hostname}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    part = destination.with_name(destination.name + ".part")
    for attempt in range(retries):
        offset = part.stat().st_size if part.exists() else 0
        headers = {"Range": f"bytes={offset}-"} if offset else {}
        try:
            async with client.stream("GET", url, headers=headers) as response:
                if response.status_code in (401, 403):
                    raise PermissionError(
                        f"HTTP {response.status_code}: signed URL may have expired"
                    )
                if response.status_code == 416 and offset:
                    # Cannot assume the partial file is complete; start over.
                    part.unlink(missing_ok=True)
                    continue
                response.raise_for_status()
                append = offset > 0 and response.status_code == 206
                if append:
                    content_range = response.headers.get("content-range", "")
                    if not content_range.startswith(f"bytes {offset}-"):
                        raise RuntimeError(f"Unexpected Content-Range: {content_range}")
                expected = response.headers.get("content-length")
                expected = int(expected) if expected and expected.isdigit() else None
                received = 0
                with part.open("ab" if append else "wb") as out:
                    async for chunk in response.aiter_bytes(1024 * 1024):
                        out.write(chunk)
                        received += len(chunk)
                if expected is not None and received != expected:
                    raise OSError(f"Incomplete response: {received}/{expected} bytes")
                os.replace(part, destination)
                return destination.stat().st_size
        except PermissionError:
            raise
        except (httpx.HTTPError, OSError, RuntimeError) as exc:
            if attempt == retries - 1:
                raise
            logging.warning("Download retry %d/%d: %s", attempt + 1, retries, exc)
            await asyncio.sleep(delay * (attempt + 1))
    raise RuntimeError("Download retries exhausted")


async def process_folder(page, client, db, folder, args):
    # Reopen the folder to refresh short-lived signed URLs.
    result = await list_directory(page, folder, args.timeout * 1000)
    for child in result["directories"]:
        if args.papers_only and child.rstrip("/").split("/")[-1].lower() == "samples":
            continue
        if args.samples_only and child.rstrip("/").split("/")[-1].lower() in (
            "paper",
            "papers",
        ):
            continue
        enqueue(db, child)
    db.commit()
    for entry in result["files"]:
        name = entry["name"]
        if "/" in name or "\\" in name or name in (".", ".."):
            raise ValueError(f"Unsafe filename: {name!r}")
        relative = safe_relative(folder + name)
        target = args.output / relative
        row = db.execute(
            "SELECT size, status FROM files WHERE path=?", (str(relative),)
        ).fetchone()
        if (
            target.is_file()
            and target.stat().st_size > 0
            and (not row or row[0] is None or target.stat().st_size == row[0])
        ):
            db.execute(
                'INSERT OR REPLACE INTO files(path,size,status,error) VALUES (?, ?, "done", NULL)',
                (str(relative), target.stat().st_size),
            )
            logging.info("[SKIP] %s", relative)
            continue
        if args.dry_run:
            logging.info("[FOUND] %s", relative)
            db.execute("INSERT OR IGNORE INTO files(path) VALUES (?)", (str(relative),))
            continue
        try:
            size = await download(
                client, entry["url"], target, args.retries, args.delay
            )
        except PermissionError:
            # Fetch a new signed URL for this folder, then retry once.
            fresh = await list_directory(page, folder, args.timeout * 1000)
            replacement = next(
                (f["url"] for f in fresh["files"] if f["name"] == name), None
            )
            if not replacement:
                raise RuntimeError(f"File disappeared after URL refresh: {name}")
            size = await download(client, replacement, target, args.retries, args.delay)
        except Exception as exc:
            db.execute(
                'INSERT OR REPLACE INTO files(path,status,error) VALUES (?, "failed", ?)',
                (str(relative), str(exc)),
            )
            db.commit()
            raise
        db.execute(
            'INSERT OR REPLACE INTO files(path,size,status,error) VALUES (?, ?, "done", NULL)',
            (str(relative), size),
        )
        db.commit()
        logging.info("[OK] %s (%d bytes)", relative, size)
    db.commit()
    return len(result["directories"]), len(result["files"])


async def main(args):
    if args.papers_only and args.samples_only:
        raise SystemExit("Choose at most one of --papers-only and --samples-only")
    root = args.root.strip("/") + "/"
    safe_relative(root)
    db = init_db(args.db)
    enqueue(db, root)
    # Requeue failures from previous runs; never retry them in a tight loop.
    db.execute("UPDATE folders SET status='pending' WHERE status='failed'")
    db.commit()
    async with async_playwright() as pw:
        browser = await pw.chromium.connect_over_cdp(args.cdp)
        context = browser.contexts[0]
        page = next((p for p in context.pages if "vx-underground.org" in p.url), None)
        if page is None:
            page = await context.new_page()
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=httpx.Timeout(args.timeout, connect=20)
        ) as client:
            processed = 0
            while (row := pending_folder(db)) is not None:
                folder = row[0]
                try:
                    folders, files = await process_folder(
                        page, client, db, folder, args
                    )
                    db.execute(
                        'UPDATE folders SET status="done", error=NULL WHERE path=?',
                        (folder,),
                    )
                    db.commit()
                    processed += 1
                    logging.info(
                        "[DIR %d] %s | %d folders, %d files",
                        processed,
                        folder,
                        folders,
                        files,
                    )
                    if args.max_dirs and processed >= args.max_dirs:
                        break
                    await asyncio.sleep(args.delay)
                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    logging.error("[ERROR] %s: %s", folder, exc)
                    db.execute(
                        'UPDATE folders SET attempts=attempts+1, status="failed", error=? WHERE path=?',
                        (str(exc), folder),
                    )
                    db.commit()
                    # Continue with other folders. Failed folders are retried on next run.
                    continue
    db.close()
    logging.info("Finished this run. Restart the same command to resume.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", default="Malware Analysis/2026/", help="Remote directory path"
    )
    parser.add_argument("--output", type=Path, default=Path("vx-downloads"))
    parser.add_argument("--db", type=Path, default=Path("vx-progress.sqlite3"))
    parser.add_argument("--cdp", default="http://127.0.0.1:9222")
    parser.add_argument("--papers-only", action="store_true")
    parser.add_argument("--samples-only", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--max-dirs", type=int, default=0, help="Stop after N directories this run"
    )
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--delay", type=float, default=1.0)
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\nInterrupted; progress saved in SQLite.")
