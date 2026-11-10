# VX-Underground Malware Analysis Downloader

Набор Python-скриптов для рекурсивной загрузки исследовательских материалов и образцов вредоносного ПО из раздела [Malware Analysis](https://vx-underground.org/) с последующей распаковкой архивов.

## Возможности

**`vx_download.py`**
- Рекурсивный обход каталогов VX-Underground.
- Загрузка PDF-отчётов и архивов с образцами.
- Сохранение оригинальной структуры каталогов.
- Возобновление загрузки после прерывания.
- Учёт обработанных файлов и каталогов в SQLite.
- Работа через Chrome и Playwright с использованием CDP.

**`unpack_7z.py`**
- Рекурсивный поиск и распаковка `.7z`.
- Поддержка архивов с паролем.
- Распаковка каждого архива в отдельный каталог.
- Пропуск ранее распакованных архивов.
- Сохранение исходных архивов.

## Требования

- Python 3.11+
- Google Chrome
- Python-пакеты: `playwright`, `httpx`, `py7zr`

Установка:

```bash
python3 -m pip install playwright httpx py7zr
```

## Загрузка файлов

### 1. Запуск Chrome

Для macOS:

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --remote-debugging-port=9222 \
  --user-data-dir="$HOME/.vx-chrome-profile"
```

Откройте https://vx-underground.org/ и при необходимости пройдите проверку Cloudflare вручную.

### 2. Запуск загрузчика

Весь раздел Malware Analysis:

```bash
python3 vx_download.py --root "Malware Analysis/"
```

Только материалы за 2026 год:

```bash
python3 vx_download.py --root "Malware Analysis/2026/"
```

Только PDF-отчёты:

```bash
python3 vx_download.py --root "Malware Analysis/" --papers-only
```

Предварительная проверка без скачивания:

```bash
python3 vx_download.py --root "Malware Analysis/" \
  --dry-run --max-dirs 10 --db vx-test.sqlite3
```

Файлы сохраняются в `vx-downloads/`. Состояние обхода хранится в SQLite, поэтому после прерывания загрузчик можно запустить повторно с теми же параметрами.

## Распаковка архивов

Рекурсивная распаковка `.7z` с паролем `infected`:

```bash
python3 unpack_7z.py vx-downloads --password infected
```

Предварительный просмотр:

```bash
python3 unpack_7z.py vx-downloads --dry-run
```

Принудительная повторная распаковка:

```bash
python3 unpack_7z.py vx-downloads --password infected --force
```

Каждый архив распаковывается в одноимённый каталог. Исходные архивы не удаляются.

## Безопасность

Архивы могут содержать действующие образцы вредоносного ПО. Рекомендуется работать с ними только в изолированной исследовательской среде.

Скрипты не предназначены для запуска извлечённых образцов.

## Примечания

- Скрипты не являются официальными инструментами VX-Underground.
- Для работы загрузчика требуется доступный Chrome с включённым CDP.
- При повторной проверке Cloudflare может потребоваться ручное вмешательство.
- Подписанные ссылки на файлы имеют ограниченный срок действия.
- Соблюдайте правила использования ресурса и ограничивайте частоту запросов.