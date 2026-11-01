# WireGuard → sing-box

CLI для выпуска удалённых профилей через wg-easy и S3. Запуск через `tsx`, сборка не нужна. **S3 — источник опубликованного состояния; `artifacts/` — его скачанная рабочая копия.**

## Настройка

Нужны Node.js **24.22.1**, npm, wg-easy **14** и существующий бакет Yandex Object Storage. Команды выполняются из корня этого пакета.

```bash
npm ci
cp -n .env.example .env
chmod 600 .env
```

Пример `.env`:

```dotenv
WG_EASY_URL=https://wg.example.com
WG_EASY_PASSWORD="your-password"
S3_ACCESS_KEY_ID=your-static-access-key
S3_SECRET_ACCESS_KEY=your-static-secret-key
S3_ENDPOINT=https://storage.yandexcloud.net
S3_REGION=ru-central1
S3_BUCKET=your-bucket-name
VPN_RULES_URL=https://storage.yandexcloud.net/your-bucket-name/rules/vpn_rules.json
```

- **WG-доступ:** `WG_EASY_URL` — адрес админки, `WG_EASY_PASSWORD` — пароль входа.
- **S3-доступ:** обязательны `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_BUCKET`. Endpoint и регион по умолчанию — значения из примера. Загрузка требует права записи с ACL `public-read`; `configs:pull` и `rules:update` также требуют ListBucket.
- **URL rules:** для `provision` и `convert` обязателен `VPN_RULES_URL` либо флаг `--rules`. Значения по умолчанию нет. При смене бакета измените URL.
- `.env` загружается автоматически; переменные процесса имеют приоритет. Пароли с `#` заключайте в кавычки.

**Опубликованные WG- и sing-box-конфиги содержат приватный ключ WG и доступны без пароля.** Клиенту требуется ядро sing-box 1.14+; проверяемая версия — **1.14.4**.

## Список команд

| Команда | Назначение | Доступы |
|---|---|---|
| [`provision`](#provision) | Выпустить и опубликовать профиль целиком | WG + S3 |
| [`wg`](#wg) | Получить исходный WireGuard-конфиг | WG |
| [`convert`](#convert) | Преобразовать локальный WG в sing-box JSON | Не нужны; требуется URL rules |
| [`upload`](#upload) | Опубликовать готовые конфиги и страницу подключения | S3 |
| [`connect`](#connect) | Создать диплинк и локальный QR для готового URL | Не нужны |
| [`configs:pull`](#configspull) | Скачать профили и rules из S3 в artifacts | S3 |
| [`rules:update`](#rulesupdate) | Опубликовать rules, обновить профили и скачать снимок S3 | S3 |
| [`test`](#проверки) | Запустить тесты с локальными mocks | Не нужны |
| [`test:sing-box`](#проверки) | Проверить конфиги и rules настоящим ядром | Локальный бинарник |
| [`typecheck`](#проверки) | Проверить TypeScript без генерации файлов | Не нужны |

Флаги передаются **после `--`**: `npm run provision -- --name iphone`. У всех семи рабочих команд есть `-h, --help`.

Имена регистрозависимы. Префикс `sf-` добавляется один раз: `iphone` → `sf-iphone`, `sf-iphone` → `sf-iphone`. Разрешены латинские буквы, цифры, `_`, `-`; первый символ ввода — буква или цифра. Длина с префиксом — до 64 символов.

## provision

Находит или создаёт клиента wg-easy, скачивает WG, собирает sing-box JSON, публикует пять файлов и скачивает опубликованный профиль в artifacts. Повторный запуск использует того же клиента и те же URL.

| Флаг | Обязателен | Значение |
|---|---|---|
| `--name <name>` | Да | Имя профиля и клиента wg-easy с автоматическим `sf-` |
| `--client-id <id>` | Нет | Выбрать существующего клиента по ID; его имя должно совпадать с итоговым именем. Нужен при дубликатах имён |
| `--rules <url>` | Если нет `VPN_RULES_URL` | HTTPS URL rules; переопределяет окружение |

```bash
npm run provision -- --name iphone
npm run provision -- --name iphone --client-id CLIENT_ID
npm run provision -- --name iphone --rules https://example.com/vpn_rules.json
```

`CLIENT_ID` замените на реальный ID. Результат — JSON с `clientId`, `pageUrl`, `profileUrl`, `importUri`, URL остальных файлов и локальными путями. Откройте **`pageUrl`**, нажмите «Открыть в sing-box» или сканируйте QR, подтвердите импорт **Remote Profile**.

## wg

Находит или создаёт клиента в wg-easy и скачивает его `.conf` во временный каталог. В S3 ничего не публикует.

| Флаг | Обязателен | Значение |
|---|---|---|
| `--name <name>` | Да | Имя клиента с автоматическим `sf-` |
| `--client-id <id>` | Нет | Скачать конфиг существующего клиента; имя должно совпадать с итоговым `--name` |

```bash
npm run wg -- --name iphone
npm run wg -- --name iphone --client-id CLIENT_ID
```

Результат: `name`, `clientId`, `created` и `wireGuardPath`. При выборе по ID новый клиент не создаётся.

## convert

Преобразует локальный WG-конфиг в sing-box JSON.

| Флаг | Обязателен | Значение / по умолчанию |
|---|---|---|
| `--input <file>` | Да | Путь к исходному WG `.conf` |
| `--output <filename>` | Нет | Имя JSON **рядом с input**, без пути. По умолчанию `sf-sing.json` |
| `--name <name>` | Нет | Имя WG endpoint внутри JSON. По умолчанию `sf-vpn` |
| `--rules <url>` | Если нет `VPN_RULES_URL` | HTTPS URL rules; переопределяет окружение |

```bash
npm run convert -- --input ./vpn.conf --output sf-sing.json --name iphone
```

Перезапись input запрещена, включая файловые ссылки. Явный `--output` не получает префикс автоматически. Результат: `name` и `singBoxPath`. Для последующего upload используйте такое же имя.

## upload

Публикует готовые конфиги, QR, HTML и data.json. После публикации скачивает профиль из S3 в artifacts. Содержимое конфигов, включая имя WG endpoint, не изменяется; приватные ключи WG в них должны совпадать.

| Флаг | Обязателен | Значение |
|---|---|---|
| `--input <file>` | Да | Путь к готовому sing-box JSON |
| `--name <name>` | Да | Имя remote profile и папки в S3, с автоматическим `sf-` |
| `--wireguard <file>` | Для первого импорта или если исходника нет в S3 | Путь к WG `.conf`. Без флага WG и clientId берутся из S3, из `wireguard.conf` и `data.json` |

```bash
# Первая публикация или восстановление из файлов
npm run upload -- --input ./sf-sing.json --wireguard ./vpn.conf --name iphone

# Обновление JSON уже опубликованного профиля
npm run upload -- --input ./sf-sing.json --name iphone
```

Результат содержит URL и локальные пути всех файлов, `importUri` и известный `clientId`. С явным `--wireguard` clientId не добавляется. Локальный artifacts не используется как неявный источник WG.

## connect

Создаёт диплинк и PNG QR для уже опубликованного профиля. Доступность URL не проверяет; файл по нему не скачивает.

| Флаг | Обязателен | Значение |
|---|---|---|
| `--url <url>` | Да | HTTPS URL sing-box JSON |
| `--name <name>` | Да | Имя при импорте, с автоматическим `sf-` |

```bash
npm run connect -- --url https://example.com/profiles/sf-iphone/sing-box.json --name iphone
```

Результат: `name`, `profileUrl`, `importUri`, `qrPath`. PNG сохраняется во временном каталоге операции.

## configs:pull

```bash
npm run configs:pull
```

Флагов, кроме `-h, --help`, нет. Скачивает все профили и общие rules. **Полностью заменяет artifacts снимком S3: локальные правки и устаревшие файлы исчезнут.** Замена выполняется после успешного скачивания всех файлов; при ошибке прежний снимок сохраняется.

Результат: `directory`, список `profiles`, `rulesPath`. Команда не пишет в S3 и не обращается к wg-easy.

## rules:update

Публикует локальные rules в прежний объект S3, меняет `v` в ссылках на эти rules внутри существующих профилей, затем выполняет `configs:pull`.

| Флаг | Обязателен | Значение / по умолчанию |
|---|---|---|
| `--input <file>` | Если нет скачанного файла rules | Исходный JSON rules. По умолчанию `artifacts/rules/vpn_rules.json` из последнего pull |

```bash
# Обычное обновление: сначала скачать, затем отредактировать, затем опубликовать
npm run configs:pull
# Отредактируйте artifacts/rules/vpn_rules.json
npm run rules:update

# Первый запуск с пустым бакетом или импорт явно выбранного файла
npm run rules:update -- --input ./rules/vpn_rules.json
```

Файл читается **до** публикации и финального pull. Если его нет, укажите `--input` или сначала выполните `configs:pull`. Репозиторный `rules/vpn_rules.json` — начальный набор; автоматически он не подставляется.

Версия выглядит как `?v=2026_11_01_17_30_15_123` — UTC без подписи; одна метка на запуск, старый `v` заменяется. В S3 обновляется общий файл rules и только ссылки в `sing-box.json`. QR, HTML, data.json и WG-конфиги не перезаписываются. Новые provision/convert автоматически `v` не добавляют.

Профили с другим URL rules, подписанными ссылками или query-параметрами кроме `v` пропускаются. Вывод: `rulesUrl`, `version`, `updated`, `skipped`, `failed`, `pull` и при ошибке скачивания `pullError`. При частичном сбое успешные изменения S3 сохраняются, код завершения ненулевой. Не меняйте те же профили одновременно через provision/upload.

После команды обновите Remote Profile в приложении: новые rules скачиваются при применении изменённого конфига. Неактивный профиль получит их при следующем запуске. Независимое часовое обновление rules остаётся резервным механизмом.

## Где лежат файлы

```text
S3                                  Локальный снимок
profiles/sf-iphone/                  artifacts/profiles/sf-iphone--<hex>/
  sing-box.json                       sing-box.json
  wireguard.conf                      wireguard.conf
  qr.png                              qr.png
  index.html                          index.html
  data.json                           data.json
rules/vpn_rules.json                 artifacts/rules/vpn_rules.json
```

Hex-суффикс различает регистр на macOS/Windows. `data.json` содержит имя, известный ID и публичные ссылки; локальных путей в нём нет. В artifacts нет служебных metadata. Файлы на POSIX имеют права `0600`, artifacts и `.env` исключены из Git.

При provision/upload промежуточные файлы и checkpoint находятся во временном каталоге. После успеха он удаляется; при ошибке путь выводится для восстановления. Можно повторить provision либо передать сохранённую пару файлов в upload. WG-клиенты автоматически не удаляются.

## Проверки

| Команда | Что проверяет |
|---|---|
| `npm run typecheck` | Исходники и тесты TypeScript, без создания JavaScript |
| `npm test` | Тесты на локальных mocks; реальные WG/S3 не нужны |
| `npm run test:sing-box` | Компиляцию rules и конфиги реальным ядром **1.14.4** |

```bash
# Отдельный тест
npm test -- test/config.test.ts

# Путь к бинарнику; без переменной используется sing-box из PATH
SING_BOX_BINARY=/absolute/path/to/sing-box npm run test:sing-box

# Справка рабочих команд
npm run provision -- --help
npm run rules:update -- --help
```

У команд проверок нет собственных флагов приложения: аргументы после `--` передаются Vitest или TypeScript. Их справка: `npm test -- --help`, `npm run typecheck -- --help`. Отсутствие ядра или другая версия — ошибка `test:sing-box`. Проверки не подтверждают работу VPN на реальных устройствах.
