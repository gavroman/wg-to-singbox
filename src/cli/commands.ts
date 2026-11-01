import { Command } from 'commander';
import type { handlers } from './handlers.js';

const RULES_HELP = 'HTTPS URL правил. Обязателен, если VPN_RULES_URL не задан в .env';
const NAME_HELP = 'К имени автоматически добавляется sf-: iphone → sf-iphone; повторный sf- не добавляется.\nДо 64 символов вместе с префиксом; латинские буквы, цифры, _ и -, первый символ ввода — буква или цифра. Регистр учитывается.';
const RULES_REQUIREMENT_HELP = 'Задайте VPN_RULES_URL в .env или передайте --rules. Значения по умолчанию нет.';

function addWgOptions(command: Command): Command {
  return command
    .requiredOption('--name <name>', 'Обязательный. Найти клиента с этим именем в wg-easy или создать нового')
    .option('--client-id <id>', 'Необязательный. Выбрать существующего клиента по ID; его имя должно совпадать с именем после добавления sf-');
}

export function createProgram(actions: ReturnType<typeof handlers>): Command {
  const program = new Command().name('sing-box-configs')
    .description('Выпуск Remote Profiles: wg-easy 14 → sing-box 1.14.4');
  program.exitOverride();
  // Configure before creating subcommands so they inherit safe error handling.
  program.configureOutput({ writeErr: () => {} });
  program.helpOption('-h, --help', 'Показать справку');

  addWgOptions(program.command('provision')
    .description('Выпустить профиль и загрузить sing-box JSON, WG-конфиг, QR, index.html и data.json в отдельную папку S3'))
    .option('--rules <url>', RULES_HELP)
    .addHelpText('after', `
Обычно достаточно:
  npm run provision -- --name iphone

При нескольких клиентах с одинаковым именем добавьте --client-id.
Повторный выпуск обновляет профиль по тому же URL в S3.
Нужны WG_EASY_URL, WG_EASY_PASSWORD, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY и S3_BUCKET в .env.
Папка S3: profiles/sf-<name>/; файлы sing-box.json, wireguard.conf, qr.png, index.html и data.json.
Результат: ID клиента, pageUrl страницы с QR и кнопками, URL всех файлов, диплинк и пути к локальным артефактам.
${RULES_REQUIREMENT_HELP}
${NAME_HELP}`)
    .action(actions.provision);

  addWgOptions(program.command('wg')
    .description('Найти или создать клиента в wg-easy и скачать его исходный WireGuard-конфиг'))
    .addHelpText('after', `
Примеры:
  npm run wg -- --name iphone
  npm run wg -- --name iphone --client-id CLIENT_ID

CLIENT_ID замените на ID из wg-easy. При выборе по ID новый клиент не создаётся.
Нужны только WG_EASY_URL и WG_EASY_PASSWORD в .env.
Результат: ID клиента и путь к .conf во временном каталоге операции.
${NAME_HELP}`)
    .action(actions.wg);

  program.command('convert').description('Преобразовать локальный WireGuard .conf в sing-box JSON')
    .requiredOption('--input <file>', 'Обязательный. Путь к исходному WireGuard .conf')
    .option('--output <filename>', 'Необязательный. Имя JSON-файла рядом с input; перезапись input запрещена', 'sf-sing.json')
    .option('--name <name>', 'Необязательный. Имя WG endpoint внутри sing-box JSON', 'sf-vpn')
    .option('--rules <url>', RULES_HELP)
    .addHelpText('after', `
Пример:
  npm run convert -- --input ./vpn.conf --output sf-sing.json --name iphone

Доступы к WG и S3 не нужны. Файл сохраняется рядом с input, а не в S3.
При последующем upload используйте такое же --name, чтобы имена совпадали.
${RULES_REQUIREMENT_HELP}
${NAME_HELP}`)
    .action(actions.convert);

  program.command('upload').description('Загрузить оба конфига, QR, index.html и data.json в папку профиля в S3')
    .requiredOption('--input <file>', 'Обязательный. Путь к готовому sing-box JSON')
    .requiredOption('--name <name>', 'Обязательный. Имя remote profile и папки profiles/sf-<name>/ в S3')
    .option('--wireguard <file>', 'Исходный WG .conf; без флага wireguard.conf и data.json скачиваются из S3')
    .addHelpText('after', `
Пример:
  npm run upload -- --input ./sf-sing.json --wireguard ./vpn.conf --name iphone

Нужны только настройки S3 в .env; S3_ENDPOINT должен быть HTTPS.
Оба конфига загружаются без изменения содержимого. Приватный ключ WG в них должен совпадать.
Без --wireguard нужны опубликованные wireguard.conf и data.json в S3 с тем же именем.
clientId берётся из data.json в S3; с явным --wireguard он не добавляется в data.json.
Повторная загрузка с тем же --name обновляет тот же URL.
Результат: URL sing-box.json, wireguard.conf, qr.png, index.html и data.json, pageUrl страницы, диплинк и локальные пути.
Команда подходит для восстановления после сбоя загрузки в provision.
${NAME_HELP}`)
    .action(actions.upload);

  program.command('connect').description('Создать диплинк и PNG QR для уже опубликованного удалённого профиля')
    .requiredOption('--url <url>', 'Обязательный. HTTPS URL опубликованного sing-box JSON')
    .requiredOption('--name <name>', 'Обязательный. Имя профиля при импорте в клиент и имя локального каталога артефактов')
    .addHelpText('after', `
Пример:
  npm run connect -- --url https://example.com/profiles/sf-iphone/sing-box.json --name iphone

Доступы к WG и S3 не нужны. Команда не скачивает и не проверяет доступность URL.
Результат: диплинк и путь к PNG QR во временном каталоге операции.
При открытии ссылки клиент sing-box добавляет Remote Profile.
Интервал обновления профиля задаётся в приложении, не в диплинке.
${NAME_HELP}`)
    .action(actions.connect);

  program.command('configs:pull').description('Скачать опубликованные профили и rules из S3 в artifacts')
    .addHelpText('after', `
Запуск:
  npm run configs:pull

S3 — источник опубликованного состояния. Команда скачивает все профили (по пять файлов) и rules.
artifacts полностью заменяется скачанным снимком; локальные правки в нём будут перезаписаны.
При ошибке скачивания прежний снимок сохраняется. Служебные metadata не создаются.
Нужны S3-ключи с правом ListBucket. Команда ничего не публикует и не обращается к WG.`)
    .action(actions.configsPull);

  program.command('rules:update').description('Опубликовать rules, обновить v в профилях и выполнить configs:pull')
    .option('--input <file>', 'Файл rules; по умолчанию artifacts/rules/vpn_rules.json из последнего configs:pull')
    .addHelpText('after', `
Обычный запуск после редактирования скачанных rules:
  npm run rules:update

Первоначальная публикация или явный импорт файла:
  npm run rules:update -- --input ./rules/vpn_rules.json

Публикует rules в тот же объект S3, затем меняет только URL rules в существующих sing-box.json.
Версия v: YYYY_MM_DD_HH_mm_ss_SSS (UTC без подписи). Новая генерация v не добавляет.
QR, HTML, data.json и WG-конфиг не перезаписываются в S3.
В конце выполняется configs:pull: artifacts получает фактическое состояние S3.
Нужны S3-ключи с ListBucket и загрузкой объектов. К WG-серверу не обращается.
Чужие источники rules, подписанные URL и другие query-параметры пропускаются.
При частичном сбое код завершения ненулевой; успешные изменения в S3 сохраняются.
Выполняйте последовательно, без одновременного provision/upload тех же профилей.
В приложении обновите Remote Profile; при применении конфига ядро скачает новые rules.`)
    .action(actions.rulesUpdate);

  return program;
}
