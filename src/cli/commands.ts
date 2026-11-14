import { Command } from 'commander';
import type { handlers } from './handlers.js';

const NAME_HELP = 'Имя профиля/клиента; префикс sf- добавляется один раз.';
const RULES_HELP = 'HTTPS URL rules вместо routing.rulesUrl из приватного конфига.';

export function createProgram(actions: ReturnType<typeof handlers>): Command {
  const program = new Command().name('sing-box-configs')
    .description('wg-easy + 3x-ui → один Remote Profile sing-box 1.14.4');
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  program.helpOption('-h, --help', 'Показать справку');
  const configured = (name: string, description: string) => program.command(name).description(description)
    .option('--config <file>', 'Приватный JSON; иначе VPN_CONFIG из окружения или .env.');
  configured('config:check', 'Локально проверить приватный конфиг').action(actions.configCheck);
  configured('panels:check', 'Проверить доступ и inbound; ничего не создавать').action(actions.panelsCheck);
  configured('provision', 'Создать/пересобрать профиль и опубликовать JSON, connections, QR, страницу и data')
    .requiredOption('--name <name>', NAME_HELP)
    .option('--client-id <id>', 'ID существующего клиента единственной wg-easy панели')
    .option('--rules <url>', RULES_HELP)
    .option('--create-only', 'Запретить перезапись существующих объектов S3')
    .action(actions.provision);
  configured('wg', 'Получить WG-подключения как локальную JSON-мапку имя → URI')
    .requiredOption('--name <name>', NAME_HELP)
    .option('--connection <name>', 'Обработать только это WG-подключение')
    .option('--client-id <id>', 'ID клиента единственной выбранной wg-easy панели')
    .action(actions.wg);
  configured('convert', 'Локально преобразовать мапку, WG .conf или файл с одной URI')
    .requiredOption('--input <file>', 'Исходный файл')
    .option('--output <filename>', 'Имя результата рядом с input, без пути', 'sf-sing.json')
    .option('--name <name>', NAME_HELP, 'sf-vpn')
    .option('--rules <url>', RULES_HELP).action(actions.convert);
  configured('upload', 'Опубликовать готовый sing-box JSON и соответствующую мапку')
    .requiredOption('--input <file>', 'Готовый sing-box JSON')
    .requiredOption('--name <name>', NAME_HELP)
    .option('--connections <file>', 'Мапка подключений; иначе читать connections.json из S3')
    .option('--create-only', 'Запретить перезапись существующих объектов S3')
    .action(actions.upload);
  configured('profiles:list', 'Показать опубликованные профили и имена подключений').action(actions.profilesList);
  configured('profiles:update', 'Пересобрать существующие профили выбранного S3')
    .requiredOption('--all', 'Применить выбранный конфиг ко всем профилям')
    .option('--rules <url>', RULES_HELP).action(actions.profilesUpdate);
  configured('configs:pull', 'Скачать S3 в artifacts; заменить локальный снимок').action(actions.configsPull);
  configured('rules:update', 'Опубликовать rules, обновить ?v в профилях и скачать снимок')
    .option('--input <file>', 'Rules JSON; иначе файл из снимка выбранного S3').action(actions.rulesUpdate);
  program.command('connect').description('Создать диплинк и QR для готового URL; конфиг не требуется')
    .requiredOption('--url <url>', 'HTTPS URL sing-box JSON')
    .requiredOption('--name <name>', NAME_HELP).action(actions.connect);
  return program;
}
