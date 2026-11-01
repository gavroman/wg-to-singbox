import { CommanderError } from 'commander';
import { loadEnvironment } from '../config/index.js';
import { formatJson } from '../artifacts/files.js';
import { UserError } from '../shared/errors.js';
import { handlers } from './handlers.js';
import { createProgram } from './commands.js';

export async function runCli(argv: string[]): Promise<number> {
  try {
    const actions = handlers(loadEnvironment(), value => process.stdout.write(formatJson(value)));
    const program = createProgram(actions);
    await program.parseAsync(argv, { from: 'user' });
    return 0;
  } catch (error) {
    if (error instanceof CommanderError && error.exitCode === 0) return 0;
    const message = error instanceof UserError ? error.message : error instanceof CommanderError
      ? 'Некорректные аргументы. Используйте --help.' : 'Операция не выполнена. Проверьте входные файлы и права доступа; завершённые этапы сохранены.';
    process.stderr.write(`Ошибка: ${message}\n`);
    return 1;
  }
}
