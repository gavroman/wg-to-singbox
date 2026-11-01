// Only these errors are safe to show: never print response bodies or SDK errors.
export class UserError extends Error {}

export function invalidConfig(field: string): never {
  throw new UserError(`Невалидный конфиг: ${field}`);
}
