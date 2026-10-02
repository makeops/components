/**
 * @fileoverview Structured JSON logging for CloudWatch Logs Insights
 * (`{ $.level = "ERROR" }`, `{ $.component = "api" }`, …).
 */

export type LogLevel = 'DEBUG'|'INFO'|'WARN'|'ERROR';

function isDebugEnabled(): boolean {
  const value = (process.env.DEBUG ?? '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes' || value === 'debug';
}

function serializeError(err: unknown): Record<string, unknown> {
  if (err instanceof Error) {
    return {name: err.name, message: err.message, stack: err.stack};
  }
  if (err && typeof err === 'object') {
    try {
      return JSON.parse(JSON.stringify(err)) as Record<string, unknown>;
    } catch {
      return {message: String(err)};
    }
  }
  return {message: String(err)};
}

/**
 * Emits one JSON log line. Extra fields are nested under `data` so top-level
 * keys stay stable for CloudWatch `$` filters.
 */
export function log(
    level: LogLevel,
    component: string,
    message: string,
    data?: unknown,
    ): void {
  const entry: Record<string, unknown> = {level, component, message};
  if (data !== undefined) {
    entry.data = data instanceof Error ? serializeError(data) : data;
  }

  const line = JSON.stringify(entry);
  switch (level) {
    case 'ERROR':
      console.error(line);
      break;
    case 'WARN':
      console.warn(line);
      break;
    default:
      console.log(line);
  }
}

/** DEBUG-gated helper bound to a component name. */
export function createDebug(component: string): (message: string, data?: unknown) =>
    void {
  return (message, data) => {
    if (!isDebugEnabled()) {
      return;
    }
    log('DEBUG', component, message, data);
  };
}

export {isDebugEnabled};
