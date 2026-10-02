/**
 * Adapter Lambda entrypoint for deployers who expose this via Function URL,
 * API Gateway, or direct invoke. Core auth stays in Cognito triggers
 * (`functions/auth`); this is not a client SDK.
 *
 * Set env `DEBUG=true` (or `1` / `yes`) for verbose logs.
 */

function isDebug(): boolean {
  const value = (process.env.DEBUG ?? '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes' || value === 'debug';
}

function debug(message: string, data?: unknown): void {
  if (!isDebug()) return;
  if (data === undefined) {
    console.debug(`[api] ${message}`);
    return;
  }
  console.debug(`[api] ${message}`, typeof data === 'string' ? data : JSON.stringify(data));
}

export async function handler(event: unknown): Promise<{
  statusCode: number;
  body: string;
}> {
  debug('invoke', event);

  // TODO: map deployer-facing operations onto Cognito InitiateAuth /
  // RespondToAuthChallenge and return Cognito tokens.
  const response = {
    statusCode: 501,
    body: JSON.stringify({ error: 'Not implemented' }),
  };

  debug('response', response);
  return response;
}
