/**
 * @fileoverview Adapter Lambda entrypoint for Function URL, API Gateway, or
 * direct invoke. Core auth lives in Cognito triggers under functions/auth.
 *
 * Set env DEBUG=true (or 1 / yes) for verbose logs.
 */

interface ApiResponse {
  statusCode: number;
  body: string;
}

function isDebugEnabled(): boolean {
  const value = (process.env.DEBUG ?? '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes' || value === 'debug';
}

function debug(message: string, data?: unknown): void {
  if (!isDebugEnabled()) {
    return;
  }
  const prefix = `[api] ${message}`;
  if (data === undefined) {
    console.log(prefix);
    return;
  }
  console.log(prefix, typeof data === 'string' ? data : JSON.stringify(data, null, 2));
}

/** Adapter handler — Cognito orchestration is not implemented yet. */
export async function handler(event: unknown): Promise<ApiResponse> {
  if (isDebugEnabled()) {
    console.log('[api] DEBUG enabled');
  }

  debug('invoke', event);

  // TODO: map deployer-facing operations onto Cognito InitiateAuth /
  // RespondToAuthChallenge and return Cognito tokens.
  const response: ApiResponse = {
    statusCode: 501,
    body: JSON.stringify({error: 'Not implemented'}),
  };

  debug('response', response);
  return response;
}
