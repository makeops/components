/**
 * @fileoverview Thin client adapter over Cognito CUSTOM_AUTH. Accepts API Gateway
 * HTTP API / Function URL events or direct invokes shaped as
 * `{method, path, headers, body}`.
 *
 * Set env DEBUG=true (or 1 / yes) for verbose logs.
 */

import {
  CognitoIdentityProviderClient,
  GetUserCommand,
  GlobalSignOutCommand,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
} from '@aws-sdk/client-cognito-identity-provider';

interface ApiResponse {
  statusCode: number;
  headers?: Record<string, string>;
  body: string;
}

interface AdapterRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
}

const cognito = new CognitoIdentityProviderClient({});

function isDebugEnabled(): boolean {
  const value = (process.env.DEBUG ?? '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes' || value === 'debug';
}

function debug(message: string, data?: unknown): void {
  if (!isDebugEnabled()) {
    return;
  }
  if (data === undefined) {
    console.log(`[api] ${message}`);
    return;
  }
  console.log(
      `[api] ${message}`,
      typeof data === 'string' ? data : JSON.stringify(data, null, 2),
  );
}

function requireEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is not set`);
  }
  return value;
}

function json(statusCode: number, body: unknown): ApiResponse {
  return {
    statusCode,
    headers: {'content-type': 'application/json'},
    body: JSON.stringify(body),
  };
}

function noContent(): ApiResponse {
  return {statusCode: 204, headers: {'content-type': 'application/json'}, body: ''};
}

function error(statusCode: number, message: string): ApiResponse {
  return json(statusCode, {error: message});
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function lowerHeaders(
    headers: Record<string, string|undefined>|undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) {
    return out;
  }
  for (const [key, value] of Object.entries(headers)) {
    if (value !== undefined) {
      out[key.toLowerCase()] = value;
    }
  }
  return out;
}

function parseBody(body: string|null|undefined, isBase64Encoded?: boolean): unknown {
  if (body == null || body === '') {
    return undefined;
  }
  const raw = isBase64Encoded ? Buffer.from(body, 'base64').toString('utf8') : body;
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return raw;
  }
}

function isHttpEvent(event: unknown): boolean {
  if (!isRecord(event)) {
    return false;
  }
  const ctx = event['requestContext'];
  if (isRecord(ctx) && isRecord(ctx['http']) && typeof ctx['http']['method'] === 'string') {
    return true;
  }
  return typeof event['httpMethod'] === 'string' && typeof event['path'] === 'string';
}

function toAdapterRequest(event: unknown): AdapterRequest {
  if (!isRecord(event)) {
    throw new Error('Unsupported event: expected object');
  }

  if (isHttpEvent(event)) {
    const ctx = event['requestContext'];
    if (isRecord(ctx) && isRecord(ctx['http']) && typeof ctx['http']['method'] === 'string') {
      return {
        method: String(ctx['http']['method']).toUpperCase(),
        path: String(event['rawPath'] ?? ctx['http']['path'] ?? '/'),
        headers: lowerHeaders(event['headers'] as Record<string, string|undefined>),
        body: parseBody(
            event['body'] as string|null|undefined,
            event['isBase64Encoded'] === true,
        ),
      };
    }

    return {
      method: String(event['httpMethod'] ?? 'GET').toUpperCase(),
      path: String(event['path'] ?? '/'),
      headers: lowerHeaders(event['headers'] as Record<string, string|undefined>),
      body: parseBody(
          event['body'] as string|null|undefined,
          event['isBase64Encoded'] === true,
      ),
    };
  }

  return {
    method: String(event['method'] ?? 'POST').toUpperCase(),
    path: String(event['path'] ?? '/'),
    headers: lowerHeaders(event['headers'] as Record<string, string|undefined>),
    body: event['body'],
  };
}

function bearerToken(headers: Record<string, string>): string|undefined {
  const value = headers['authorization'];
  if (!value) {
    return undefined;
  }
  const match = /^Bearer\s+(.+)$/i.exec(value.trim());
  return match?.[1];
}

function decodeJwtPayload(token: string): Record<string, unknown>|undefined {
  const parts = token.split('.');
  if (parts.length < 2 || !parts[1]) {
    return undefined;
  }
  try {
    const padded = parts[1] + '='.repeat((4 - (parts[1].length % 4)) % 4);
    const jsonText = Buffer.from(
        padded.replace(/-/g, '+').replace(/_/g, '/'),
        'base64',
    ).toString('utf8');
    return JSON.parse(jsonText) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function emailFromAttributes(
    attributes: Array<{Name?: string; Value?: string}>|undefined): string|null {
  const email = attributes?.find((attr) => attr.Name === 'email')?.Value?.trim();
  return email || null;
}

function isValidCallbackUrl(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      return false;
    }
    return !url.search;
  } catch {
    return false;
  }
}

async function requestMagicLink(req: AdapterRequest): Promise<ApiResponse> {
  const body = (req.body ?? {}) as {email?: unknown; callbackUrl?: unknown};
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const callbackUrl =
      typeof body.callbackUrl === 'string' ? body.callbackUrl.trim() : '';

  if (!email || !email.includes('@')) {
    return error(400, 'Invalid email');
  }
  if (!callbackUrl || !isValidCallbackUrl(callbackUrl)) {
    return error(400, 'Invalid callback URL');
  }

  const clientId = requireEnv('COGNITO_CLIENT_ID');

  try {
    const initiated = await cognito.send(new InitiateAuthCommand({
      AuthFlow: 'CUSTOM_AUTH',
      ClientId: clientId,
      AuthParameters: {USERNAME: email},
    }));

    if (!initiated.Session || initiated.ChallengeName !== 'CUSTOM_CHALLENGE') {
      debug('unexpected initiate response', initiated);
      return noContent();  // avoid account enumeration
    }

    await cognito.send(new RespondToAuthChallengeCommand({
      ClientId: clientId,
      ChallengeName: 'CUSTOM_CHALLENGE',
      Session: initiated.Session,
      ChallengeResponses: {
        USERNAME: email,
        ANSWER: '__request_link__',
      },
      ClientMetadata: {
        signInMethod: 'MAGIC_LINK',
        redirectUrl: callbackUrl,
        haveMagicLinkToken: 'no',
      },
    }));
  } catch (err) {
    // UserNotFound / NotAuthorized etc. — still 204 to avoid enumeration.
    debug('requestMagicLink cognito error', err);
  }

  return noContent();
}

async function verifyMagicLink(req: AdapterRequest): Promise<ApiResponse> {
  const body = (req.body ?? {}) as {token?: unknown};
  const token = typeof body.token === 'string' ? body.token.trim() : '';
  if (!token) {
    return error(400, 'Missing token');
  }

  const payload = decodeJwtPayload(token);
  const username =
      typeof payload?.['username'] === 'string' ? payload['username'] : '';
  if (!username) {
    return error(400, 'Invalid or expired token');
  }

  const clientId = requireEnv('COGNITO_CLIENT_ID');

  try {
    const initiated = await cognito.send(new InitiateAuthCommand({
      AuthFlow: 'CUSTOM_AUTH',
      ClientId: clientId,
      AuthParameters: {USERNAME: username},
    }));

    if (!initiated.Session || initiated.ChallengeName !== 'CUSTOM_CHALLENGE') {
      return error(400, 'Invalid or expired token');
    }

    // Complete PROVIDE_AUTH_PARAMETERS round without sending a new email.
    const prepared = await cognito.send(new RespondToAuthChallengeCommand({
      ClientId: clientId,
      ChallengeName: 'CUSTOM_CHALLENGE',
      Session: initiated.Session,
      ChallengeResponses: {
        USERNAME: username,
        ANSWER: '__have_token__',
      },
      ClientMetadata: {
        signInMethod: 'MAGIC_LINK',
        haveMagicLinkToken: 'yes',
      },
    }));

    if (!prepared.Session || prepared.ChallengeName !== 'CUSTOM_CHALLENGE') {
      return error(400, 'Invalid or expired token');
    }

    const verified = await cognito.send(new RespondToAuthChallengeCommand({
      ClientId: clientId,
      ChallengeName: 'CUSTOM_CHALLENGE',
      Session: prepared.Session,
      ChallengeResponses: {
        USERNAME: username,
        ANSWER: token,
      },
      ClientMetadata: {
        signInMethod: 'MAGIC_LINK',
        haveMagicLinkToken: 'yes',
      },
    }));

    const accessToken = verified.AuthenticationResult?.AccessToken;
    if (!accessToken) {
      return error(400, 'Invalid or expired token');
    }

    return json(200, {token: accessToken});
  } catch (err) {
    debug('verifyMagicLink cognito error', err);
    return error(400, 'Invalid or expired token');
  }
}

async function getSession(req: AdapterRequest): Promise<ApiResponse> {
  const token = bearerToken(req.headers);
  if (!token) {
    return error(401, 'Missing or invalid Authorization header');
  }

  try {
    const user = await cognito.send(new GetUserCommand({AccessToken: token}));
    return json(200, {email: emailFromAttributes(user.UserAttributes)});
  } catch (err) {
    debug('getSession cognito error', err);
    return json(200, {email: null});
  }
}

async function logout(req: AdapterRequest): Promise<ApiResponse> {
  const token = bearerToken(req.headers);
  if (!token) {
    return error(401, 'Missing or invalid Authorization header');
  }

  try {
    await cognito.send(new GlobalSignOutCommand({AccessToken: token}));
  } catch (err) {
    // Idempotent logout for invalid/expired tokens.
    debug('logout cognito error', err);
  }

  return noContent();
}

async function getAccount(req: AdapterRequest): Promise<ApiResponse> {
  const token = bearerToken(req.headers);
  if (!token) {
    return error(401, 'Missing or invalid Authorization header');
  }

  try {
    const user = await cognito.send(new GetUserCommand({AccessToken: token}));
    const email = emailFromAttributes(user.UserAttributes);
    if (!email) {
      return error(401, 'Invalid or expired session');
    }
    return json(200, {email});
  } catch (err) {
    debug('getAccount cognito error', err);
    return error(401, 'Invalid or expired session');
  }
}

async function handleRequest(req: AdapterRequest): Promise<ApiResponse> {
  const path = req.path.replace(/\/+$/, '') || '/';
  const key = `${req.method} ${path}`;

  switch (key) {
    case 'POST /api/auth/magic-link':
      return requestMagicLink(req);
    case 'POST /api/auth/verify':
      return verifyMagicLink(req);
    case 'GET /api/auth/session':
      return getSession(req);
    case 'POST /api/auth/logout':
      return logout(req);
    case 'GET /api/account':
      return getAccount(req);
    default:
      return error(404, 'Not found');
  }
}

/** Client adapter entrypoint. */
export async function handler(event: unknown): Promise<ApiResponse|Record<string, unknown>> {
  if (isDebugEnabled()) {
    console.log('[api] DEBUG enabled');
  }
  debug('invoke', event);

  let request: AdapterRequest;
  try {
    request = toAdapterRequest(event);
  } catch {
    const errBody = {error: 'Unsupported event shape'};
    if (isHttpEvent(event)) {
      return json(400, errBody);
    }
    return errBody;
  }

  const response = await handleRequest(request);
  debug('response', response);

  if (isHttpEvent(event)) {
    return response;
  }

  // Direct invoke: structured status + parsed body.
  return {
    statusCode: response.statusCode,
    body: response.body ? JSON.parse(response.body || 'null') : null,
  };
}
