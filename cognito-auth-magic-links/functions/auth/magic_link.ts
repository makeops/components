/**
 * @fileoverview Cognito custom-auth magic-link challenge handlers (Define /
 * Create / Verify) plus KMS-signed JWT issuance and single-use DynamoDB claims.
 */

import {DynamoDBClient} from '@aws-sdk/client-dynamodb';
import {KMSClient, SignCommand, VerifyCommand} from '@aws-sdk/client-kms';
import {SendEmailCommand, SESClient} from '@aws-sdk/client-ses';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import type {
  CreateAuthChallengeTriggerEvent,
  DefineAuthChallengeTriggerEvent,
  VerifyAuthChallengeResponseTriggerEvent,
} from 'aws-lambda';
import {createHash, randomUUID} from 'crypto';
import {readFileSync} from 'fs';
import {join} from 'path';

/** Includes the initial PROVIDE_AUTH_PARAMETERS round. */
const MAX_CUSTOM_CHALLENGE_ATTEMPTS = 3;
const TOKEN_TTL_SECONDS = 60 * 15;
const LOGIN_LINK_PLACEHOLDER = '{{LOGIN_LINK}}';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const ses = new SESClient({});
const kms = new KMSClient({});

/** Bundled beside the handler via NodejsFunction commandHooks. */
const emailTextTemplate = readFileSync(join(__dirname, 'magic-link.txt'), 'utf8');
const emailHtmlTemplate = readFileSync(join(__dirname, 'magic-link.html'), 'utf8');

interface JwtClaims {
  sid: string;
  exp: number;
}

interface JwtPayloadFields {
  sid?: unknown;
  exp?: unknown;
}

function requireEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is not set`);
  }
  return value;
}

function allowedRedirectUrls(): string[] {
  return (process.env.ALLOWED_REDIRECT_URLS ?? '')
      .split(',')
      .map((url) => url.trim())
      .filter(Boolean);
}

function isDebugEnabled(): boolean {
  const value = (process.env.DEBUG ?? '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes' || value === 'debug';
}

function debug(message: string, data?: unknown): void {
  if (!isDebugEnabled()) {
    return;
  }
  if (data === undefined) {
    console.log(`[auth:magic-link] ${message}`);
    return;
  }
  console.log(`[auth:magic-link] ${message}`, JSON.stringify(data));
}

function encodeBase64Url(value: string|Buffer|Record<string, unknown>): string {
  const buffer = Buffer.isBuffer(value) ?
      value :
      Buffer.from(typeof value === 'string' ? value : JSON.stringify(value));
  return buffer.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
}

function decodeBase64Url(value: string): Buffer {
  const padded = value + '='.repeat((4 - (value.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/**
 * Resolves `clientMetadata.redirectUrl` against ALLOWED_REDIRECT_URLS.
 * Missing values fall back to the first allowlisted URL.
 */
export function resolveRedirectUrl(
    clientMetadata?: Record<string, string>|null): string|undefined {
  const redirectUrl = clientMetadata?.redirectUrl?.trim();
  const allowed = allowedRedirectUrls();
  if (!redirectUrl) {
    return allowed[0];
  }
  return allowed.includes(redirectUrl) ? redirectUrl : undefined;
}

async function signJwt(payload: Record<string, unknown>): Promise<string> {
  const keyId = requireEnv('MAGIC_LINK_SIGN_KEY_ARN');
  const header = {alg: 'RS256', typ: 'JWT', kid: keyId};
  const message = `${encodeBase64Url(header)}.${encodeBase64Url(payload)}`;
  const digest = createHash('sha256').update(message).digest();

  const result = await kms.send(new SignCommand({
    KeyId: keyId,
    Message: digest,
    MessageType: 'DIGEST',
    SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
  }));
  if (!result.Signature) {
    throw new Error('KMS Sign returned no signature');
  }

  return `${message}.${encodeBase64Url(Buffer.from(result.Signature))}`;
}

async function verifyJwt(token: string): Promise<JwtClaims|undefined> {
  const [headerB64, payloadB64, signatureB64] = token.split('.');
  if (!headerB64 || !payloadB64 || !signatureB64) {
    return undefined;
  }

  let payload: JwtPayloadFields;
  try {
    payload = JSON.parse(decodeBase64Url(payloadB64).toString('utf8'));
  } catch {
    return undefined;
  }

  if (typeof payload.sid !== 'string' || typeof payload.exp !== 'number') {
    return undefined;
  }
  if (payload.exp < Math.floor(Date.now() / 1000)) {
    debug('token expired', {exp: payload.exp});
    return undefined;
  }

  const digest = createHash('sha256').update(`${headerB64}.${payloadB64}`).digest();
  const verified = await kms.send(new VerifyCommand({
    KeyId: requireEnv('MAGIC_LINK_SIGN_KEY_ARN'),
    Message: digest,
    MessageType: 'DIGEST',
    Signature: decodeBase64Url(signatureB64),
    SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
  }));

  if (!verified.SignatureValid) {
    return undefined;
  }
  return {sid: payload.sid, exp: payload.exp};
}

function recipientEmail(event: CreateAuthChallengeTriggerEvent): string {
  const email = event.request.userAttributes?.email?.trim();
  if (email) {
    return email;
  }
  if (event.userName.includes('@')) {
    return event.userName;
  }
  throw new Error('No email available to send magic link');
}

async function sendEmail(to: string, loginLink: string): Promise<void> {
  const from = requireEnv('MAGIC_LINK_FROM_EMAIL');
  const fromName = process.env.MAGIC_LINK_FROM_NAME?.trim() || 'Auth';
  const subject = process.env.MAGIC_LINK_SUBJECT?.trim() || 'Your sign-in link';
  const textBody = emailTextTemplate.split(LOGIN_LINK_PLACEHOLDER).join(loginLink);
  const htmlBody = emailHtmlTemplate.split(LOGIN_LINK_PLACEHOLDER).join(loginLink);

  await ses.send(new SendEmailCommand({
    Source: `${fromName} <${from}>`,
    Destination: {ToAddresses: [to]},
    Message: {
      Subject: {Data: subject, Charset: 'UTF-8'},
      Body: {
        Text: {Charset: 'UTF-8', Data: textBody},
        Html: {Charset: 'UTF-8', Data: htmlBody},
      },
    },
  }));
}

async function createAndSendMagicLink(
    event: CreateAuthChallengeTriggerEvent, redirectUrl: string): Promise<void> {
  const sid = randomUUID();
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + TOKEN_TTL_SECONDS;
  const keyId = requireEnv('MAGIC_LINK_SIGN_KEY_ARN');
  const table = requireEnv('MAGIC_LINK_TABLE_NAME');
  const to = recipientEmail(event);

  const token = await signJwt({sid, exp, username: event.userName});

  await ddb.send(new PutCommand({
    TableName: table,
    Item: {sid, username: event.userName, exp, iat, kmsKeyId: keyId},
    ConditionExpression: 'attribute_not_exists(sid)',
  }));

  const loginLink = `${redirectUrl}?token=${encodeURIComponent(token)}`;
  // Dev: log full URL; never put it in the Cognito challenge response.
  console.log(`[magic-link] email=${to} url=${loginLink}`);

  await sendEmail(to, loginLink);
  debug('emailed', {sid, username: event.userName, to, redirectUrl});
}

/**
 * Verifies a magic-link JWT: KMS signature, expiry, username binding, and
 * single-use claim in DynamoDB.
 */
export async function verifyMagicLink(token: string, username: string): Promise<boolean> {
  try {
    const verified = await verifyJwt(token);
    if (!verified) {
      return false;
    }

    const {sid, exp: tokenExp} = verified;
    const now = Math.floor(Date.now() / 1000);
    const table = requireEnv('MAGIC_LINK_TABLE_NAME');

    const {Item} = await ddb.send(new GetCommand({TableName: table, Key: {sid}}));
    if (!Item) {
      debug('no ddb record', {sid});
      return false;
    }
    if (typeof Item.exp === 'number' && Item.exp < now) {
      return false;
    }
    if (typeof Item.exp === 'number' && Item.exp !== tokenExp) {
      return false;
    }
    if (Item.username !== username) {
      return false;
    }
    if (Item.uat !== undefined && Item.uat !== null) {
      debug('already used', {sid});
      return false;
    }

    try {
      await ddb.send(new UpdateCommand({
        TableName: table,
        Key: {sid},
        UpdateExpression: 'SET uat = :uat',
        ConditionExpression: 'attribute_not_exists(uat)',
        ExpressionAttributeValues: {':uat': now},
      }));
    } catch (err: unknown) {
      const name = err && typeof err === 'object' && 'name' in err ?
          String((err as {name: unknown}).name) :
          '';
      if (name === 'ConditionalCheckFailedException') {
        return false;
      }
      console.error('[auth:magic-link] failed to mark used', err);
      return false;  // fail closed
    }

    return true;
  } catch (err) {
    console.error('[auth:magic-link] verify error', err);
    return false;
  }
}

function deny(
    event: DefineAuthChallengeTriggerEvent, reason: string): DefineAuthChallengeTriggerEvent {
  debug(`deny: ${reason}`);
  event.response.issueTokens = false;
  event.response.failAuthentication = true;
  return event;
}

function allow(event: DefineAuthChallengeTriggerEvent): DefineAuthChallengeTriggerEvent {
  event.response.issueTokens = true;
  event.response.failAuthentication = false;
  return event;
}

function nextChallenge(event: DefineAuthChallengeTriggerEvent): DefineAuthChallengeTriggerEvent {
  event.response.issueTokens = false;
  event.response.failAuthentication = false;
  event.response.challengeName = 'CUSTOM_CHALLENGE';
  return event;
}

/** Steers CUSTOM_AUTH for the magic-link flow. */
export function handleDefineAuthChallenge(
    event: DefineAuthChallengeTriggerEvent): DefineAuthChallengeTriggerEvent {
  const session = event.request.session ?? [];

  // First InitiateAuth — wait for clientMetadata on RespondToAuthChallenge.
  if (session.length === 0) {
    return nextChallenge(event);
  }

  if (session.some((entry) => entry.challengeName !== 'CUSTOM_CHALLENGE')) {
    return deny(event, 'only CUSTOM_CHALLENGE allowed');
  }

  const {signInMethod} = event.request.clientMetadata ?? {};
  if (signInMethod !== 'MAGIC_LINK') {
    return deny(event, `unsupported signInMethod: ${signInMethod}`);
  }

  const last = session.at(-1);
  if (last?.challengeResult === true) {
    return allow(event);
  }
  if (session.length >= MAX_CUSTOM_CHALLENGE_ATTEMPTS) {
    return deny(event, 'too many attempts');
  }

  return nextChallenge(event);
}

/** Issues PROVIDE_AUTH_PARAMETERS or emails a magic-link token. */
export async function handleCreateAuthChallenge(
    event: CreateAuthChallengeTriggerEvent): Promise<CreateAuthChallengeTriggerEvent> {
  // Round 1: ask the client for metadata (signInMethod, redirectUrl, …).
  if (!event.request.session?.length) {
    const parameters = {challenge: 'PROVIDE_AUTH_PARAMETERS'};
    event.response.challengeMetadata = 'PROVIDE_AUTH_PARAMETERS';
    event.response.publicChallengeParameters = parameters;
    event.response.privateChallengeParameters = parameters;
    return event;
  }

  const meta = event.request.clientMetadata ?? {};
  if (meta.signInMethod !== 'MAGIC_LINK') {
    debug('create: unsupported signInMethod', meta.signInMethod);
    return event;
  }

  // Client already holds the emailed token (opened the link elsewhere).
  if (meta.haveMagicLinkToken === 'yes') {
    event.response.challengeMetadata = 'MAGIC_LINK';
    event.response.privateChallengeParameters = {challenge: 'PROVIDE_MAGIC_LINK'};
    event.response.publicChallengeParameters = {};
    return event;
  }

  const redirectUrl = resolveRedirectUrl(meta);
  if (!redirectUrl) {
    debug('create: redirectUrl not allowlisted', meta.redirectUrl);
    return event;
  }

  await createAndSendMagicLink(event, redirectUrl);

  event.response.challengeMetadata = 'MAGIC_LINK';
  event.response.privateChallengeParameters = {challenge: 'PROVIDE_MAGIC_LINK'};
  event.response.publicChallengeParameters = {};
  return event;
}

/** Validates the magic-link token from challengeAnswer. */
export async function handleVerifyAuthChallenge(
    event: VerifyAuthChallengeResponseTriggerEvent,
    ): Promise<VerifyAuthChallengeResponseTriggerEvent> {
  // Cognito username is on event.userName (same value stored in DDB at create).
  event.response.answerCorrect =
      await verifyMagicLink(event.request.challengeAnswer, event.userName);
  return event;
}
