import type {
  CreateAuthChallengeTriggerEvent,
  DefineAuthChallengeTriggerEvent,
  PreTokenGenerationV2TriggerEvent,
  VerifyAuthChallengeResponseTriggerEvent,
} from 'aws-lambda';

type AuthTriggerEvent =
  | DefineAuthChallengeTriggerEvent
  | CreateAuthChallengeTriggerEvent
  | VerifyAuthChallengeResponseTriggerEvent
  | PreTokenGenerationV2TriggerEvent;

function isDebug(): boolean {
  const value = (process.env.DEBUG ?? '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes' || value === 'debug';
}

function debug(message: string, data?: unknown): void {
  if (!isDebug()) return;
  if (data === undefined) {
    console.debug(`[auth] ${message}`);
    return;
  }
  console.debug(`[auth] ${message}`, typeof data === 'string' ? data : JSON.stringify(data));
}

/**
 * Single Cognito Lambda entrypoint. Wire the same function ARN to
 * DefineAuthChallenge, CreateAuthChallenge, VerifyAuthChallengeResponse,
 * and PreTokenGeneration (V2_0).
 *
 * Set env `DEBUG=true` (or `1` / `yes`) for verbose logs.
 */
export async function handler(event: AuthTriggerEvent): Promise<AuthTriggerEvent> {
  debug('invoke', { triggerSource: event.triggerSource, userName: event.userName });

  let result: AuthTriggerEvent;

  switch (event.triggerSource) {
    case 'DefineAuthChallenge_Authentication':
      result = defineAuthChallenge(event);
      break;

    case 'CreateAuthChallenge_Authentication':
      result = createAuthChallenge(event);
      break;

    case 'VerifyAuthChallengeResponse_Authentication':
      result = verifyAuthChallengeResponse(event);
      break;

    case 'TokenGeneration_HostedAuth':
    case 'TokenGeneration_Authentication':
    case 'TokenGeneration_NewPasswordChallenge':
    case 'TokenGeneration_AuthenticateDevice':
    case 'TokenGeneration_RefreshTokens':
      result = preTokenGeneration(event);
      break;

    default:
      console.warn(`Unhandled Cognito triggerSource: ${(event as { triggerSource?: string }).triggerSource}`);
      return event;
  }

  debug('response', result.response);
  return result;
}

function defineAuthChallenge(
  event: DefineAuthChallengeTriggerEvent,
): DefineAuthChallengeTriggerEvent {
  const session = event.request.session ?? [];
  const lastChallenge = session.at(-1);

  debug('defineAuthChallenge', {
    sessionLength: session.length,
    lastChallengeName: lastChallenge?.challengeName,
    lastChallengeResult: lastChallenge?.challengeResult,
  });

  if (session.length === 0) {
    event.response.challengeName = 'CUSTOM_CHALLENGE';
    event.response.issueTokens = false;
    event.response.failAuthentication = false;
    return event;
  }

  if (lastChallenge?.challengeResult === true) {
    event.response.issueTokens = true;
    event.response.failAuthentication = false;
    return event;
  }

  if (
    lastChallenge?.challengeName === 'CUSTOM_CHALLENGE' &&
    lastChallenge.challengeResult === false &&
    session.length >= 3
  ) {
    event.response.issueTokens = false;
    event.response.failAuthentication = true;
    return event;
  }

  event.response.challengeName = 'CUSTOM_CHALLENGE';
  event.response.issueTokens = false;
  event.response.failAuthentication = false;
  return event;
}

function createAuthChallenge(
  event: CreateAuthChallengeTriggerEvent,
): CreateAuthChallengeTriggerEvent {
  debug('createAuthChallenge', {
    challengeName: event.request.challengeName,
    clientMetadata: event.request.clientMetadata,
  });

  // TODO: magic-link (SES + KMS + DynamoDB) / WebAuthn challenge issuance.
  event.response.publicChallengeParameters ??= {};
  event.response.privateChallengeParameters ??= {};
  event.response.challengeMetadata ??= 'CUSTOM_CHALLENGE';
  return event;
}

function verifyAuthChallengeResponse(
  event: VerifyAuthChallengeResponseTriggerEvent,
): VerifyAuthChallengeResponseTriggerEvent {
  debug('verifyAuthChallengeResponse', {
    hasAnswer: Boolean(event.request.challengeAnswer),
    privateChallengeParameterKeys: Object.keys(event.request.privateChallengeParameters ?? {}),
  });

  // TODO: validate magic-link token or WebAuthn assertion.
  event.response.answerCorrect = false;
  return event;
}

function preTokenGeneration(
  event: PreTokenGenerationV2TriggerEvent,
): PreTokenGenerationV2TriggerEvent {
  debug('preTokenGeneration', {
    triggerSource: event.triggerSource,
    clientId: event.callerContext.clientId,
  });

  event.response.claimsAndScopeOverrideDetails ??= {
    accessTokenGeneration: {},
    idTokenGeneration: {},
  };

  // TODO: custom claims from user attributes (db_org_id, auth_method, …).
  return event;
}
