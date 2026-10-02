/**
 * @fileoverview Cognito User Pool trigger entrypoint. Wire the same function
 * ARN to DefineAuthChallenge, CreateAuthChallenge, VerifyAuthChallengeResponse,
 * and PreTokenGeneration (V2_0).
 */

import type {
  CreateAuthChallengeTriggerEvent,
  DefineAuthChallengeTriggerEvent,
  PreTokenGenerationV2TriggerEvent,
  VerifyAuthChallengeResponseTriggerEvent,
} from 'aws-lambda';

import {createDebug, log} from '../log';
import {
  handleCreateAuthChallenge,
  handleDefineAuthChallenge,
  handleVerifyAuthChallenge,
} from './magic_link';

type AuthTriggerEvent =
    | DefineAuthChallengeTriggerEvent
    | CreateAuthChallengeTriggerEvent
    | VerifyAuthChallengeResponseTriggerEvent
    | PreTokenGenerationV2TriggerEvent;

const debug = createDebug('auth');

function magicLinksEnabled(): boolean {
  return (process.env.MAGIC_LINK_ENABLED ?? '').trim().toLowerCase() === 'true';
}

/**
 * Cognito trigger handler. Set DEBUG=true for verbose logs.
 */
export async function handler(event: AuthTriggerEvent): Promise<AuthTriggerEvent> {
  debug('invoke', {triggerSource: event.triggerSource, userName: event.userName});

  switch (event.triggerSource) {
    case 'DefineAuthChallenge_Authentication':
      return defineAuthChallenge(event);

    case 'CreateAuthChallenge_Authentication':
      return createAuthChallenge(event);

    case 'VerifyAuthChallengeResponse_Authentication':
      return verifyAuthChallenge(event);

    case 'TokenGeneration_HostedAuth':
    case 'TokenGeneration_Authentication':
    case 'TokenGeneration_NewPasswordChallenge':
    case 'TokenGeneration_AuthenticateDevice':
    case 'TokenGeneration_RefreshTokens':
      return preTokenGeneration(event);

    default: {
      const triggerSource = (event as {triggerSource?: string}).triggerSource;
      log('WARN', 'auth', 'unhandled triggerSource', {triggerSource});
      return event;
    }
  }
}

function defineAuthChallenge(
    event: DefineAuthChallengeTriggerEvent): DefineAuthChallengeTriggerEvent {
  if (!magicLinksEnabled()) {
    event.response.issueTokens = false;
    event.response.failAuthentication = true;
    return event;
  }
  return handleDefineAuthChallenge(event);
}

async function createAuthChallenge(
    event: CreateAuthChallengeTriggerEvent): Promise<CreateAuthChallengeTriggerEvent> {
  if (!magicLinksEnabled()) {
    return event;
  }
  return handleCreateAuthChallenge(event);
}

async function verifyAuthChallenge(
    event: VerifyAuthChallengeResponseTriggerEvent,
    ): Promise<VerifyAuthChallengeResponseTriggerEvent> {
  if (!magicLinksEnabled()) {
    event.response.answerCorrect = false;
    return event;
  }
  return handleVerifyAuthChallenge(event);
}

/** Enrich tokens with custom attributes from the user pool. */
function preTokenGeneration(
    event: PreTokenGenerationV2TriggerEvent): PreTokenGenerationV2TriggerEvent {
  const attrs = event.request.userAttributes ?? {};
  const claims: Record<string, string> = {};

  if (attrs['custom:db_org_id']) {
    claims['db_org_id'] = attrs['custom:db_org_id'];
  }
  if (attrs['custom:auth_method']) {
    claims['auth_method'] = attrs['custom:auth_method'];
  }

  event.response.claimsAndScopeOverrideDetails = {
    accessTokenGeneration: {claimsToAddOrOverride: claims},
    idTokenGeneration: {claimsToAddOrOverride: claims},
  };

  debug('preToken claims', claims);
  return event;
}
