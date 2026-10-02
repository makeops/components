/**
 * @fileoverview Unit tests for the Cognito trigger router.
 */

const handleDefineAuthChallenge = jest.fn((event) => event);
const handleCreateAuthChallenge = jest.fn(async (event) => event);
const handleVerifyAuthChallenge = jest.fn(async (event) => {
  event.response.answerCorrect = true;
  return event;
});

jest.mock('./magic_link', () => ({
  handleDefineAuthChallenge: (...args: [unknown]) => handleDefineAuthChallenge(...args),
  handleCreateAuthChallenge: (...args: [unknown]) => handleCreateAuthChallenge(...args),
  handleVerifyAuthChallenge: (...args: [unknown]) => handleVerifyAuthChallenge(...args),
}));

import type {
  CreateAuthChallengeTriggerEvent,
  DefineAuthChallengeTriggerEvent,
  PreTokenGenerationV2TriggerEvent,
  VerifyAuthChallengeResponseTriggerEvent,
} from 'aws-lambda';

import {handler} from './auth_handler';

function defineEvent(): DefineAuthChallengeTriggerEvent {
  return {
    version: '1',
    region: 'eu-west-1',
    userPoolId: 'pool',
    userName: 'user@example.com',
    triggerSource: 'DefineAuthChallenge_Authentication',
    callerContext: {awsSdkVersion: 'aws-sdk-js-3', clientId: 'client'},
    request: {
      userAttributes: {sub: 'sub-1', email: 'user@example.com'},
      session: [],
      userNotFound: false,
    },
    response: {
      challengeName: '' as DefineAuthChallengeTriggerEvent['response']['challengeName'],
      issueTokens: false,
      failAuthentication: false,
    },
  };
}

function createEvent(): CreateAuthChallengeTriggerEvent {
  return {
    version: '1',
    region: 'eu-west-1',
    userPoolId: 'pool',
    userName: 'user@example.com',
    triggerSource: 'CreateAuthChallenge_Authentication',
    callerContext: {awsSdkVersion: 'aws-sdk-js-3', clientId: 'client'},
    request: {
      userAttributes: {sub: 'sub-1', email: 'user@example.com'},
      challengeName: 'CUSTOM_CHALLENGE',
      session: [],
      userNotFound: false,
    },
    response: {
      publicChallengeParameters: {},
      privateChallengeParameters: {},
      challengeMetadata: '',
    },
  };
}

function verifyEvent(): VerifyAuthChallengeResponseTriggerEvent {
  return {
    version: '1',
    region: 'eu-west-1',
    userPoolId: 'pool',
    userName: 'user@example.com',
    triggerSource: 'VerifyAuthChallengeResponse_Authentication',
    callerContext: {awsSdkVersion: 'aws-sdk-js-3', clientId: 'client'},
    request: {
      userAttributes: {sub: 'sub-1', email: 'user@example.com'},
      privateChallengeParameters: {},
      challengeAnswer: 'token',
      userNotFound: false,
    },
    response: {answerCorrect: false},
  };
}

function preTokenEvent(
    attrs: Record<string, string> = {},
    ): PreTokenGenerationV2TriggerEvent {
  return {
    version: '1',
    region: 'eu-west-1',
    userPoolId: 'pool',
    userName: 'user@example.com',
    triggerSource: 'TokenGeneration_Authentication',
    callerContext: {awsSdkVersion: 'aws-sdk-js-3', clientId: 'client'},
    request: {
      userAttributes: {sub: 'sub-1', email: 'user@example.com', ...attrs},
      groupConfiguration: {},
    },
    response: {claimsAndScopeOverrideDetails: {}},
  };
}

describe('auth handler router', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.MAGIC_LINK_ENABLED = 'true';
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    delete process.env.MAGIC_LINK_ENABLED;
    jest.restoreAllMocks();
  });

  it('routes DefineAuthChallenge to the magic-link handler when enabled', async () => {
    const event = defineEvent();
    await handler(event);
    expect(handleDefineAuthChallenge).toHaveBeenCalledTimes(1);
    expect(handleDefineAuthChallenge).toHaveBeenCalledWith(event);
  });

  it('fails DefineAuthChallenge when magic links are disabled', async () => {
    process.env.MAGIC_LINK_ENABLED = 'false';
    const result = await handler(defineEvent()) as DefineAuthChallengeTriggerEvent;
    expect(handleDefineAuthChallenge).not.toHaveBeenCalled();
    expect(result.response.issueTokens).toBe(false);
    expect(result.response.failAuthentication).toBe(true);
  });

  it('routes CreateAuthChallenge when enabled', async () => {
    const event = createEvent();
    await handler(event);
    expect(handleCreateAuthChallenge).toHaveBeenCalledWith(event);
  });

  it('skips CreateAuthChallenge when magic links are disabled', async () => {
    process.env.MAGIC_LINK_ENABLED = 'false';
    const event = createEvent();
    const result = await handler(event);
    expect(handleCreateAuthChallenge).not.toHaveBeenCalled();
    expect(result).toBe(event);
  });

  it('routes VerifyAuthChallenge when enabled', async () => {
    const event = verifyEvent();
    const result =
        await handler(event) as VerifyAuthChallengeResponseTriggerEvent;
    expect(handleVerifyAuthChallenge).toHaveBeenCalledWith(event);
    expect(result.response.answerCorrect).toBe(true);
  });

  it('forces answerCorrect=false when magic links are disabled', async () => {
    process.env.MAGIC_LINK_ENABLED = 'false';
    const result =
        await handler(verifyEvent()) as VerifyAuthChallengeResponseTriggerEvent;
    expect(handleVerifyAuthChallenge).not.toHaveBeenCalled();
    expect(result.response.answerCorrect).toBe(false);
  });

  it('injects custom claims on PreTokenGeneration', async () => {
    const result = await handler(preTokenEvent({
      'custom:db_org_id': 'org-42',
      'custom:auth_method': 'magic_link',
    })) as PreTokenGenerationV2TriggerEvent;

    expect(result.response.claimsAndScopeOverrideDetails).toEqual({
      accessTokenGeneration: {
        claimsToAddOrOverride: {
          db_org_id: 'org-42',
          auth_method: 'magic_link',
        },
      },
      idTokenGeneration: {
        claimsToAddOrOverride: {
          db_org_id: 'org-42',
          auth_method: 'magic_link',
        },
      },
    });
  });

  it('returns empty claim maps when custom attributes are absent', async () => {
    const result =
        await handler(preTokenEvent()) as PreTokenGenerationV2TriggerEvent;
    expect(
        result.response.claimsAndScopeOverrideDetails.accessTokenGeneration
            ?.claimsToAddOrOverride,
    ).toEqual({});
  });

  it('passes through unhandled trigger sources', async () => {
    const event = {
      ...defineEvent(),
      triggerSource: 'UserMigration_Authentication',
    } as unknown as DefineAuthChallengeTriggerEvent;
    const result = await handler(event);
    expect(result).toBe(event);
    expect(console.warn).toHaveBeenCalled();
  });
});
