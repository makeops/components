/**
 * @fileoverview Unit tests for Cognito magic-link challenge handlers.
 */

const mockDdbSend = jest.fn();
const mockKmsSend = jest.fn();
const mockSesSend = jest.fn();

jest.mock('fs', () => ({
  readFileSync: jest.fn((filePath: string) => {
    if (String(filePath).endsWith('.html')) {
      return '<p><a href="{{LOGIN_LINK}}">Sign in</a></p>';
    }
    return 'Sign in: {{LOGIN_LINK}}\n';
  }),
}));

jest.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: jest.fn().mockImplementation(() => ({})),
}));

jest.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: () => ({send: (...args: unknown[]) => mockDdbSend(...args)}),
  },
  GetCommand: jest.fn().mockImplementation((input) => ({...input, _op: 'Get'})),
  PutCommand: jest.fn().mockImplementation((input) => ({...input, _op: 'Put'})),
  UpdateCommand:
      jest.fn().mockImplementation((input) => ({...input, _op: 'Update'})),
}));

jest.mock('@aws-sdk/client-kms', () => ({
  KMSClient: jest.fn().mockImplementation(() => ({
    send: (...args: unknown[]) => mockKmsSend(...args),
  })),
  SignCommand: jest.fn().mockImplementation((input) => ({...input, _op: 'Sign'})),
  VerifyCommand:
      jest.fn().mockImplementation((input) => ({...input, _op: 'Verify'})),
}));

jest.mock('@aws-sdk/client-ses', () => ({
  SESClient: jest.fn().mockImplementation(() => ({
    send: (...args: unknown[]) => mockSesSend(...args),
  })),
  SendEmailCommand:
      jest.fn().mockImplementation((input) => ({...input, _op: 'SendEmail'})),
}));

import type {
  CreateAuthChallengeTriggerEvent,
  DefineAuthChallengeTriggerEvent,
  VerifyAuthChallengeResponseTriggerEvent,
} from 'aws-lambda';
import {createHash} from 'crypto';

import {
  handleCreateAuthChallenge,
  handleDefineAuthChallenge,
  handleVerifyAuthChallenge,
  resolveRedirectUrl,
  verifyMagicLink,
} from './magic_link';

const ALLOWED = 'https://app.example/auth/callback';
const USER = 'user@example.com';

function encodeBase64Url(value: string|Buffer|object): string {
  const buffer = Buffer.isBuffer(value) ?
      value :
      Buffer.from(typeof value === 'string' ? value : JSON.stringify(value));
  return buffer.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
}

function buildToken(payload: Record<string, unknown>, signature = 'sig'): string {
  const header = {alg: 'RS256', typ: 'JWT', kid: 'test-key'};
  return `${encodeBase64Url(header)}.${encodeBase64Url(payload)}.${
      encodeBase64Url(Buffer.from(signature))}`;
}

function baseDefine(
    overrides: {
      session?: DefineAuthChallengeTriggerEvent['request']['session'];
      clientMetadata?: Record<string, string>;
    } = {},
    ): DefineAuthChallengeTriggerEvent {
  return {
    version: '1',
    region: 'eu-west-1',
    userPoolId: 'pool',
    userName: USER,
    triggerSource: 'DefineAuthChallenge_Authentication',
    callerContext: {awsSdkVersion: 'aws-sdk-js-3', clientId: 'client'},
    request: {
      userAttributes: {sub: 'sub-1', email: USER},
      session: overrides.session ?? [],
      clientMetadata: overrides.clientMetadata ?? {
        signInMethod: 'MAGIC_LINK',
        redirectUrl: ALLOWED,
      },
      userNotFound: false,
    },
    response: {
      challengeName: '' as DefineAuthChallengeTriggerEvent['response']['challengeName'],
      issueTokens: false,
      failAuthentication: false,
    },
  };
}

function baseCreate(
    overrides: {
      session?: CreateAuthChallengeTriggerEvent['request']['session'];
      clientMetadata?: Record<string, string>;
      userName?: string;
      email?: string;
    } = {},
    ): CreateAuthChallengeTriggerEvent {
  return {
    version: '1',
    region: 'eu-west-1',
    userPoolId: 'pool',
    userName: overrides.userName ?? USER,
    triggerSource: 'CreateAuthChallenge_Authentication',
    callerContext: {awsSdkVersion: 'aws-sdk-js-3', clientId: 'client'},
    request: {
      userAttributes: {
        sub: 'sub-1',
        email: overrides.email ?? USER,
      },
      challengeName: 'CUSTOM_CHALLENGE',
      session: overrides.session ?? [{
        challengeName: 'CUSTOM_CHALLENGE',
        challengeResult: false,
      }],
      clientMetadata: overrides.clientMetadata ?? {
        signInMethod: 'MAGIC_LINK',
        redirectUrl: ALLOWED,
        haveMagicLinkToken: 'no',
      },
      userNotFound: false,
    },
    response: {
      publicChallengeParameters: {},
      privateChallengeParameters: {},
      challengeMetadata: '',
    },
  };
}

function baseVerify(answer: string): VerifyAuthChallengeResponseTriggerEvent {
  return {
    version: '1',
    region: 'eu-west-1',
    userPoolId: 'pool',
    userName: USER,
    triggerSource: 'VerifyAuthChallengeResponse_Authentication',
    callerContext: {awsSdkVersion: 'aws-sdk-js-3', clientId: 'client'},
    request: {
      userAttributes: {sub: 'sub-1', email: USER},
      privateChallengeParameters: {challenge: 'PROVIDE_MAGIC_LINK'},
      challengeAnswer: answer,
      userNotFound: false,
    },
    response: {answerCorrect: false},
  };
}

describe('resolveRedirectUrl', () => {
  beforeEach(() => {
    process.env.ALLOWED_REDIRECT_URLS = `${ALLOWED},http://localhost:3000/callback`;
  });

  afterEach(() => {
    delete process.env.ALLOWED_REDIRECT_URLS;
  });

  it('returns the provided allowlisted redirectUrl', () => {
    expect(resolveRedirectUrl({redirectUrl: ALLOWED})).toBe(ALLOWED);
  });

  it('falls back to the first allowlisted URL when redirectUrl is missing', () => {
    expect(resolveRedirectUrl({})).toBe(ALLOWED);
    expect(resolveRedirectUrl(null)).toBe(ALLOWED);
    expect(resolveRedirectUrl(undefined)).toBe(ALLOWED);
  });

  it('rejects redirectUrls that are not allowlisted', () => {
    expect(resolveRedirectUrl({redirectUrl: 'https://evil.example/phish'})).toBeUndefined();
  });

  it('trims whitespace on redirectUrl', () => {
    expect(resolveRedirectUrl({redirectUrl: `  ${ALLOWED}  `})).toBe(ALLOWED);
  });
});

describe('handleDefineAuthChallenge', () => {
  it('issues CUSTOM_CHALLENGE on an empty session', () => {
    const result = handleDefineAuthChallenge(baseDefine({session: []}));
    expect(result.response.challengeName).toBe('CUSTOM_CHALLENGE');
    expect(result.response.issueTokens).toBe(false);
    expect(result.response.failAuthentication).toBe(false);
  });

  it('issues tokens when the last CUSTOM_CHALLENGE succeeded', () => {
    const result = handleDefineAuthChallenge(baseDefine({
      session: [{
        challengeName: 'CUSTOM_CHALLENGE',
        challengeResult: true,
      }],
    }));
    expect(result.response.issueTokens).toBe(true);
    expect(result.response.failAuthentication).toBe(false);
  });

  it('denies non-CUSTOM_CHALLENGE session entries', () => {
    const result = handleDefineAuthChallenge(baseDefine({
      session: [{
        challengeName: 'PASSWORD_VERIFIER',
        challengeResult: true,
      }],
    }));
    expect(result.response.issueTokens).toBe(false);
    expect(result.response.failAuthentication).toBe(true);
  });

  it('denies unsupported signInMethod', () => {
    const result = handleDefineAuthChallenge(baseDefine({
      session: [{
        challengeName: 'CUSTOM_CHALLENGE',
        challengeResult: false,
      }],
      clientMetadata: {signInMethod: 'PASSWORD'},
    }));
    expect(result.response.failAuthentication).toBe(true);
  });

  it('continues after a failed attempt under the max', () => {
    const result = handleDefineAuthChallenge(baseDefine({
      session: [{
        challengeName: 'CUSTOM_CHALLENGE',
        challengeResult: false,
      }],
    }));
    expect(result.response.challengeName).toBe('CUSTOM_CHALLENGE');
    expect(result.response.failAuthentication).toBe(false);
    expect(result.response.issueTokens).toBe(false);
  });

  it('denies after too many unsuccessful attempts', () => {
    const failed = {
      challengeName: 'CUSTOM_CHALLENGE' as const,
      challengeResult: false,
    };
    const result = handleDefineAuthChallenge(baseDefine({
      session: [failed, failed, failed],
    }));
    expect(result.response.failAuthentication).toBe(true);
    expect(result.response.issueTokens).toBe(false);
  });
});

describe('handleCreateAuthChallenge', () => {
  beforeEach(() => {
    process.env.ALLOWED_REDIRECT_URLS = ALLOWED;
    process.env.MAGIC_LINK_SIGN_KEY_ARN = 'arn:aws:kms:eu-west-1:123:key/test';
    process.env.MAGIC_LINK_TABLE_NAME = 'magic-links';
    process.env.MAGIC_LINK_FROM_EMAIL = 'noreply@example.com';
    process.env.MAGIC_LINK_FROM_NAME = 'Auth';
    process.env.MAGIC_LINK_SUBJECT = 'Your sign-in link';
    mockDdbSend.mockReset();
    mockKmsSend.mockReset();
    mockSesSend.mockReset();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('asks for auth parameters on the first create (empty session)', async () => {
    const result = await handleCreateAuthChallenge(baseCreate({session: []}));
    expect(result.response.challengeMetadata).toBe('PROVIDE_AUTH_PARAMETERS');
    expect(result.response.publicChallengeParameters).toEqual({
      challenge: 'PROVIDE_AUTH_PARAMETERS',
    });
    expect(mockSesSend).not.toHaveBeenCalled();
    expect(mockKmsSend).not.toHaveBeenCalled();
  });

  it('skips email when the client already has a magic-link token', async () => {
    const result = await handleCreateAuthChallenge(baseCreate({
      clientMetadata: {
        signInMethod: 'MAGIC_LINK',
        haveMagicLinkToken: 'yes',
      },
    }));
    expect(result.response.challengeMetadata).toBe('MAGIC_LINK');
    expect(result.response.privateChallengeParameters).toEqual({
      challenge: 'PROVIDE_MAGIC_LINK',
    });
    expect(result.response.publicChallengeParameters).toEqual({});
    expect(mockSesSend).not.toHaveBeenCalled();
  });

  it('does not send email for unsupported signInMethod', async () => {
    const result = await handleCreateAuthChallenge(baseCreate({
      clientMetadata: {signInMethod: 'WEBAUTHN'},
    }));
    expect(mockSesSend).not.toHaveBeenCalled();
    expect(result.response.challengeMetadata).toBe('');
  });

  it('does not send email when redirectUrl is not allowlisted', async () => {
    const result = await handleCreateAuthChallenge(baseCreate({
      clientMetadata: {
        signInMethod: 'MAGIC_LINK',
        redirectUrl: 'https://evil.example/phish',
        haveMagicLinkToken: 'no',
      },
    }));
    expect(mockSesSend).not.toHaveBeenCalled();
    expect(result.response.challengeMetadata).toBe('');
  });

  it('signs, stores, and emails a magic link without exposing the token publicly', async () => {
    mockKmsSend.mockResolvedValueOnce({Signature: Buffer.from('signed-bytes')});
    mockDdbSend.mockResolvedValueOnce({});
    mockSesSend.mockResolvedValueOnce({});

    const result = await handleCreateAuthChallenge(baseCreate());

    expect(result.response.challengeMetadata).toBe('MAGIC_LINK');
    expect(result.response.publicChallengeParameters).toEqual({});
    expect(JSON.stringify(result.response)).not.toMatch(/signed-bytes|token=/);

    expect(mockKmsSend).toHaveBeenCalledTimes(1);
    expect(mockDdbSend).toHaveBeenCalledTimes(1);
    const putInput = mockDdbSend.mock.calls[0][0] as {
      TableName: string;
      Item: {username: string; sid: string; exp: number};
      ConditionExpression: string;
    };
    expect(putInput.TableName).toBe('magic-links');
    expect(putInput.Item.username).toBe(USER);
    expect(putInput.Item.sid).toEqual(expect.any(String));
    expect(putInput.ConditionExpression).toBe('attribute_not_exists(sid)');

    expect(mockSesSend).toHaveBeenCalledTimes(1);
    const sesInput = mockSesSend.mock.calls[0][0] as {
      Destination: {ToAddresses: string[]};
      Message: {
        Subject: {Data: string};
        Body: {Text: {Data: string}; Html: {Data: string}};
      };
      Source: string;
    };
    expect(sesInput.Destination.ToAddresses).toEqual([USER]);
    expect(sesInput.Source).toBe('Auth <noreply@example.com>');
    expect(sesInput.Message.Subject.Data).toBe('Your sign-in link');
    expect(sesInput.Message.Body.Text.Data).toContain(`${ALLOWED}?token=`);
    expect(sesInput.Message.Body.Html.Data).toContain(`${ALLOWED}?token=`);
    expect(sesInput.Message.Body.Text.Data).not.toContain('{{LOGIN_LINK}}');
  });

  it('uses username as recipient when email attribute is missing', async () => {
    mockKmsSend.mockResolvedValueOnce({Signature: Buffer.from('signed-bytes')});
    mockDdbSend.mockResolvedValueOnce({});
    mockSesSend.mockResolvedValueOnce({});

    await handleCreateAuthChallenge(baseCreate({
      userName: 'alias@example.com',
      email: '',
    }));

    const sesInput = mockSesSend.mock.calls[0][0] as {
      Destination: {ToAddresses: string[]};
    };
    expect(sesInput.Destination.ToAddresses).toEqual(['alias@example.com']);
  });
});

describe('verifyMagicLink / handleVerifyAuthChallenge', () => {
  const sid = '11111111-1111-1111-1111-111111111111';
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 900;

  beforeEach(() => {
    process.env.MAGIC_LINK_SIGN_KEY_ARN = 'arn:aws:kms:eu-west-1:123:key/test';
    process.env.MAGIC_LINK_TABLE_NAME = 'magic-links';
    mockDdbSend.mockReset();
    mockKmsSend.mockReset();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('returns false for malformed tokens', async () => {
    expect(await verifyMagicLink('not-a-jwt', USER)).toBe(false);
    expect(await verifyMagicLink('a.b', USER)).toBe(false);
    expect(mockKmsSend).not.toHaveBeenCalled();
  });

  it('returns false for expired token claims before calling KMS verify', async () => {
    const token = buildToken({sid, exp: now - 10, username: USER});
    expect(await verifyMagicLink(token, USER)).toBe(false);
    expect(mockKmsSend).not.toHaveBeenCalled();
  });

  it('returns false when KMS signature verification fails', async () => {
    mockKmsSend.mockResolvedValueOnce({SignatureValid: false});
    const token = buildToken({sid, exp, username: USER});
    expect(await verifyMagicLink(token, USER)).toBe(false);
    expect(mockDdbSend).not.toHaveBeenCalled();
  });

  it('returns false when no DynamoDB record exists', async () => {
    mockKmsSend.mockResolvedValueOnce({SignatureValid: true});
    mockDdbSend.mockResolvedValueOnce({Item: undefined});
    const token = buildToken({sid, exp, username: USER});
    expect(await verifyMagicLink(token, USER)).toBe(false);
  });

  it('returns false when username does not match the stored record', async () => {
    mockKmsSend.mockResolvedValueOnce({SignatureValid: true});
    mockDdbSend.mockResolvedValueOnce({
      Item: {sid, username: 'other@example.com', exp},
    });
    const token = buildToken({sid, exp, username: USER});
    expect(await verifyMagicLink(token, USER)).toBe(false);
  });

  it('returns false when token exp does not match the stored record', async () => {
    mockKmsSend.mockResolvedValueOnce({SignatureValid: true});
    mockDdbSend.mockResolvedValueOnce({
      Item: {sid, username: USER, exp: exp + 1},
    });
    const token = buildToken({sid, exp, username: USER});
    expect(await verifyMagicLink(token, USER)).toBe(false);
  });

  it('returns false when the magic link was already used', async () => {
    mockKmsSend.mockResolvedValueOnce({SignatureValid: true});
    mockDdbSend.mockResolvedValueOnce({
      Item: {sid, username: USER, exp, uat: now - 5},
    });
    const token = buildToken({sid, exp, username: USER});
    expect(await verifyMagicLink(token, USER)).toBe(false);
  });

  it('returns false on ConditionalCheckFailedException (lost single-use race)', async () => {
    mockKmsSend.mockResolvedValueOnce({SignatureValid: true});
    mockDdbSend
        .mockResolvedValueOnce({Item: {sid, username: USER, exp}})
        .mockRejectedValueOnce(
            Object.assign(new Error('conditional'), {
              name: 'ConditionalCheckFailedException',
            }),
        );
    const token = buildToken({sid, exp, username: USER});
    expect(await verifyMagicLink(token, USER)).toBe(false);
  });

  it('fails closed when marking used throws an unexpected error', async () => {
    mockKmsSend.mockResolvedValueOnce({SignatureValid: true});
    mockDdbSend
        .mockResolvedValueOnce({Item: {sid, username: USER, exp}})
        .mockRejectedValueOnce(new Error('dynamo unavailable'));
    const token = buildToken({sid, exp, username: USER});
    expect(await verifyMagicLink(token, USER)).toBe(false);
  });

  it('returns true and marks the link used on a valid token', async () => {
    mockKmsSend.mockResolvedValueOnce({SignatureValid: true});
    mockDdbSend
        .mockResolvedValueOnce({Item: {sid, username: USER, exp}})
        .mockResolvedValueOnce({});
    const token = buildToken({sid, exp, username: USER});

    expect(await verifyMagicLink(token, USER)).toBe(true);

    const verifyCall = mockKmsSend.mock.calls[0][0] as {
      Message: Buffer;
      Signature: Buffer;
    };
    const [headerB64, payloadB64] = token.split('.');
    const expectedDigest =
        createHash('sha256').update(`${headerB64}.${payloadB64}`).digest();
    expect(Buffer.compare(verifyCall.Message, expectedDigest)).toBe(0);

    const updateCall = mockDdbSend.mock.calls[1][0] as {
      _op: string;
      ConditionExpression: string;
      Key: {sid: string};
    };
    expect(updateCall._op).toBe('Update');
    expect(updateCall.Key.sid).toBe(sid);
    expect(updateCall.ConditionExpression).toBe('attribute_not_exists(uat)');
  });

  it('sets answerCorrect from verifyMagicLink in the Cognito verify trigger', async () => {
    mockKmsSend.mockResolvedValueOnce({SignatureValid: true});
    mockDdbSend
        .mockResolvedValueOnce({Item: {sid, username: USER, exp}})
        .mockResolvedValueOnce({});
    const token = buildToken({sid, exp, username: USER});

    const result = await handleVerifyAuthChallenge(baseVerify(token));
    expect(result.response.answerCorrect).toBe(true);
  });
});
