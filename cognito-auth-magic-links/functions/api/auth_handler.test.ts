/**
 * @fileoverview Unit tests for the client-facing Cognito auth API adapter.
 */

const mockCognitoSend = jest.fn();

jest.mock('@aws-sdk/client-cognito-identity-provider', () => {
  const actual = jest.requireActual('@aws-sdk/client-cognito-identity-provider');
  return {
    ...actual,
    CognitoIdentityProviderClient: jest.fn().mockImplementation(() => ({
      send: (...args: unknown[]) => mockCognitoSend(...args),
    })),
  };
});

import {
  GetUserCommand,
  GlobalSignOutCommand,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
} from '@aws-sdk/client-cognito-identity-provider';

import {handler} from './auth_handler';

function encodeBase64Url(value: object): string {
  return Buffer.from(JSON.stringify(value))
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
}

function magicLinkToken(username: string): string {
  return `${encodeBase64Url({alg: 'none'})}.${
      encodeBase64Url({sid: 'sid-1', username, exp: 9999999999})}.sig`;
}

function directEvent(
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
    ): Record<string, unknown> {
  return {method, path, headers, body};
}

function httpApiEvent(
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
    ): Record<string, unknown> {
  return {
    version: '2.0',
    rawPath: path,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    isBase64Encoded: false,
    requestContext: {http: {method, path}},
  };
}

function parseHttpBody(response: unknown): unknown {
  const r = response as {statusCode: number; body: string};
  return r.body ? JSON.parse(r.body) : null;
}

describe('api auth handler', () => {
  beforeEach(() => {
    mockCognitoSend.mockReset();
    process.env.COGNITO_CLIENT_ID = 'test-client-id';
    process.env.COGNITO_USER_POOL_ID = 'eu-west-1_pool';
    jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    delete process.env.COGNITO_CLIENT_ID;
    delete process.env.COGNITO_USER_POOL_ID;
    jest.restoreAllMocks();
  });

  describe('routing and event shapes', () => {
    it('returns 404 for unknown routes', async () => {
      const result = await handler(
          directEvent('GET', '/api/unknown')) as {statusCode: number; body: unknown};
      expect(result.statusCode).toBe(404);
      expect(result.body).toEqual({error: 'Not found'});
    });

    it('normalizes trailing slashes on paths', async () => {
      mockCognitoSend
          .mockResolvedValueOnce({
            Session: 's1',
            ChallengeName: 'CUSTOM_CHALLENGE',
          })
          .mockResolvedValueOnce({});
      const result = await handler(directEvent(
          'POST',
          '/api/auth/magic-link/',
          {email: 'user@example.com', callbackUrl: 'https://app.example/cb'},
      )) as {statusCode: number};
      expect(result.statusCode).toBe(204);
    });

    it('returns HTTP envelope for API Gateway / Function URL events', async () => {
      mockCognitoSend
          .mockResolvedValueOnce({
            Session: 's1',
            ChallengeName: 'CUSTOM_CHALLENGE',
          })
          .mockResolvedValueOnce({});
      const result = await handler(httpApiEvent(
          'POST',
          '/api/auth/magic-link',
          {email: 'user@example.com', callbackUrl: 'https://app.example/cb'},
      )) as {statusCode: number; body: string; headers?: Record<string, string>};
      expect(result.statusCode).toBe(204);
      expect(result.body).toBe('');
      expect(result.headers?.['content-type']).toBe('application/json');
    });

    it('rejects unsupported event shapes for direct invoke', async () => {
      const result = await handler('not-an-object');
      expect(result).toEqual({error: 'Unsupported event shape'});
    });
  });

  describe('POST /api/auth/magic-link', () => {
    it('rejects invalid email with 400', async () => {
      const result = await handler(directEvent(
          'POST',
          '/api/auth/magic-link',
          {email: 'not-an-email', callbackUrl: 'https://app.example/cb'},
      )) as {statusCode: number; body: unknown};
      expect(result.statusCode).toBe(400);
      expect(result.body).toEqual({error: 'Invalid email'});
      expect(mockCognitoSend).not.toHaveBeenCalled();
    });

    it('rejects callback URLs with query strings', async () => {
      const result = await handler(directEvent(
          'POST',
          '/api/auth/magic-link',
          {
            email: 'user@example.com',
            callbackUrl: 'https://app.example/cb?x=1',
          },
      )) as {statusCode: number; body: unknown};
      expect(result.statusCode).toBe(400);
      expect(result.body).toEqual({error: 'Invalid callback URL'});
    });

    it('initiates CUSTOM_AUTH and responds with magic-link metadata', async () => {
      mockCognitoSend
          .mockResolvedValueOnce({
            Session: 'session-1',
            ChallengeName: 'CUSTOM_CHALLENGE',
          })
          .mockResolvedValueOnce({Session: 'session-2'});

      const result = await handler(directEvent(
          'POST',
          '/api/auth/magic-link',
          {
            email: 'User@Example.com ',
            callbackUrl: 'https://app.example/auth/callback',
          },
      )) as {statusCode: number; body: unknown};

      expect(result.statusCode).toBe(204);
      expect(result.body).toBeNull();
      expect(mockCognitoSend).toHaveBeenCalledTimes(2);

      const initiate = mockCognitoSend.mock.calls[0][0];
      expect(initiate).toBeInstanceOf(InitiateAuthCommand);
      expect(initiate.input).toEqual({
        AuthFlow: 'CUSTOM_AUTH',
        ClientId: 'test-client-id',
        AuthParameters: {USERNAME: 'user@example.com'},
      });

      const respond = mockCognitoSend.mock.calls[1][0];
      expect(respond).toBeInstanceOf(RespondToAuthChallengeCommand);
      expect(respond.input.ClientMetadata).toEqual({
        signInMethod: 'MAGIC_LINK',
        redirectUrl: 'https://app.example/auth/callback',
        haveMagicLinkToken: 'no',
      });
      expect(respond.input.ChallengeResponses.USERNAME).toBe('user@example.com');
    });

    it('still returns 204 when Cognito errors (no account enumeration)', async () => {
      mockCognitoSend.mockRejectedValueOnce(new Error('UserNotFoundException'));
      const result = await handler(directEvent(
          'POST',
          '/api/auth/magic-link',
          {
            email: 'missing@example.com',
            callbackUrl: 'https://app.example/cb',
          },
      )) as {statusCode: number};
      expect(result.statusCode).toBe(204);
    });

    it('still returns 204 when InitiateAuth returns an unexpected challenge', async () => {
      mockCognitoSend.mockResolvedValueOnce({
        Session: 's1',
        ChallengeName: 'PASSWORD_VERIFIER',
      });
      const result = await handler(directEvent(
          'POST',
          '/api/auth/magic-link',
          {
            email: 'user@example.com',
            callbackUrl: 'https://app.example/cb',
          },
      )) as {statusCode: number};
      expect(result.statusCode).toBe(204);
      expect(mockCognitoSend).toHaveBeenCalledTimes(1);
    });
  });

  describe('POST /api/auth/verify', () => {
    it('rejects a missing token', async () => {
      const result = await handler(
          directEvent('POST', '/api/auth/verify', {})) as {
        statusCode: number;
        body: unknown;
      };
      expect(result.statusCode).toBe(400);
      expect(result.body).toEqual({error: 'Missing token'});
    });

    it('rejects tokens without a username claim', async () => {
      const token = `${encodeBase64Url({alg: 'none'})}.${
          encodeBase64Url({sid: 'x', exp: 9999999999})}.sig`;
      const result = await handler(directEvent(
          'POST', '/api/auth/verify', {token})) as {
        statusCode: number;
        body: unknown;
      };
      expect(result.statusCode).toBe(400);
      expect(result.body).toEqual({error: 'Invalid or expired token'});
    });

    it('exchanges a valid magic-link token for a Cognito access token', async () => {
      const token = magicLinkToken('user@example.com');
      mockCognitoSend
          .mockResolvedValueOnce({
            Session: 's1',
            ChallengeName: 'CUSTOM_CHALLENGE',
          })
          .mockResolvedValueOnce({
            Session: 's2',
            ChallengeName: 'CUSTOM_CHALLENGE',
          })
          .mockResolvedValueOnce({
            AuthenticationResult: {AccessToken: 'access-token-123'},
          });

      const result = await handler(directEvent(
          'POST', '/api/auth/verify', {token})) as {
        statusCode: number;
        body: unknown;
      };

      expect(result.statusCode).toBe(200);
      expect(result.body).toEqual({token: 'access-token-123'});
      expect(mockCognitoSend).toHaveBeenCalledTimes(3);

      const finalRespond = mockCognitoSend.mock.calls[2][0];
      expect(finalRespond).toBeInstanceOf(RespondToAuthChallengeCommand);
      expect(finalRespond.input.ChallengeResponses.ANSWER).toBe(token);
      expect(finalRespond.input.ClientMetadata.haveMagicLinkToken).toBe('yes');
    });

    it('returns 400 when Cognito does not issue tokens', async () => {
      const token = magicLinkToken('user@example.com');
      mockCognitoSend
          .mockResolvedValueOnce({
            Session: 's1',
            ChallengeName: 'CUSTOM_CHALLENGE',
          })
          .mockResolvedValueOnce({
            Session: 's2',
            ChallengeName: 'CUSTOM_CHALLENGE',
          })
          .mockResolvedValueOnce({AuthenticationResult: {}});

      const result = await handler(directEvent(
          'POST', '/api/auth/verify', {token})) as {
        statusCode: number;
        body: unknown;
      };
      expect(result.statusCode).toBe(400);
      expect(result.body).toEqual({error: 'Invalid or expired token'});
    });

    it('returns 400 when Cognito throws during verify', async () => {
      const token = magicLinkToken('user@example.com');
      mockCognitoSend.mockRejectedValueOnce(new Error('NotAuthorizedException'));
      const result = await handler(directEvent(
          'POST', '/api/auth/verify', {token})) as {
        statusCode: number;
        body: unknown;
      };
      expect(result.statusCode).toBe(400);
      expect(result.body).toEqual({error: 'Invalid or expired token'});
    });
  });

  describe('GET /api/auth/session', () => {
    it('requires a Bearer token', async () => {
      const result = await handler(
          directEvent('GET', '/api/auth/session')) as {
        statusCode: number;
        body: unknown;
      };
      expect(result.statusCode).toBe(401);
      expect(result.body).toEqual({
        error: 'Missing or invalid Authorization header',
      });
    });

    it('returns email for a valid access token', async () => {
      mockCognitoSend.mockResolvedValueOnce({
        UserAttributes: [
          {Name: 'sub', Value: 'sub-1'},
          {Name: 'email', Value: 'user@example.com'},
        ],
      });
      const result = await handler(directEvent(
          'GET',
          '/api/auth/session',
          undefined,
          {Authorization: 'Bearer access-token'},
      )) as {statusCode: number; body: unknown};
      expect(result.statusCode).toBe(200);
      expect(result.body).toEqual({email: 'user@example.com'});
      expect(mockCognitoSend.mock.calls[0][0]).toBeInstanceOf(GetUserCommand);
    });

    it('returns email:null for invalid/expired tokens (not 401)', async () => {
      mockCognitoSend.mockRejectedValueOnce(new Error('NotAuthorizedException'));
      const result = await handler(directEvent(
          'GET',
          '/api/auth/session',
          undefined,
          {authorization: 'Bearer bad'},
      )) as {statusCode: number; body: unknown};
      expect(result.statusCode).toBe(200);
      expect(result.body).toEqual({email: null});
    });
  });

  describe('POST /api/auth/logout', () => {
    it('requires a Bearer token', async () => {
      const result = await handler(
          directEvent('POST', '/api/auth/logout')) as {
        statusCode: number;
        body: unknown;
      };
      expect(result.statusCode).toBe(401);
    });

    it('returns 204 after GlobalSignOut', async () => {
      mockCognitoSend.mockResolvedValueOnce({});
      const result = await handler(directEvent(
          'POST',
          '/api/auth/logout',
          undefined,
          {Authorization: 'Bearer access-token'},
      )) as {statusCode: number; body: unknown};
      expect(result.statusCode).toBe(204);
      expect(result.body).toBeNull();
      expect(mockCognitoSend.mock.calls[0][0]).toBeInstanceOf(GlobalSignOutCommand);
    });

    it('returns 204 even when GlobalSignOut fails (idempotent)', async () => {
      mockCognitoSend.mockRejectedValueOnce(new Error('NotAuthorizedException'));
      const result = await handler(directEvent(
          'POST',
          '/api/auth/logout',
          undefined,
          {Authorization: 'Bearer access-token'},
      )) as {statusCode: number};
      expect(result.statusCode).toBe(204);
    });
  });

  describe('GET /api/account', () => {
    it('requires a Bearer token', async () => {
      const result = await handler(directEvent('GET', '/api/account')) as {
        statusCode: number;
        body: unknown;
      };
      expect(result.statusCode).toBe(401);
    });

    it('returns the account email for a valid session', async () => {
      mockCognitoSend.mockResolvedValueOnce({
        UserAttributes: [{Name: 'email', Value: 'user@example.com'}],
      });
      const result = await handler(directEvent(
          'GET',
          '/api/account',
          undefined,
          {Authorization: 'Bearer access-token'},
      )) as {statusCode: number; body: unknown};
      expect(result.statusCode).toBe(200);
      expect(result.body).toEqual({email: 'user@example.com'});
    });

    it('returns 401 for invalid sessions', async () => {
      mockCognitoSend.mockRejectedValueOnce(new Error('NotAuthorizedException'));
      const result = await handler(directEvent(
          'GET',
          '/api/account',
          undefined,
          {Authorization: 'Bearer bad'},
      )) as {statusCode: number; body: unknown};
      expect(result.statusCode).toBe(401);
      expect(result.body).toEqual({error: 'Invalid or expired session'});
    });

    it('returns 401 when the user has no email attribute', async () => {
      mockCognitoSend.mockResolvedValueOnce({UserAttributes: []});
      const result = await handler(directEvent(
          'GET',
          '/api/account',
          undefined,
          {Authorization: 'Bearer access-token'},
      )) as {statusCode: number; body: unknown};
      expect(result.statusCode).toBe(401);
    });
  });

  describe('HTTP body parsing', () => {
    it('parses base64-encoded API Gateway bodies', async () => {
      mockCognitoSend
          .mockResolvedValueOnce({
            Session: 's1',
            ChallengeName: 'CUSTOM_CHALLENGE',
          })
          .mockResolvedValueOnce({});

      const payload = Buffer.from(JSON.stringify({
                       email: 'user@example.com',
                       callbackUrl: 'https://app.example/cb',
                     }))
                          .toString('base64');

      const result = await handler({
        version: '2.0',
        rawPath: '/api/auth/magic-link',
        headers: {},
        body: payload,
        isBase64Encoded: true,
        requestContext: {http: {method: 'POST', path: '/api/auth/magic-link'}},
      });

      expect((result as {statusCode: number}).statusCode).toBe(204);
      expect(parseHttpBody(result)).toBeNull();
    });
  });
});
