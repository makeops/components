#!/usr/bin/env node
import {AttributeType, TableV2} from 'aws-cdk-lib/aws-dynamodb';
import {PolicyStatement} from 'aws-cdk-lib/aws-iam';
import {Key, KeySpec, KeyUsage} from 'aws-cdk-lib/aws-kms';
import {FunctionUrlAuthType, Runtime} from 'aws-cdk-lib/aws-lambda';
import {NodejsFunction} from 'aws-cdk-lib/aws-lambda-nodejs';
import * as cdk from 'aws-cdk-lib/core';
import {Construct} from 'constructs';
import {join} from 'path';

import {CognitoAuthMagicLinksStackTestStack} from './test_stack';

const FUNCTIONS_DIR = join(__dirname, 'functions');
const CONTENT_DIR = join(__dirname, 'content');

/** Magic-link feature wiring supplied by the deployer. */
export interface MagicLinkConfig {
  /** Verified SES identity used as From address. */
  fromEmail: string;
  fromName?: string;
  /** Email subject line. Default: `Your sign-in link`. */
  subject?: string;
  /**
   * Path to the plain-text email body template (`{{LOGIN_LINK}}` placeholder).
   * Default: this module's `content/magic-link.txt`.
   */
  textBody?: string;
  /**
   * Path to the HTML email body template (`{{LOGIN_LINK}}` placeholder).
   * Default: this module's `content/magic-link.html`.
   */
  htmlBody?: string;
  /** Absolute callback URLs allowed in clientMetadata.redirectUrl. */
  allowedRedirectUrls: string[];
  /** Feature gate. Default: true when `magicLink` is set. */
  enabled?: boolean;
}

/** Cognito User Pool client the API adapter calls. */
export interface CognitoClientConfig {
  userPoolId: string;
  clientId: string;
}

/** Props for {@link CognitoAuthMagicLinksStack}. */
export interface CognitoAuthMagicLinksStackProps extends cdk.StackProps {
  /** Verbose logs on the Cognito trigger Lambda. Default: `true`. */
  authDebug?: string;
  /** Verbose logs on the adapter Lambda. Default: `true`. */
  apiDebug?: string;
  /** Enable magic-link custom auth (creates table + KMS key). */
  magicLink?: MagicLinkConfig;
  /** User Pool + app client used by the API adapter Lambda. */
  cognito?: CognitoClientConfig;
}

/** CDK stack that creates Cognito trigger and adapter Lambdas. */
export class CognitoAuthMagicLinksStack extends cdk.Stack {
  readonly authHandler: NodejsFunction;
  readonly apiHandler: NodejsFunction;
  readonly magicLinkTable?: TableV2;
  readonly magicLinkSignKey?: Key;

  constructor(scope: Construct, id: string, props: CognitoAuthMagicLinksStackProps) {
    super(scope, id, props);

    const authDebug = props.authDebug ?? process.env.AUTH_DEBUG ?? 'true';
    const apiDebug = props.apiDebug ?? process.env.API_DEBUG ?? process.env.DEBUG ?? 'true';
    const magicLinkEnabled =
        !!props.magicLink && props.magicLink.enabled !== false;

    const magicLinkEnv: Record<string, string> = {
      MAGIC_LINK_ENABLED: magicLinkEnabled ? 'true' : 'false',
    };

    if (magicLinkEnabled && props.magicLink) {
      this.magicLinkSignKey = new Key(this, 'MagicLinkSignKey', {
        keySpec: KeySpec.RSA_2048,
        keyUsage: KeyUsage.SIGN_VERIFY,
        description: 'Signs and verifies magic-link JWTs',
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      });

      this.magicLinkTable = new TableV2(this, 'MagicLinkTable', {
        partitionKey: {name: 'sid', type: AttributeType.STRING},
        timeToLiveAttribute: 'exp',
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      });

      magicLinkEnv.MAGIC_LINK_TABLE_NAME = this.magicLinkTable.tableName;
      magicLinkEnv.MAGIC_LINK_SIGN_KEY_ARN = this.magicLinkSignKey.keyArn;
      magicLinkEnv.MAGIC_LINK_FROM_EMAIL = props.magicLink.fromEmail;
      magicLinkEnv.MAGIC_LINK_FROM_NAME = props.magicLink.fromName ?? 'Auth';
      magicLinkEnv.MAGIC_LINK_SUBJECT =
          props.magicLink.subject ?? 'Your sign-in link';
      magicLinkEnv.ALLOWED_REDIRECT_URLS =
          props.magicLink.allowedRedirectUrls.join(',');
    }

    const textBodyPath =
        props.magicLink?.textBody ?? join(CONTENT_DIR, 'magic-link.txt');
    const htmlBodyPath =
        props.magicLink?.htmlBody ?? join(CONTENT_DIR, 'magic-link.html');

    this.authHandler = new NodejsFunction(this, 'AuthHandler', {
      entry: join(FUNCTIONS_DIR, 'auth', 'auth_handler.ts'),
      handler: 'handler',
      runtime: Runtime.NODEJS_24_X,
      description: 'Cognito custom auth + pre-token generation triggers',
      environment: {
        DEBUG: authDebug,
        ...magicLinkEnv,
      },
      bundling: {
        commandHooks: {
          beforeBundling: () => [],
          beforeInstall: () => [],
          afterBundling: (_inputDir, outputDir) => [
            `cp "${textBodyPath}" "${outputDir}/magic-link.txt"`,
            `cp "${htmlBodyPath}" "${outputDir}/magic-link.html"`,
          ],
        },
      },
    });

    if (magicLinkEnabled && this.magicLinkTable && this.magicLinkSignKey) {
      this.magicLinkTable.grantReadWriteData(this.authHandler);
      this.magicLinkSignKey.grantSignVerify(this.authHandler);
      this.magicLinkSignKey.grant(this.authHandler, 'kms:DescribeKey');
      this.authHandler.addToRolePolicy(new PolicyStatement({
        actions: ['ses:SendEmail', 'ses:SendRawEmail'],
        resources: ['*'],
      }));
    }

    this.apiHandler = new NodejsFunction(this, 'ApiHandler', {
      entry: join(FUNCTIONS_DIR, 'api', 'auth_handler.ts'),
      handler: 'handler',
      runtime: Runtime.NODEJS_24_X,
      description: 'Adapter Lambda for Cognito auth operations',
      environment: {
        DEBUG: apiDebug,
        ...(props.cognito ? {
          COGNITO_USER_POOL_ID: props.cognito.userPoolId,
          COGNITO_CLIENT_ID: props.cognito.clientId,
        } : {}),
      },
    });

    if (props.cognito) {
      // InitiateAuth / RespondToAuthChallenge do not support resource-level IAM.
      this.apiHandler.addToRolePolicy(new PolicyStatement({
        actions: [
          'cognito-idp:InitiateAuth',
          'cognito-idp:RespondToAuthChallenge',
          'cognito-idp:GetUser',
          'cognito-idp:GlobalSignOut',
        ],
        resources: ['*'],
      }));
    }

    // Used to test the solution as we build it out.
    this.apiHandler.addFunctionUrl({authType: FunctionUrlAuthType.NONE});
  }
}

const app = new cdk.App();
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

const magicLinks =
    new CognitoAuthMagicLinksStack(app, 'CognitoAuthMagicLinksStack', {env});

new CognitoAuthMagicLinksStackTestStack(app, 'CognitoAuthMagicLinksStackTestStack', {
  env,
  authHandler: magicLinks.authHandler,
});
