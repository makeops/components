#!/usr/bin/env node
import { FunctionUrlAuthType, Runtime } from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import { join } from 'path';
import { CognitoAuthMagicLinksStackTestStack } from './test-stack';

const FUNCTIONS_DIR = join(__dirname, 'functions');

export interface CognitoAuthMagicLinksStackProps extends cdk.StackProps {
  debug?: string;
}

export class CognitoAuthMagicLinksStack extends cdk.Stack {
  readonly authHandler: NodejsFunction;
  readonly apiHandler: NodejsFunction;

  constructor(scope: Construct, id: string, props: CognitoAuthMagicLinksStackProps) {
    super(scope, id, props);

    const environment = {
      DEBUG: props.debug ?? '',
    };

    this.authHandler = new NodejsFunction(this, 'AuthHandler', {
      entry: join(FUNCTIONS_DIR, 'auth', 'auth-handler.ts'),
      handler: 'handler',
      runtime: Runtime.NODEJS_24_X,
      description: 'Cognito custom auth + pre-token generation triggers',
      environment,
    });

    this.apiHandler = new NodejsFunction(this, 'ApiHandler', {
      entry: join(FUNCTIONS_DIR, 'api', 'auth-handler.ts'),
      handler: 'handler',
      runtime: Runtime.NODEJS_24_X,
      description: 'Adapter Lambda for Cognito auth operations',
      environment,
    });

    // Used to test the solution as we build it out
    this.apiHandler.addFunctionUrl({ authType: FunctionUrlAuthType.NONE })

  }
}

const app = new cdk.App();
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

const magicLinks = new CognitoAuthMagicLinksStack(app, 'CognitoAuthMagicLinksStack', { env });

new CognitoAuthMagicLinksStackTestStack(app, 'CognitoAuthMagicLinksStackTestStack', {
  env,
  authHandler: magicLinks.authHandler,
});
