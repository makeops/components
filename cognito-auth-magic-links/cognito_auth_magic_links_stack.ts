#!/usr/bin/env node
/**
 * @fileoverview CDK app entry: sample stack built from {@link CognitoAuthMagicLinks}.
 */

import {FunctionUrlAuthType} from 'aws-cdk-lib/aws-lambda';
import {NodejsFunction} from 'aws-cdk-lib/aws-lambda-nodejs';
import * as cdk from 'aws-cdk-lib/core';
import {Construct} from 'constructs';

import {
  CognitoAuthMagicLinks,
  CognitoAuthMagicLinksProps,
  CognitoClientConfig,
  MagicLinkConfig,
} from './cognito_auth_magic_links';
import {CognitoAuthMagicLinksStackTestStack} from './test_stack';

export type {CognitoAuthMagicLinksProps, CognitoClientConfig, MagicLinkConfig};
export {CognitoAuthMagicLinks};

/** Props for {@link CognitoAuthMagicLinksStack}. */
export interface CognitoAuthMagicLinksStackProps extends cdk.StackProps,
                                                         CognitoAuthMagicLinksProps {}

/** Sample stack that only composes {@link CognitoAuthMagicLinks}. */
export class CognitoAuthMagicLinksStack extends cdk.Stack {
  readonly cognitoAuth: CognitoAuthMagicLinks;
  readonly authHandler: NodejsFunction;
  readonly apiHandler: NodejsFunction;

  constructor(scope: Construct, id: string, props: CognitoAuthMagicLinksStackProps = {}) {
    super(scope, id, props);

    this.cognitoAuth = new CognitoAuthMagicLinks(this, 'CognitoAuthMagicLinks', {
      authDebug: props.authDebug,
      apiDebug: props.apiDebug,
      magicLink: props.magicLink,
      cognito: props.cognito,
    });

    this.authHandler = this.cognitoAuth.authHandler;
    this.apiHandler = this.cognitoAuth.apiHandler;

    // Used to test the solution as we build it out.
    this.apiHandler.addFunctionUrl({authType: FunctionUrlAuthType.NONE});
  }
}

const app = new cdk.App();
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

// const magicLinks =
//     new CognitoAuthMagicLinksStack(app, 'CognitoAuthMagicLinksStack', {env});

new CognitoAuthMagicLinksStackTestStack(app, 'CognitoAuthMagicLinksStackTestStack', {
  env,
});
