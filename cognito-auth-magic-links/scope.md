# Scope: Cognito Auth Magic Links

## Problem

Amazon Cognito’s built-in passwordless options do not give full control over **URL-based magic-link** sign-in. Customers who need auth in a specific AWS region (compliance / data residency) often cannot rely on a third-party IdP and must host this themselves.

This component is a **TypeScript CDK construct** that provides Cognito-hook + adapter Lambda plumbing for magic links and WebAuthn, behind explicit feature gates. **Decoupling is key:** the deployer owns the User Pool and how clients reach the adapter.

## Goals

- Deliver a **CDK-only, TypeScript** construct (no multi-language IaC, no bundled front-end SDKs).
- Support **two gated features**, independently toggleable at deploy time:
  1. **Magic links** — email one-time URL → verify → **Cognito tokens**.
  2. **Auth keys (WebAuthn)** — register / assert credentials, without the full aws-samples FIDO2 surface (no SMS OTP, no React clients, lean defaults).
- Prefer **regional self-host** over SaaS auth for residency and control.
- Cognito User Pool triggers do the auth work; a **client adapter Lambda** maps app operations ([`docs/api.md`](docs/api.md)) onto Cognito.

## Resolved decisions

| Topic | Decision |
| --- | --- |
| Auth keys | **WebAuthn** |
| Tokens | Adapter returns **Cognito tokens** (not a separate session store) |
| User Pool | Deployer already has a pool **or** composes this construct into their CDK app; this project does **not** own/require creating the pool |
| Client entry | Core logic behind handlers that accept **API Gateway events or raw Lambda invokes**; front door is the deployer’s choice |
| Composition | Expose **Lambda function refs/names and related resources** for the deployer to wire (`addTrigger`, IAM, invoke permissions, etc.) |

## Architecture

### Cognito hooks first

| Trigger | Role |
| --- | --- |
| `DefineAuthChallenge` | Drive `CUSTOM_AUTH` for magic links / WebAuthn |
| `CreateAuthChallenge` | Issue challenge (send magic-link email, create WebAuthn challenge) |
| `VerifyAuthChallengeResponse` | Validate one-time token / WebAuthn assertion |
| Other hooks as needed | e.g. `PreSignUp`, `PreTokenGeneration` — only when required |

### Client adapter

- Thin Lambda(s) that translate app calls into Cognito `InitiateAuth` / `RespondToAuthChallenge` (and WebAuthn credential helpers where hooks are not enough).
- **Handler abstraction:** same core code, entrypoints for API Gateway **and** direct invoke.
- This package does **not** mandate API Gateway, Function URL, or any public front door.

### Decoupling / composition model

```
Deployer's CDK app
├── UserPool (theirs, or created in their app / test-stack)
├── This construct
│   ├── Trigger Lambdas (Define / Create / Verify / …)
│   ├── Adapter Lambda(s)
│   └── Supporting resources (DynamoDB, KMS, SES config, …)
└── Deployer wires:
    ├── userPool.addTrigger(..., construct.defineAuthChallengeFn)
    ├── grants / env for adapter → Cognito
    └── optional API Gateway / Function URL / direct invoke → adapter
```

- Outputs / public props: function constructs (and names/ARNs as useful), table/key refs, anything the deployer must attach.
- [`test-stack.ts`](test-stack.ts) is the reference composition: local User Pool + clients/groups + `addTrigger` wiring.

## Feature gates

| Gate | When enabled | When disabled |
| --- | --- | --- |
| `magicLinks` | Custom-auth path for magic links, SES send path, one-time token store, adapter ops | No magic-link challenge path or supporting infra |
| `authKeys` | WebAuthn custom-auth + credential storage + adapter ops | No WebAuthn path or supporting infra |

- Gates are **CDK props** (config object presence or explicit booleans).
- Either on alone, both on, or both off.
- Disabled features must not deploy unused Lambdas or tables.

## In scope

### Magic links (aligned with `docs/api.md`)

- Request magic link (email + `callbackUrl`) → **204**, no body, no enumeration.
- Link: `{callbackUrl}?token=<one-time-token>`.
- Verify → **Cognito tokens** surfaced as the bearer payload the app stores.
- Session / logout mapped to Cognito token validation / revocation (or global sign-out) as appropriate.
- Dev: log full magic-link URL server-side; never return it in the adapter response.

### Auth keys (WebAuthn)

- Gated credential register / challenge / assert via Cognito custom auth + minimal storage.
- Narrower than aws-samples FIDO2 (no SMS OTP; no bundled UI; usernameless/discoverable only if explicitly needed later).

### Platform (owned by this construct)

- Trigger + adapter Lambda code and CDK definitions.
- Supporting resources (e.g. DynamoDB, KMS, SES usage config).
- Clear exports for deployer wiring.

### Platform (owned by deployer)

- Cognito User Pool (and clients, groups, as in test-stack).
- Attaching triggers and exposing the adapter (API Gateway, direct invoke, etc.).

## Out of scope

| aws-samples includes | This project |
| --- | --- |
| FIDO2 + Magic Link + **SMS OTP step-up** | Magic links + WebAuthn only |
| Web / React / React Native clients | **CDK + Lambdas only** |
| Amplify helpers | Not required |
| Monolithic always-on construct | **Explicit gates**; lean defaults |
| Creating/owning the User Pool by default | **Deployer-owned** pool / composition |

Also out of scope:

- Non-TypeScript CDK.
- Mandating a specific public front door for the adapter.
- Parallel session tokens instead of Cognito tokens.
- Returning magic-link URLs in adapter responses.
- Account enumeration via magic-link responses.

## Design notes (from reference, not copy)

- Same Cognito Define / Create / Verify shape as [aws-samples/amazon-cognito-passwordless-auth](https://github.com/aws-samples/amazon-cognito-passwordless-auth); do not fork the full monorepo.
- One-time magic-link metadata in DynamoDB (single-use, throttle, expiry); prefer KMS-signed links.
- Optional config blocks as enablement: `magicLink?: {…}`, `authKeys?: {…}`.

## Success criteria

1. Construct deploys with `magicLinks` and/or `authKeys` independently.
2. Challenge create/verify runs in Cognito User Pool triggers.
3. Adapter returns Cognito tokens; handlers work for API Gateway and raw invoke.
4. Deployer can wire an existing (or app-local) User Pool using exported functions/resources; test-stack demonstrates this.
5. No SMS OTP, no bundled front-end auth SDK, no unused infra when a gate is off.
