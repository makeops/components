# Cognito Magic Links Authentication

This component provides the helper functions to support deployment of a magic link solution on top of Amazon Cognito.

## Challenge

Currently Amazon Cognito only has code-based authentication for magic links. This solution provides some of the plumbing that supports extending this to full URL based authentication.

### Why this vs other tools?

Often customers want to operate authentication in a specific AWS region due to compliance and data residency reasons. When a service provider doesn't offer this, it's often required to host this yourself.

The Cognito Magic Links solution provides a simple wrapper around this.
