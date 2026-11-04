import type { BrowserOptions } from '@sentry/react';

export const sentryOptions: BrowserOptions = {
  dsn: 'https://0d870d17fdb1421b8545267fc711b19a@o84586.ingest.sentry.io/5272406',
  // API requests carry an Authorization token, and activation and
  // password-reset links carry a token query parameter.
  dataCollection: {
    userInfo: false,
    cookies: false,
    httpHeaders: { request: false, response: false },
    httpBodies: [],
    urlQueryParams: false,
    genAI: { inputs: false, outputs: false },
    mcp: { inputs: false, outputs: false },
    databaseQueryData: false,
    queues: false,
    graphQL: { document: false, variables: false },
    stackFrameVariables: false,
  },
};
