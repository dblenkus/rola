import type { BrowserOptions } from '@sentry/react';

export const sentryOptions: BrowserOptions = {
  // Empty in development, which turns reporting off.
  dsn: import.meta.env.VITE_SENTRY_DSN,
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
