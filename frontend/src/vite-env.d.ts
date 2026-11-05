interface ViteTypeOptions {
  strictImportMetaEnv: unknown;
}

interface ImportMetaEnv {
  readonly VITE_PAYPAL_CLIENT_ID?: string;
  readonly VITE_SENTRY_DSN?: string;
}
