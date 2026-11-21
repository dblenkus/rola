import { readdirSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import reactHooks from 'eslint-plugin-react-hooks';
import { defineConfig, globalIgnores } from 'eslint/config';
import tseslint from 'typescript-eslint';

const srcDir = join(import.meta.dirname, 'src');
const featuresDir = join(srcDir, 'features');
const features = readdirSync(featuresDir, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name);

// A feature imports another feature only through its index. The import is
// resolved against the importing file, so no spelling of the path (through
// features/, src/ or ./ and ../ segments) reaches past another feature's index.
const featureImports = {
  meta: {
    type: 'problem',
    schema: [],
    messages: {
      deepImport:
        'Import another feature through its index.ts, as ../<feature>.',
    },
  },
  create(context) {
    const [ownFeature] = relative(featuresDir, context.filename).split(sep);
    const check = (node) => {
      const path = node.source?.value;
      if (typeof path !== 'string' || !path.startsWith('.')) {
        return;
      }
      const target = resolve(dirname(context.filename), path);
      const [feature, ...rest] = relative(featuresDir, target).split(sep);
      if (feature === ownFeature || !features.includes(feature)) {
        return;
      }
      if (
        rest.length === 0 ||
        (rest.length === 1 && /^index(\.tsx?)?$/.test(rest[0]))
      ) {
        return;
      }
      context.report({ node: node.source, messageId: 'deepImport' });
    };
    return {
      ImportDeclaration: check,
      ExportNamedDeclaration: check,
      ExportAllDeclaration: check,
      ImportExpression: check,
    };
  },
};

// Shared code imports no app or feature code, however the path is spelled.
const sharedImports = {
  meta: {
    type: 'problem',
    schema: [],
    messages: {
      upwardImport: 'Shared code imports no app or feature code.',
    },
  },
  create(context) {
    const check = (node) => {
      const path = node.source?.value;
      if (typeof path !== 'string' || !path.startsWith('.')) {
        return;
      }
      const target = resolve(dirname(context.filename), path);
      const [top] = relative(srcDir, target).split(sep);
      if (top === 'app' || top === 'features') {
        context.report({ node: node.source, messageId: 'upwardImport' });
      }
    };
    return {
      ImportDeclaration: check,
      ExportNamedDeclaration: check,
      ExportAllDeclaration: check,
      ImportExpression: check,
    };
  },
};

const local = {
  rules: { 'feature-imports': featureImports, 'shared-imports': sharedImports },
};

export default defineConfig(
  globalIgnores(['dist', 'src/shared/api/generated-api.ts']),
  js.configs.recommended,
  tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    extends: [reactHooks.configs.flat.recommended],
    rules: {
      'react-hooks/exhaustive-deps': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_' },
      ],
      'no-console': ['error', { allow: ['warn', 'error'] }],
      eqeqeq: ['error', 'always'],
    },
  },
  {
    // The classic scripts that index.html links, which run in the page.
    files: ['public/**/*.js'],
    languageOptions: {
      sourceType: 'script',
      globals: { document: 'readonly', localStorage: 'readonly' },
    },
  },
  {
    files: ['src/shared/**/*.{ts,tsx}'],
    plugins: { local },
    rules: {
      'local/shared-imports': 'error',
    },
  },
  {
    files: ['src/features/**/*.{ts,tsx}'],
    plugins: { local },
    rules: {
      'local/feature-imports': 'error',
    },
  },
  prettier,
);
