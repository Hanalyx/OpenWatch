import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';
import prettier from 'eslint-config-prettier';
import globals from 'globals';

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'coverage/**',
      'src/api/schema.d.ts', // generated from api/openapi.yaml
      '**/*.config.{js,ts,cjs,mjs}',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.es2022 },
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    plugins: { react, 'react-hooks': reactHooks },
    settings: { react: { version: 'detect' } },
    rules: {
      ...react.configs.recommended.rules,
      'react/react-in-jsx-scope': 'off', // React 19 automatic JSX runtime
      'react/prop-types': 'off', // TypeScript checks props
      'react/no-unescaped-entities': 'off', // noisy; apostrophes in copy are fine
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      // Honor the codebase's `_`-prefix convention for intentionally-unused
      // params/vars (e.g. positional callback args that aren't referenced).
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' },
      ],
    },
  },
  {
    // Test files legitimately use `any` for mocks/spies and require() for
    // dynamic module assertions; relax those two there only.
    files: ['**/*.test.{ts,tsx}', 'tests/**/*.{ts,tsx}'],
    languageOptions: { globals: { ...globals.node } },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-require-imports': 'off',
    },
  },
  // Must be last: turns off eslint rules that conflict with Prettier formatting.
  prettier,
);
