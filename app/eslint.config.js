// Flat config for ESLint v9
// This mirrors the previous .eslintrc.cjs intent using flat config syntax
import tsParser from '@typescript-eslint/parser'
import tsPlugin from '@typescript-eslint/eslint-plugin'
import importPlugin from 'eslint-plugin-import'
import boundaries from 'eslint-plugin-boundaries'

export default [
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'src/shared/api/client/**', // OpenAPI generated
      'src/routeTree.gen.ts', // Router generated
    ],
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: './tsconfig.json',
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
      import: importPlugin,
      boundaries,
    },
    settings: {
      // Keep path groups like before; resolver TS optional
      'boundaries/elements': [
        { type: 'shared', pattern: 'src/shared/**' },
        { type: 'entities', pattern: 'src/entities/**' },
        { type: 'features', pattern: 'src/features/**' },
        { type: 'widgets', pattern: 'src/widgets/**' },
        { type: 'processes', pattern: 'src/processes/**' },
        { type: 'routes', pattern: 'src/routes/**' },
        { type: 'assets', pattern: 'src/**/*.{svg,png,jpg,jpeg,gif,webp}' },
      ],
      'boundaries/ignore': [
        '**/*.svg',
        '**/*.png',
        '**/*.jpg',
        '**/*.jpeg',
        '**/*.gif',
        '**/*.webp',
      ],
    },
    rules: {
      // parity with previous config
      'import/no-unresolved': 'off',
      'import/order': [
        'warn',
        {
          alphabetize: { order: 'asc', caseInsensitive: true },
          'newlines-between': 'always',
          groups: ['builtin', 'external', 'internal', 'parent', 'sibling', 'index', 'object'],
          pathGroups: [
            { pattern: '@/shared/**', group: 'internal', position: 'before' },
            { pattern: '@/entities/**', group: 'internal', position: 'before' },
            { pattern: '@/features/**', group: 'internal', position: 'before' },
            { pattern: '@/widgets/**', group: 'internal', position: 'before' },
            { pattern: '@/processes/**', group: 'internal', position: 'before' },
            { pattern: '@/routes/**', group: 'internal', position: 'before' },
          ],
          pathGroupsExcludedImportTypes: ['builtin', 'external'],
        },
      ],
      'boundaries/no-unknown': 'error',
      'boundaries/element-types': [
        'error',
        {
          default: 'disallow',
          rules: [
            { from: ['routes'], allow: ['widgets', 'features', 'entities', 'shared', 'processes', 'assets'] },
            { from: ['widgets'], allow: ['features', 'entities', 'shared'] },
            { from: ['features'], allow: ['entities', 'shared'] },
            { from: ['processes'], allow: ['features', 'entities', 'shared'] },
            { from: ['entities'], allow: ['shared'] },
            { from: ['shared'], allow: [] },
          ],
        },
      ],
    },
  },
]
