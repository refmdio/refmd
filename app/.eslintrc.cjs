/* eslint-env node */
module.exports = {
  root: true,
  ignorePatterns: [
    'dist/**',
    'node_modules/**',
    'src/shared/api/client/**', // OpenAPI generated
    'src/routeTree.gen.ts',     // Router generated
  ],
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint', 'boundaries', 'import'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:import/recommended',
  ],
  settings: {
    'import/resolver': {
      typescript: {
        project: './tsconfig.json',
      },
    },
    'boundaries/elements': [
      { type: 'shared', pattern: 'src/shared/**' },
      { type: 'entities', pattern: 'src/entities/**' },
      { type: 'features', pattern: 'src/features/**' },
      { type: 'widgets', pattern: 'src/widgets/**' },
      { type: 'processes', pattern: 'src/processes/**' },
      { type: 'routes', pattern: 'src/routes/**' },
    ],
  },
  rules: {
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
          { from: ['routes'], allow: ['widgets', 'features', 'entities', 'shared', 'processes'] },
          { from: ['widgets'], allow: ['features', 'entities', 'shared'] },
          { from: ['features'], allow: ['entities', 'shared'] },
          { from: ['processes'], allow: ['features', 'entities', 'shared'] },
          { from: ['entities'], allow: ['shared'] },
          { from: ['shared'], allow: [] },
        ],
      },
    ],
  },
}

