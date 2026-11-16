import js from '@eslint/js';
import parser from '@typescript-eslint/parser';
import globals from 'globals';
export default [
 { ignores: ['dist/**', 'node_modules/**'] },
 js.configs.recommended,
 { files: ['src/**/*.ts'], languageOptions: { parser, ecmaVersion: 'latest', sourceType: 'module', globals: { ...globals.browser, ...globals.node } }, rules: { 'no-undef': 'warn', 'no-unused-vars': ['warn', { args: 'none', caughtErrors: 'none' }], 'no-empty': ['warn', { allowEmptyCatch: true }], 'no-redeclare': 'warn', 'no-unreachable': 'warn', 'no-unused-private-class-members': 'warn', 'no-async-promise-executor': 'warn', 'no-prototype-builtins': 'warn' } },
];
