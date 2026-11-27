import firebaseRulesPlugin from '@firebase/eslint-plugin-security-rules';

export default [
  {
    ignores: [
      'dist/**/*',
      'node_modules/**/*',
      'agents-management/dist/**/*',
      'agents-program/dist/**/*',
      'src/**/*',
      'agents-management/src/**/*',
      'agents-program/src/**/*',
    ],
  },
  firebaseRulesPlugin.configs['flat/recommended'],
];
