import eslintPluginAstro from 'eslint-plugin-astro';
import tsEslint from 'typescript-eslint';

export default [
  {
    ignores: ['dist', '.astro'],
  },
  // add more generic rule sets here, such as:
  // js.configs.recommended,
  ...tsEslint.configs.recommended,
  ...eslintPluginAstro.configs.recommended,
  {
    rules: {
      // customize or disable rules here
    },
  },
];
