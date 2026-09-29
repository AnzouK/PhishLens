// ESLint config for the Chrome extension (flat config, ESLint 9).
//
// Two tiers on purpose:
//   error: rules that only fire on real bugs (dead code, duplicate keys,
//          assigning to a const, broken typeof checks...). These fail CI.
//   warn:  rules that are useful but noisy on existing code (undefined
//          names across script files, unused variables). They show up as
//          annotations on the pull request without blocking it. Promote
//          them to "error" once the warnings are cleaned up.
import globals from "globals";

const bugRules = {
  "no-const-assign": "error",
  "no-dupe-args": "error",
  "no-dupe-else-if": "error",
  "no-dupe-keys": "error",
  "no-duplicate-case": "error",
  "no-func-assign": "error",
  "no-invalid-regexp": "error",
  "no-obj-calls": "error",
  "no-self-assign": "error",
  "no-setter-return": "error",
  "no-sparse-arrays": "error",
  "no-unreachable": "error",
  "no-unsafe-finally": "error",
  "no-unsafe-negation": "error",
  "getter-return": "error",
  "use-isnan": "error",
  "valid-typeof": "error",
};

const hygieneRules = {
  "no-undef": "warn",
  "no-unused-vars": ["warn", { args: "none", caughtErrors: "none" }],
  "no-empty": ["warn", { allowEmptyCatch: true }],
  eqeqeq: ["warn", "smart"],
};

export default [
  {
    files: ["extension/**/*.js"],
    languageOptions: {
      ecmaVersion: "latest",
      // Classic scripts: the extension has no bundler and no ES modules.
      sourceType: "script",
      globals: {
        ...globals.browser,
        ...globals.webextensions,
        ...globals.serviceworker,
        // Shared between files through globalThis (see lib/*.js).
        PhishLensHistory: "readonly",
        PhishLensLimeCache: "readonly",
      },
    },
    rules: { ...bugRules, ...hygieneRules },
  },
];
