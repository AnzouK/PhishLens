// ESLint config for the Chrome extension (flat config, ESLint 9).
//
// Every rule fails CI (v1.12: the hygiene rules were promoted from
// "warn" once the existing warnings were fixed).
//   bug-class rules: dead code, duplicate keys, assigning to a const,
//                    broken typeof checks...
//   hygiene rules:   undefined names, unused variables, loose equality.
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
  "no-undef": "error",
  "no-unused-vars": ["error", { args: "none", caughtErrors: "none" }],
  "no-empty": ["error", { allowEmptyCatch: true }],
  eqeqeq: ["error", "smart"],
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
