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
  // An empty catch must say in a comment why the error is ignored.
  "no-empty": ["error", { allowEmptyCatch: false }],
  eqeqeq: ["error", "smart"],
};

export default [
  // Copies of extension/lib/ written by scripts/build_site.py (linted as
  // the extension's own files).
  { ignores: ["site/redact.js", "site/shared.js"] },
  {
    files: ["extension/**/*.js"],
    languageOptions: {
      ecmaVersion: "latest",
      // Classic scripts (no bundler), each wrapped in a function; the
      // popup is ES modules (below).
      sourceType: "script",
      globals: {
        ...globals.browser,
        ...globals.webextensions,
        ...globals.serviceworker,
        // The libraries of lib/, one globalThis name each, and the
        // namespace of the mail-page scripts (content_scripts/core.js).
        PhishLensApi: "readonly",
        PhishLensConstants: "readonly",
        PhishLensDom: "readonly",
        PhishLensGmail: "readonly",
        PhishLensHistory: "readonly",
        PhishLensI18n: "readonly",
        PhishLensRedact: "readonly",
        PhishLensReport: "readonly",
        PhishLensLocales: "writable",
        PhishLensLimeCache: "readonly",
        PhishLensShared: "readonly",
        PhishLensPage: "readonly",
      },
    },
    rules: { ...bugRules, ...hygieneRules },
  },
  {
    // The website: plain browser scripts.
    files: ["site/app.js", "site/nav.js", "site/lang.js"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "script",
      globals: { ...globals.browser },
    },
    rules: { ...bugRules, ...hygieneRules },
  },
  {
    files: ["extension/popup/*.js"],
    languageOptions: { sourceType: "module" },
  },
];
