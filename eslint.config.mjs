// ESLint config for the Chrome extension (flat config, ESLint 9).
//
// Every rule fails CI (v1.12: the hygiene rules were promoted from
// "warn" once the existing warnings were fixed).
//   bug-class rules: dead code, duplicate keys, assigning to a const,
//                    broken typeof checks...
//   hygiene rules:   undefined names, unused variables, loose equality.
import fs from "node:fs";
import path from "node:path";
import globals from "globals";

// The content scripts of one manifest entry run in one shared scope: a
// top-level name declared in core.js is visible in banner.js, gmail.js...
// Those names are read from the files, so the list never goes stale.
const CONTENT_DIR = "extension/content_scripts";
const contentGlobals = {};
for (const file of fs.readdirSync(CONTENT_DIR).filter((f) => f.endsWith(".js"))) {
  const src = fs.readFileSync(path.join(CONTENT_DIR, file), "utf8");
  for (const m of src.matchAll(/^(?:async\s+)?(?:function|const|let|class)\s+([A-Za-z_$][\w$]*)/gm)) {
    contentGlobals[m[1]] = "writable";
  }
  for (const m of src.matchAll(/^const\s*\{([^}]+)\}\s*=/gm)) {
    for (const name of m[1].split(",")) contentGlobals[name.trim()] = "writable";
  }
}

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
        PhishLensShared: "readonly",
      },
    },
    rules: { ...bugRules, ...hygieneRules },
  },
  {
    files: [`${CONTENT_DIR}/*.js`],
    languageOptions: { globals: contentGlobals },
    rules: {
      // A top-level function of one content script is used by the others.
      "no-unused-vars": ["error", { vars: "local", args: "none", caughtErrors: "none" }],
    },
  },
];
