// Removing personal data from an email before it is shared.
// Used before a report leaves the browser (the server runs the same
// rules again, backend/redaction.py). What is removed:
//   email addresses, phone numbers, long numbers (accounts, cards, codes,
//   IBANs), the path and query of every link (the domain stays: it is
//   what tells a phishing site from a real one), @handles and usernames,
//   names after a greeting or a title, and the words given in `terms`
//   (the user's own name and address, read from the mail page).
// The person always sees the result before sending it.
(function () {
"use strict";

const GREETING = "(?:Hi|Hello|Hey|Dear|Bonjour|Bonsoir|Salut|Cher|Chère|Olá|Ola|Oi|Hola|Estimado|Estimada|" +
    "Hallo|Liebe|Lieber|Ciao|Caro|Cara|Gentile|Beste|Querida|Querido|Prezado|Prezada|Sannu|Barka)";
const TITLE = "(?:M\\.|Mr\\.?|Mrs\\.?|Ms\\.?|Mme\\.?|Mlle\\.?|Dr\\.?|Madame|Monsieur|Mister|Miss|Sr\\.|Sra\\.|" +
    "Herr|Frau|Signor|Signora|Alhaji|Malam)";
const NAME = "[A-ZÀ-Ý][\\p{L}'’-]*";
const NOT_NAMES = new Set(("nous je we i you your we're we've it its this that the a le la les un une vous votre " +
    "vos pour en merci thank thanks please suite if for today user users customer customers client cliente member " +
    "membre team équipe there all everyone friend friends madame monsieur madam sir mate esteemed valued student " +
    "bonjour hello hi obrigado todos tous and et y o e peer meet mr mrs ms dr m mme mlle sr sra herr frau").split(" "));

const RE = {
    email: /(?<![\p{L}\p{N}._%+-])[\p{L}\p{N}._%+-]+@[\p{L}\p{N}.-]+\.[\p{L}]{2,}/gu,
    url: /\b(?:https?:\/\/|www\.)([^\s/?#<>"']*[^\s/?#<>"'.,;:!?)])(?:[/?#][^\s<>"']*[^\s<>"'.,;:!?)])?/giu,
    iban: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b/g,
    longNumber: /(?<![\p{L}\p{N}])\d(?:[ .-]?\d){5,}(?![\p{L}\p{N}])/gu,
    phone: /(?<![\p{L}\p{N}])\+\d[\d ().-]{6,}\d/gu,
    handle: /(?<![\p{L}\p{N}<])@[\p{L}\p{N}_.]{2,}/gu,
    invisible: /\p{Cf}/gu,
};

function maskNames(words) {
    return words.split(/\s+/).map((w) => (NOT_NAMES.has(w.toLowerCase().replace(/[.,!]/g, "")) ? w : "<NAME>")).join(" ");
}

function isUsername(token) {
    const core = token.match(/[\p{L}\p{N}_](?:.*[\p{L}\p{N}_])?/su)?.[0] || "";
    if (core.length < 6 || core.startsWith("<")) return false;
    if (core.includes("_") && /\p{L}/u.test(core)) return true;
    return /\p{Ll}/u.test(core) && /\d/.test(core) && /\p{L}{3}/u.test(core);
}

// Words to remove wherever they appear, from the user's own address and
// display name ("ana.silva82@..." -> "ana", "silva").
function termsFrom(...values) {
    const out = new Set();
    for (const v of values) {
        for (const part of String(v || "").split(/[^\p{L}]+/u)) {
            if (part.length >= 3) out.add(part.toLowerCase());
        }
    }
    ["gmail", "outlook", "hotmail", "yahoo", "live", "mail", "inbox", "com"].forEach((w) => out.delete(w));
    return [...out];
}

function redact(text, terms = []) {
    // Compatibility forms folded (no-break and narrow spaces become
    // spaces, full-width digits plain ones) and invisible characters
    // removed, before any rule. Same as backend/redaction.py.
    let t = String(text || "").normalize("NFKC").replace(RE.invisible, "");
    t = t.replace(RE.email, "<EMAIL>");
    t = t.replace(RE.url, (_, host) => `<URL:${host.toLowerCase().replace(/^www\./, "")}>`);
    t = t.replace(RE.iban, "<NUMBER>");
    t = t.replace(RE.phone, "<PHONE>");
    t = t.replace(RE.longNumber, "<NUMBER>");
    t = t.replace(RE.handle, "<NAME>");
    for (const lead of [`${TITLE}\\s+`, `${GREETING},?\\s+`]) {
        t = t.replace(new RegExp(`(\\b${lead})(${NAME}(?:\\s+${NAME}){0,2})`, "gu"),
            (_, a, b) => a + maskNames(b));
    }
    const termSet = new Set(terms.map((x) => String(x).toLowerCase()).filter(Boolean));
    t = t.replace(/\S+/gu, (w) => {
        if (/<(?:NAME|EMAIL|NUMBER|PHONE|URL)/.test(w)) return w;
        if (isUsername(w)) return w.replace(/[\p{L}\p{N}_]+/u, "<NAME>");
        if (!termSet.size) return w;
        return w.replace(/[\p{L}]+/gu, (m) => (termSet.has(m.toLowerCase()) ? "<NAME>" : m));
    });
    return t.replace(/[ \t]{2,}/g, " ").trim();
}

const api = Object.freeze({ redact, termsFrom });
// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = api;
globalThis.PhishLensRedact = api;
})();
