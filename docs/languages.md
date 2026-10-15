# Languages

PhishLens deals with languages in four places, each handled separately:

| Part | Languages | Where it lives |
| --- | --- | --- |
| Extension interface (popup, Gmail and Outlook banners, notifications) | English, French, Portuguese, Spanish, German, Italian, Dutch, Hausa | `extension/lib/i18n.js`, `extension/lib/locales/` |
| Chrome Web Store name and description | The same, except Hausa (Chrome has no Hausa locale) | `extension/_locales/` |
| Website and its legal pages | The same 8 languages | `site-src/`, built by `scripts/build_site.py` |
| Reading emails: OCR of images and scanned PDFs | Latin-script languages, Cyrillic, Arabic, Chinese, Japanese, Korean, Hindi | `backend/ocr.py`, Tesseract packs in the Dockerfiles |
| Reading emails: text model | The model in use decides (see [Text model](#text-model)) | `backend/text_model.py` |

## Extension interface

### How it works

Every text the user can see is looked up by key. `lib/locales/<lang>.js`
defines one dictionary per language:

```js
(globalThis.PhishLensLocales ||= {}).fr = { "verdict_safe": "Cet e-mail semble sûr", ... };
```

`lib/i18n.js` exposes `PhishLensI18n`:

| Function | Use |
| --- | --- |
| `t(key, vars)` | Text in the current language, `{name}` placeholders filled from `vars`. Falls back to English, then to the key itself. |
| `tn(key, count, vars)` | Plural: picks `key_one` or `key_other`. |
| `flagLabel(flag)`, `reasonLabel(reason)` | Labels for the backend's attachment flags (`flag_<name>`) and dropper reasons (`reason_<slug>`). |
| `applyTo(root)` | Fills the popup's static HTML: `data-i18n` (text), `data-i18n-html`, `data-i18n-title`, `data-i18n-placeholder`, `data-i18n-aria-label`. |
| `init()`, `setLanguage(code)`, `onChange(fn)` | Reads the saved choice and follows changes made in another view. |

The language is the one picked in **Settings > Language** (stored as
`ui_lang` in `chrome.storage.local`), or the browser's language when the
setting is "Automatic" and the browser language is supported, otherwise
English. The same files are loaded by the popup (`popup.html`), the
content scripts (listed first in `manifest.json`) and the service worker
(`importScripts`), so a change in Settings reaches open Gmail and Outlook
tabs without a reload.

PhishLens does not use `chrome.i18n` for the interface: Chrome only
offers the languages it supports itself, and Hausa is not one of them.
`_locales/` is used only for the store listing (`__MSG_extName__`,
`__MSG_extDescription__` in the manifest).

### Security

Some texts carry data from the email (`{sender}`, `{services}`,
`{organizer}`). Translated text is therefore treated like any other
untrusted string: it goes through `escapeHTML` or `textContent`. Only
keys ending in `_html` are inserted as HTML, and they are static strings
shipped with the extension. `tests/extension/locales.test.js` fails if a
`${t(...)}` inside a template literal is not escaped.

### Checks

`tests/extension/locales.test.js` (run by CI with `node --test`):

- every language has exactly the English keys, with the same
  `{placeholders}` and the same HTML tags;
- plural keys come in `_one` / `_other` pairs;
- every key used by `t()` / `tn()` in the code and by `data-i18n*` in
  `popup.html` exists;
- every `_locales/` folder has a name and a description short enough for
  the store (132 characters).

The Playwright popup tests run with an English browser locale, so they
check the English texts.

### Adding a language or a text

- **New text:** add the key to `en.js`, then to every other locale file
  (the test lists what is missing).
- **New language:** copy `en.js` to `<code>.js`, translate the values
  (keep keys, placeholders and tags), add the code and its native name to
  `LANGUAGES` in `i18n.js`, and the file to the three load lists
  (`manifest.json` content scripts, `popup.html`, `background.js`). If
  Chrome supports the language, add `_locales/<code>/messages.json` too.
- Keep the wording plain, and use the same terms as the rest of the
  file (for example the same word for "sender" everywhere).

### Translation status

English is the reference. French, Portuguese, Spanish, German, Italian
and Dutch are complete. **Hausa is a draft** waiting for review by a
native speaker; the file says so in its first line. Corrections are
welcome as pull requests or issues.

## Website

The site is static. `site-src/` holds the sources:

| Path | Contents |
| --- | --- |
| `site-src/index.html` | Home page template: `{{key}}` is replaced by a string, `{{>head}}`, `{{>header}}`, `{{>footer}}` by shared parts |
| `site-src/strings/<lang>.json` | Every text of the site in one language, including the texts `app.js` shows (`js_*` keys) |
| `site-src/legal/<lang>/PRIVACY.md`, `TERMS.md` | Translations of the root `PRIVACY.md` and `TERMS.md` |

`python3 scripts/build_site.py` (needs pandoc) writes `site/`: English at
the root, the other languages in `site/<lang>/`, `site/i18n/<lang>.js`
for the scripts, and `sitemap.xml`. Each page lists all its translations
with `hreflang` links, and the header has a language menu. On an English
page, `lang.js` shows a link to the visitor's language when the browser
asks for one the site has; it never redirects and stores nothing.
`site/` is generated: edit `site-src/` and rebuild.

The translated legal pages say at the top that the English version
prevails. When `PRIVACY.md` or `TERMS.md` changes, update the seven
translations in the same pull request.

`tests/ui/site.spec.js` loads every language version, checks that
`app.js` answers in the page's language, that the language menu leads to
the same page in another language, and that a French browser is offered
the French version.

## Detected language

`/analyse` and `/analyse_attachment` return `language: {code, confidence}`
(`backend/language.py`): the writing system decides for non-Latin text
(Cyrillic, with Ukrainian letters told apart, Arabic, Devanagari, Han,
kana, Hangul...), and for Latin text the share of common words of each
language decides between English, French, Portuguese, Spanish, German,
Italian, Dutch, Polish, Turkish, Indonesian, Vietnamese, Swahili, Hausa,
Yoruba and Igbo. Too little text gives `und`. The banner shows it and asks
the user to confirm or correct it; answers are kept in the history and
can be shared with the statistics.

## OCR

`OCR_LANG` (default `auto`) lets Tesseract's script detection (OSD) pick
the language packs for each image: Latin script uses
`eng+fra+spa+por+deu+ita+nld`, Cyrillic `rus+ukr+eng`, Arabic `ara+eng`,
Han `chi_sim+eng`, Japanese `jpn+eng`, Hangul `kor+eng`, Devanagari
`hin+eng`. Only installed packs are used; without OSD data, the Latin set
is used. Set `OCR_LANG=eng` (or any Tesseract language string) to force
one. Both Dockerfiles install these packs.

## Text model

The text model decides which languages are read well. The model in
production is the English DistilBERT
([AnzouKiona/phishlens-distilbert](https://huggingface.co/AnzouKiona/phishlens-distilbert)):
emails in other languages get a less reliable wording score, while the
link, sender and threat-intelligence checks work the same in every
language. A multilingual model is being evaluated; the backend can
already load it without code changes (see
[architecture.md, text model](architecture.md#text-model)), and its
model card will list the languages it was tested on and its results.
