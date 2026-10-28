# Languages

| Part | Languages |
| --- | --- |
| Extension interface and website | English, French, Portuguese, Spanish, German, Italian, Dutch, Hausa |
| Chrome Web Store listing | the same, except Hausa (Chrome has no Hausa locale) |
| Text model | 22 trained, 6 measured on real phishing ([text model](#text-model)) |
| OCR of images and scanned PDFs | Latin scripts, Cyrillic, Arabic, Chinese, Japanese, Korean, Hindi ([OCR](#ocr)) |

## Interface

Every visible text is looked up by key in `extension/lib/locales/<lang>.js`;
`t("key", {name})` falls back to English, then to the key. The language
is the one chosen in Settings, or the browser's.

PhishLens does not use `chrome.i18n` for this: Chrome only offers the
languages it supports itself, and Hausa is not one of them. `_locales/`
is only the store listing.

Texts can carry data from the email (`{sender}`, a file name), so they
always become text nodes, never HTML. The few keys ending in `_html`
(bold, code, line breaks) are rebuilt from an allowlist of tags.

`tests/extension/locales.test.js` keeps the 8 languages in step: same
keys, same placeholders, same tags, no missing key, no `innerHTML`.
`backend/tests/test_site_strings.py` does the same for the website's
figures.

**Adding a text:** add the key to `en.js`, then to the other files (the
test lists what is missing). **Adding a language:** copy `en.js`,
translate the values, add the code to `LANGUAGES` in `i18n.js` and the
file to the three load lists (manifest, `popup.html`, `background.js`).

**Hausa is a draft** awaiting a native speaker. A reviewer who does not
use git can work in a spreadsheet:

```bash
python3 scripts/translation_review.py export ha -o hausa-review.xlsx
python3 scripts/translation_review.py import ha hausa-review.xlsx
```

## Website

`site-src/strings/<lang>.json` holds every text of the site,
`site-src/legal/<lang>/` the translated privacy policy and terms (the
English version prevails). `python3 scripts/build_site.py` writes
`site/`; edit `site-src/` and rebuild. When `PRIVACY.md` or `TERMS.md`
changes, the seven translations change in the same pull request.

## Detected language

`/analyse` returns `language: {code, confidence}`: the writing system
decides for non-Latin text, common words decide between the Latin-script
languages, too little text gives `und`. The banner asks the user to
confirm it; answers stay in the local history.

## OCR

With `OCR_LANG=auto`, Tesseract's script detection picks the packs for
each image (Latin: `eng+fra+spa+por+deu+ita+nld`; Cyrillic, Arabic, Han,
Japanese, Hangul and Devanagari with English). Missing packs are
skipped; `OCR_LANG=eng` forces one.

## Text model

The wording score is only as good as the text model for that language.
PhishLens Cloud runs a multilingual model trained on 22 languages and
measured on real phishing in English, French, German, Dutch, Portuguese
and Spanish; it is private because part of its training mail is. A
self-hosted server uses the public English model
([AnzouKiona/phishlens-distilbert](https://huggingface.co/AnzouKiona/phishlens-distilbert))
by default, which is far less reliable outside English. The link,
sender and threat-intelligence checks work the same in every language.
How the multilingual model was built: [multilingual-model.md](multilingual-model.md).
