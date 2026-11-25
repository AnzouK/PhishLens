# Languages

Each part of PhishLens covers its own set of languages. The extension
interface and the website come in English, French, Portuguese, Spanish,
German, Italian, Dutch and Hausa. The Chrome Web Store listing has the
same languages except Hausa, because Chrome has no Hausa locale. The
[text model](#text-model) was trained on 22 languages and measured on
real phishing in 6. [OCR](#ocr) of images and scanned PDFs reads Latin
scripts, Cyrillic, Arabic, Chinese, Japanese, Korean and Hindi.

## Interface

Every visible text is looked up by key in `extension/lib/locales/<lang>.js`,
and `t("key", {name})` falls back to English, then to the key. The
language is the one chosen in Settings, or the browser's.

PhishLens does not use `chrome.i18n` for this, because Chrome only
offers the languages it supports itself and Hausa is not one of them.
`_locales/` is only the store listing.

Texts can carry data from the email (`{sender}`, a file name), so they
always become text nodes, never HTML. The few keys ending in `_html`
(bold, code, line breaks) are rebuilt from an allowlist of tags.

`tests/extension/locales.test.js` keeps the 8 languages in step (same
keys, same placeholders, same tags, no missing key, no `innerHTML`).
`backend/tests/test_site_strings.py` does the same for the website's
figures.

To add a text, add the key to `en.js`, then to the other files (the test
lists what is missing). To add a language, copy `en.js`, translate the
values, add the code to `LANGUAGES` in `i18n.js` and add the file to the
three load lists (manifest, `popup.html`, `background.js`).

The Hausa translation is a draft awaiting a native speaker. A reviewer
who does not use git can work in a spreadsheet:

```bash
python3 scripts/translation_review.py export ha -o hausa-review.xlsx
python3 scripts/translation_review.py import ha hausa-review.xlsx
```

## Website

`site-src/strings/<lang>.json` holds every text of the site, and
`site-src/legal/<lang>/` the translated privacy policy and terms (the
English version prevails). `python3 scripts/build_site.py` writes
`site/`, so edit `site-src/` and rebuild. When `PRIVACY.md` or `TERMS.md`
changes, the seven translations change in the same pull request.

## Detected language

`/analyse` returns `language: {code, confidence}`. The writing system
decides for non-Latin text, common words decide between the Latin-script
languages, and too little text gives `und`. The banner asks the user to
confirm it, and the answers stay in the local history.

## OCR

With `OCR_LANG=auto`, Tesseract's script detection picks the packs for
each image. Latin text uses `eng+fra+spa+por+deu+ita+nld`, and Cyrillic,
Arabic, Han, Japanese, Hangul and Devanagari are each read together
with English. Missing packs are
skipped, and `OCR_LANG=eng` forces one.

## Text model

The wording score is only as good as the text model for that language.
PhishLens Cloud runs a multilingual model trained on 22 languages and
measured on real phishing in English, French, German, Dutch, Portuguese
and Spanish. It is private because part of its training mail is. A
self-hosted server uses the public English model
([AnzouKiona/phishlens-distilbert](https://huggingface.co/AnzouKiona/phishlens-distilbert))
by default, which is far less reliable outside English. The link,
sender and threat-intelligence checks work the same in every language.
The multilingual model itself is described in
[multilingual-model.md](multilingual-model.md).
