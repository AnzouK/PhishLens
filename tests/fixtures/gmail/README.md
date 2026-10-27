Sample Gmail pages for `tests/extension/gmail_page.test.js`, written by
hand in the shape of Gmail's own pages (no real message or account).
When Gmail changes its page, replace the sample with the new shape
(addresses and names made up) and update `extension/lib/gmail_page.js`.

- `show_original.html`: the "Show original" view of a received message.
- `show_original_sent.html`: the same view for a message the user sent
  (no Received header).
- `globals_script.txt`: the inline script that holds the account token.
