# Omapager v1.2.0

Preferences, secret hygiene, and an optional model layer.

## Changes

- **Preferences window.** The cog in the panel now opens a full window instead of the 380 px panel page. It holds the settings that need room: provider, endpoint, model, key, and what the model may do. The panel page keeps the small toggles and is one click away from it.
- **Swap mouse buttons.** `swapMouseButtons` turns the bar indicator over: right-click becomes the plain click, left-click opens the panel. Notification cards keep right-click for the source menu.
- **Recent notifications are actionable.** Each row in the Recent list keeps what its card could do: copy a code, open a link, copy a phone number, snooze the source, or remove the row. The text stays redacted; the offer is held in memory for the session only.
- **Clicks no longer dismiss.** A left click on a card body does nothing unless `allowDefaultActionOnCardClick` is on, so a mis-click cannot lose a notification. Middle-click dismisses; the close button is still there.
- **Verification codes from SMS.** A phone number's digits used to be harvested as codes, and the 24-character keyword window could slice a six-digit code into a five-digit one - both put the wrong value behind the copy button. Phone-shaped numbers are now excluded from code detection and window edges snap to token boundaries.
- **Always show the latest five.** `alwaysShowRecent` opens the panel with the latest five notifications already listed, instead of waiting behind the Recent fold-out. The Recent header stops offering to collapse while it is on.
- **Sensitive text filter.** `sensitiveFilter` (`off`, `mask`, `redact`) hides API keys, tokens, private keys, passwords in connection URLs, card and account numbers, email addresses and phone numbers on the card. History is redacted regardless. The rules run locally; no model is involved. `Redact.js` and its Python mirror in the store are separate implementations on purpose, and the corpus tests check that they agree.
- **Duplicated messages.** The same message arriving from two sources is shown once. The local comparison needs no model; when one is configured, it is asked about pairs that already look similar.
- **Saved files.** A notification that names a file it saved grows a File button with Reveal, Properties, Open and Copy path. `fileManager` chooses between the desktop's registered file manager and `nautilus`, `dolphin`, `thunar` or `nemo`.
- **System One duplicate checks.** `llmDedupeApi` can send the duplicate question to a System One model such as Jev (`group/jev` at Magpie) instead of a chat model. Jev answers one yes/no question with a probability, so there is no generation and nothing to parse: about 0.8 s against 2.5-2.8 s for a chat model, and stable across runs. A card merges at 0.7 or above.
- **Cheaper duplicate checks.** `llmDedupeModel` names a second model used only for the duplicate question, so a small or flash model can carry the frequent yes/no while the main one handles button suggestions. Empty means one model for both. The preferences window offers the provider's own list and a text field, and its connection test reports a model id the provider lists but refuses.
- **Optional model layer.** `llmProvider` selects an OpenAI-compatible endpoint: `ollama`, `lmstudio` and `llamacpp` locally, `openrouter`, `openai`, `deepseek` remotely, or `custom` with `llmBaseUrl`. Off by default and inert until chosen. It can confirm a duplicate and suggest a button, and a suggestion is shown only when the message already contained the thing it points at — the model cannot add a link, a path or a command.
- **The API key lives in the keyring.** Set through the preferences window; stored via libsecret. Never in `shell.json`, never in state, never in argv, never in a log. On a machine with no secret service the model section disables itself rather than falling back to plaintext.

## Updating

Run `omarchy restart shell` after updating. Existing configuration values are preserved; every new setting has a default that leaves current behaviour unchanged, and `sensitiveFilter` and `llmProvider` both default to off.

The network protections and optional Bubblewrap policy from v1.1.0 are unchanged. The model helper adds one deliberate exception to the helper profiles — it is both networked and bus-connected, because it must reach the provider and the keyring — and that profile is documented in `docs/SANDBOX.md`.

[Changes since v1.1.1](https://github.com/njpatel/omapager/compare/v1.1.1...v1.2.0)
