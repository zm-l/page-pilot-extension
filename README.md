# Page Pilot: Permission and Privacy MVP

Page Pilot is a Chrome Side Panel agent. This MVP focuses on two things:

1. **Permissions are requested only when needed.** The user can also grant access to all sites at once.
2. **The agent refuses to read or fill sensitive information.**

It has two modes:

- **AI mode** (with an OpenRouter API key): describe the goal in plain language. An AI model of your choice plans and runs it one step at a time.
- **Simple commands** (no key): a fixed set of commands such as `read page` or `click Sign up`. In AI mode, start a message with `/` to use one.

## Turn on AI mode

1. Create a key at [openrouter.ai/keys](https://openrouter.ai/keys). Keys start with `sk-or-`.
2. In the panel, open **Settings → AI model (OpenRouter)**, paste the key, and keep the default model `anthropic/claude-haiku-5.5` or enter any OpenRouter model ID. Other suggestions: `google/gemini-3.8-flash`, `qwen/qwen3.8-flash`.
3. Click **Save**. Chrome asks once for access to `openrouter.ai`, then the panel runs a connection test. The header badge changes to **AI · model**.

The key is stored only in this browser profile (`chrome.storage.local`) and sent only to `openrouter.ai`. **Never put it in a source file.** Use **Remove key** to delete it.

### How the AI agent works

Each turn the agent **observes** the page, the **AI picks one action**, and the **panel carries it out**. The panel shows the AI's current plan, a short reasoning line and every step with its status.

- **What the AI receives:** your request, any answers or notes you add, the action history with results, and a filtered page summary. The summary contains element labels with IDs, "filled"/"empty" (never values), headings and redacted visible text, all wrapped in `<untrusted_page>`.
- **Adding information:** if the AI asks a question, a card appears. You can answer in the card or in the main box. Anything you type while it is working is passed along as a note on the next step.
- **Recovery:** errors such as a missing element, a pop-up in the way or a page change go back to the AI so it can try another approach. After 3 failures in a row, you choose **Keep trying** or **Stop**. After 20 steps, it asks before continuing.
- **Safety enforced outside the AI:** the AI can't skip any rule. Sensitive fields are refused by the page helper, risky clicks always show the confirmation card, and a request containing a card number, SSN, password or key is refused before anything goes to the AI.

## Install (about 1 minute)

1. Open `chrome://extensions` and turn on **Developer mode** (top right).
2. Click **Load unpacked** and pick this folder (`page-pilot-extension`).
3. Pin Page Pilot, then click its toolbar icon (or press **Alt+Shift+P**) to open the Side Panel.

At install time Chrome shows **no website warnings**. The extension only asks for `sidePanel`, `activeTab`, `scripting` and `storage`.

## Permission model

| Level | How the user grants it | What it covers | When it ends |
|---|---|---|---|
| **No access** (default) | Install state | Nothing. The panel can still open tabs. | – |
| **This tab, once** | Click the toolbar icon or press Alt+Shift+P (Chrome `activeTab`) | The current tab only | When the tab navigates or closes |
| **This site, for this task** | “Allow on *site* for this task” in the permission card | One site | Removed automatically when the task ends |
| **Always on this site** | “Always allow on *site*” (card or access bar) | One site, permanently | When the user removes it under Permissions |
| **All sites** | Onboarding choice, permission card, or the Permissions panel | Every http/https site | “Switch to Ask when needed” or “Revoke everything” |
| **Tab list** (optional `tabs`) | Asked only for “list tabs” or “switch to tab *title*” | Tab titles and URLs | Revoke under Permissions |

How it works:

- Website access uses `optional_host_permissions`, and `chrome.permissions.request()` is called from the button click itself, so Chrome's own dialog confirms every grant.
- The content helper (`content.js`) is **not** a declared content script. It is injected with `chrome.scripting` only after access exists.
- The access bar at the top of the panel always shows the current tab's level and has a one-click upgrade or removal.
- If a page navigates mid-task and access is lost, the next step shows the permission card again instead of failing silently.

## Sensitive data: refuse by design

| Layer | What it does |
|---|---|
| Request | Commands that ask to read, copy or fill passwords, card numbers, CVV, SSN/ID, OTP/2FA codes, bank details, API keys or tokens are refused before any page access. |
| Fill | Refuses fields that are `type=password`, have `autocomplete=cc-*` / `*-password` / `one-time-code`, or are labelled like the above. It also refuses values that look like card numbers (Luhn check), SSNs or secret keys. |
| Read | Never returns any form field value, only “filled” or “empty”. Sensitive fields appear as “sensitive, not read”. |
| Text | Redacts card numbers, SSNs, `password: …` / `api key: …` patterns, `sk-…`/`ghp_…` keys and JWTs. Skips `[data-sensitive]` / `[data-private]` zones. Strips query strings from URLs. |
| Prompt injection | Ignores hidden text and treats page content as data, never as instructions. The panel labels results as untrusted. |

These rules apply under **every** permission level, including “All sites”.

## Control and recovery

- Every request becomes a **visible plan**. Each step shows waiting, running, done, failed, refused, skipped or stopped, with a one-line result.
- **Stop** cancels the task at any point, including while a card is waiting for an answer.
- Before Page Pilot clicks anything that submits, sends, buys, deletes, signs up or closes a tab, it asks for **confirmation**. If the button changes after you confirm, the click is blocked.
- When a step fails (element not found, covered by a pop-up, page rejected a value, page reloading), the user can **Retry**, **Skip** or **Stop**.
- For dynamic pages and SPAs, Page Pilot waits up to 3 s for elements, finds re-rendered elements again, and detects navigation after clicks.

## Commands

`read page` · `find <text>` · `scroll down|up|top|bottom` · `click <text>` · `fill <field> with <value>` · `type <value> into <field>` · `close popup` · `open <url>` · `list tabs` · `switch to tab <n or title>` · `close tab` · `help`

Chain commands with `then` or `;`, for example: `close popup then fill name with Ada then click Create account`.

## Try it (5-minute test script)

Serve the demo page (Chrome needs an http URL for site permissions):

```powershell
cd demo
python -m http.server 8000
```

Open `http://localhost:8000/test-page.html`, then try:

1. **First run:** open the panel. The welcome card offers “Ask me when needed” or “Allow on all sites”. Pick **Ask me**.
2. **Allow once:** type `read page`. Because you opened the panel with the toolbar icon, the tab is already accessible “once”. The card is **not** shown. The result lists fields with **Password** and **Card number** marked “sensitive, not read”. The card number, SSN and API key in the Account section are hidden, and the hidden injection text does not appear.
3. **Per-site grant:** reload the page (this ends the one-time access) and type `find pricing`. The permission card appears. Choose **Allow on localhost for this task**. After the task, the panel reports that task-only access was removed.
4. **Refusals:** try `read the password`, `fill card number with 4111 1111 1111 1111` and `fill password with hunter2`. All are refused, and nothing on the page is touched.
5. **Multi-step and confirmation:** `close popup then fill name with Ada Lovelace then fill email with ada@example.com then fill country with Singapore then click Create account`. The final click asks for confirmation.
6. **Dynamic content:** `scroll bottom then click Upgrade to Pro`. The button appears after 2 s, so the agent waits for it.
7. **Failure recovery:** `click Nonexistent button`. You get Retry, Skip and Stop.
8. **All sites:** open **Permissions**, then **Allow on all websites**. Chrome's dialog appears. Later, use **Switch to “Ask when needed”** or **Revoke everything**.
9. **Tabs:** `list tabs` asks for the optional tab permission. `switch to tab 1` works without it.

## Files

- `manifest.json`: minimal required permissions; optional host and `tabs` permissions
- `background.js`: toolbar click opens the panel and grants `activeTab`
- `ai.js`: OpenRouter client, system prompt, agent loop, AI settings
- `sidepanel.html/.css/.js`: onboarding, access bar, Settings panel, plans, confirmations, recovery, simple commands
- `content.js`: on-demand page helper with sensitive-data detection, redaction and element IDs (`observe`)
- `demo/test-page.html`: local test page

## Known MVP limits

- The AI sees a text summary of the page, not screenshots, so canvas-heavy or very visual sites are harder.
- The cost is one AI call per step. With the default model, a typical 8-step task costs well under one US cent.
- Doesn't reach into cross-origin iframes or closed shadow DOM.
- Chrome blocks all extensions on `chrome://` pages and the Web Store. The access bar says so.
