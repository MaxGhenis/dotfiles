# discord: Discord's bot API from the shell

[`bin/discord`](../bin/discord) reads, searches and posts in Discord through a bot account. It needs only Python's standard library (3.9 or later, so macOS's own `/usr/bin/python3` will do) and gets its token from `agent-secret`, so agents can run it in any session.

## Why a bot account

Discord bans scripting a normal user account. Its [support article on self-bots](https://support.discord.com/hc/en-us/articles/115002192352-Automated-User-Accounts-Self-Bots) says doing so can get the account terminated, and it points automation to bot accounts. That makes a bot the only route that is both scriptable and allowed. The trade-off: a bot sees only the servers someone added it to and the DMs people send it. It can't read your own DMs, or servers where you can't add bots.

## Setup (once)

1. In the [Developer Portal](https://discord.com/developers/applications), click **New Application**, name it and click **Create**. Discord gives every app a bot user automatically.
2. On the **Bot** page, click **Reset Token** and copy the token. You can also switch off **Public Bot** there so only you can add the bot. The API can't change that setting.
3. Store the token: `agent-secret set agent/discord-bot-token`, then paste it at the hidden prompt. `DISCORD_BOT_TOKEN` in the environment overrides it.
4. Run `discord setup --yes`. It checks the token and turns on the message-content and members intents: Discord lets a bot in fewer than 100 servers set these itself with `PATCH /applications/@me`. Then it prints the invite link.
5. Open the invite link once for each server you want the bot in, pick the server and click **Authorize**.

Without the message-content intent, Discord returns other people's messages with empty text. `discord read` warns when every message comes back empty.

## Commands

| Command | What it does |
|---|---|
| `discord whoami` | The bot, its app, which intents are on and how many servers it's in |
| `discord guilds` | The servers the bot is in |
| `discord channels SERVER [--threads]` | The server's channels as a tree, plus active threads if you ask |
| `discord read CHANNEL [-n 50] [--before WHEN] [--after WHEN] [--all] [--grep RE]` | Messages, oldest first. `--around MSG` instead gives up to 100 messages around one |
| `discord search SERVER [TEXT] [--channel C] [--author U] [--has link] [--before/--after WHEN] [--nsfw] [-n 25]` | Discord's server-wide message search (10,000 hits at most; `--nsfw` adds age-restricted channels) |
| `discord members SERVER [--query NAME]` | Members and their user ids (for `dm`) |
| `discord send CHANNEL [TEXT\|-] [--reply-to MSG] [--file PATH]... [--again] --yes` | Post a message. A message link as CHANNEL makes it a reply |
| `discord dm USER [TEXT\|-] [--file PATH]... [--again] --yes` | DM a user who shares a server with the bot |
| `discord edit CHANNEL MSG [TEXT\|-] --yes` | Edit one of the bot's messages |
| `discord delete CHANNEL MSG --yes` | Delete a message |
| `discord react CHANNEL MSG EMOJI [--remove] --yes` | Add or remove the bot's reaction |
| `discord download CHANNEL MSG [--dir DIR]` | Save a message's attachments |
| `discord invite [--guild SERVER] [--permissions LIST]` | The link that adds the bot to a server |

- **CHANNEL** takes an id, a link (`https://discord.com/channels/SERVER/CHANNEL[/MESSAGE]`, with or without `ptb.`, `canary.` or a `?query`) or a name: `"Server/#channel"`, or `#channel` when only one of the bot's servers has a channel by that name. Names must match exactly (ignoring case), so a typo fails instead of posting somewhere else. A message link can stand in for `CHANNEL MSG`.
- **WHEN** takes a message id, a message link or an ISO date or time. A time without an offset counts as local time. Dates before Discord began, or after tomorrow, are clamped.
- **SERVER** takes an id or the server's exact name.
- The read commands take `--json` or `--jsonl`. `read --all --jsonl` exports a whole channel.
- Text comes from the argument, or from stdin when the argument is `-`. It never reads stdin uninvited, which would hang in an agent's shell. Text that starts with `-` needs `--` before it: `discord send C -- '-1 for this'`. Every word after `--` is an argument, never an option, on every Python version (argparse up to at least 3.12.5 lets such words through as options when options and arguments mix, so the CLI handles `--` itself).
- Options can go anywhere among the arguments (`discord edit LINK --yes 'new text'`), but must be spelled out in full: `--ye` isn't `--yes`.

## Safety

- **Every write dry-runs first.** `send`, `dm`, `edit`, `delete`, `react` and `setup` print what they would do, send nothing and exit 3 unless you pass exactly `--yes`. With `--yes` they print the link of each message they posted. A dry run also checks every `--file`, so one that passes means the real run can read them.
- **No pings by default.** Every message goes out with `allowed_mentions` set to ping nobody, reply pings included. `--allow-mentions` lets user and role mentions ping, and `--allow-everyone` lets `@everyone` and `@here` ping.
- **No double posts.** Every message carries a `nonce` with `enforce_nonce`, so when a lost or cut-off response makes the CLI retry, Discord returns the first message instead of posting it again. The nonces derive from the channel, the text, the reply target and the files (their names and contents), so running the same send again within a few minutes (after a failure partway through a long message, say) returns the parts already posted, marked `already posted`, instead of repeating them. `--again` posts a deliberate repeat. Whether Discord returned an older message is judged by Discord's own clock (its `Date` header), so a wrong clock here can't mislabel a new one. A message send stops retrying 90 seconds after a try that may have posted it, inside the "past few minutes" in which Discord's docs say it matches nonces; a send that only met rate limits can't have posted, so it keeps waiting. A send that fails partway says how many parts went out and whether running it again repeats them. Other POST and PATCH calls never retry unless a repeat can't act twice.
- **The token goes only to `https://discord.com/api`.** The API opener follows no redirect, because urllib's default handler would carry the `Authorization` header to the next host. Attachment downloads go only to Discord's CDN hosts over https, redirects included, without the token. A token that isn't shaped like a bot token (three dot-joined parts, about 70 characters) is refused before it reaches an HTTP header, and every error, expected or not, prints as one line with the token removed (`DISCORD_DEBUG=1` adds a redacted traceback).
- **Downloads stay put.** Attachments go to `./discord-MESSAGE` (or `--dir`), which must be a real folder of yours, not a symbolic link or another user's folder. The CLI opens that folder once and creates every file through that handle, so swapping the folder for a link mid-download changes nothing. Each file is created new, so nothing is overwritten and no symbolic link inside the folder is followed, and a file whose write fails is removed. Names lose path parts, leading dots and dashes, and control characters, and are cut to 200 bytes.
- **What others wrote can't drive your terminal.** Plain-text output and error messages show control characters and bidirectional-text controls in message text, names and file names as `\x1b`-style escapes. `--json` keeps the data exact.
- **Rate limits.** The client waits out a 429 or an exhausted bucket for as long as Discord asks, up to 60 seconds, says so on stderr when a wait reaches 5 seconds, and fails beyond 60 seconds. Routes that Discord says share a bucket wait together. A 429 with no wait time (a Cloudflare block after too many failed requests) fails at once. Search retries, with a growing delay, while Discord is still indexing the server, and fails when Discord asks for more than 60 seconds. Search always asks for full pages of 25 and stops at the first page that adds nothing, so short pages or a stale `total_results` can't turn into thousands of requests.

## Live messages

The CLI holds no Gateway connection, so it only sees messages when you ask. To chat with Claude in a Discord DM in real time, Anthropic's [Discord channel plugin](https://github.com/anthropics/claude-plugins-official/tree/main/external_plugins/discord) can use the same bot. It reads `DISCORD_BOT_TOKEN` from the shell, so you can run:

```bash
DISCORD_BOT_TOKEN="$(agent-secret get agent/discord-bot-token)" claude --channels plugin:discord@claude-plugins-official
```

That exports the token to every process the session starts, MCP servers and shell commands included, so anything that prints the environment there can show it. Run it only in a session meant for the Discord channel.

## Tests

```bash
uv run --no-project --with pytest --with hypothesis --with regex python -m pytest tests/test_discord.py -q
```

A fake transport stands in for the API, so the tests make no network calls. Property tests check these invariants:

- message chunks fit the 2000-character limit, counted in UTF-16 units, never lose or reorder a visible character, and add only the lines that close and reopen a code block, so no piece but the last leaves a code block open;
- every cut falls on a grapheme boundary, checked against the `regex` module's implementation of Unicode's segmentation rules (UAX #29), unless no boundary fits in the back half of the window;
- snowflake cursors round-trip, and message links parse back to their ids;
- paging returns exactly the messages Discord's documented `before`/`after` rules select, whatever order a page arrives in, without wasted requests;
- no write leaves without `--yes`, whatever other flags come with it;
- the token never reaches the terminal or a host other than the API;
- download names can't leave their folder, pass for an option, or overflow a file system's name limit;
- printed text holds no control characters.

The suite also pins each fix from two rounds of independent review, by finding: the redacting catch-all, retries after a cut-off response, nonces that hold across runs, symlink-proof downloads, exact-name matching, search paging, `--` on old Pythons, and the rest. Reverting any one fix fails a test. CI runs it on Python 3.9 (macOS's system Python), 3.11, 3.12.5 (the last argparse seen mishandling `--`) and 3.14.
