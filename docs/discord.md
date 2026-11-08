# discord: Discord's bot API from the shell

[`bin/discord`](../bin/discord) reads, searches and posts in Discord through a bot account. It needs only Python's standard library and gets its token from `agent-secret`, so agents can run it in any session.

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
| `discord read CHANNEL [-n 50] [--before WHEN] [--after WHEN] [--around MSG] [--all] [--grep RE]` | Messages, oldest first |
| `discord search SERVER [TEXT] [--channel C] [--author U] [--has link] [--before/--after WHEN] [-n 25]` | Discord's server-wide message search |
| `discord members SERVER [--query NAME]` | Members and their user ids (for `dm`) |
| `discord send CHANNEL [TEXT\|-] [--reply-to MSG] [--file PATH]... --yes` | Post a message. A message link as CHANNEL makes it a reply |
| `discord dm USER [TEXT\|-] [--file PATH]... --yes` | DM a user who shares a server with the bot |
| `discord edit CHANNEL MSG [TEXT\|-] --yes` | Edit one of the bot's messages |
| `discord delete CHANNEL MSG --yes` | Delete a message |
| `discord react CHANNEL MSG EMOJI [--remove] --yes` | Add or remove the bot's reaction |
| `discord download CHANNEL MSG [--dir DIR]` | Save a message's attachments |
| `discord invite [--guild SERVER] [--permissions LIST]` | The link that adds the bot to a server |

- **CHANNEL** takes an id, a link (`https://discord.com/channels/SERVER/CHANNEL[/MESSAGE]`) or a name: `"Server/#channel"`, or `#channel` when only one of the bot's servers has a channel by that name. Names must match exactly (ignoring case), so a typo fails instead of posting somewhere else. A message link can stand in for `CHANNEL MSG`.
- **WHEN** takes a message id, a message link or an ISO date or time. A time without an offset counts as local time.
- **SERVER** takes an id or the server's exact name.
- The read commands take `--json` or `--jsonl`. `read --all --jsonl` exports a whole channel.
- Text comes from the argument or from stdin (`-`, or no argument). Text that starts with `-` needs `--` before it.

## Safety

- **Every write dry-runs first.** `send`, `dm`, `edit`, `delete`, `react` and `setup` print what they would do, send nothing and exit 3 unless you pass `--yes`. With `--yes` they print the link of each message they posted.
- **No pings by default.** Every message goes out with `allowed_mentions` set to ping nobody, reply pings included. `--allow-mentions` lets user and role mentions ping, and `--allow-everyone` lets `@everyone` and `@here` ping.
- **No double posts.** Every message carries a fresh `nonce` with `enforce_nonce`, so when a lost response makes the CLI retry, Discord returns the first message instead of posting it again. Other POST and PATCH calls never retry unless a repeat can't act twice.
- **The token goes only to `https://discord.com/api`.** The API opener follows no redirect, because urllib's default handler would carry the `Authorization` header to the next host. Attachment downloads go only to Discord's CDN hosts, without the token. No message or error ever prints the token.
- **Downloads stay put.** Attachments go to a new folder (`./discord-MESSAGE` unless `--dir`), with names stripped of path parts and existing files never overwritten.
- **Rate limits.** The client waits out a 429 for as long as Discord asks, up to 60 seconds, and fails beyond that. It honors exhausted buckets and global limits, and retries a search while Discord is still indexing the server.

## Live messages

The CLI holds no Gateway connection, so it only sees messages when you ask. To chat with Claude in a Discord DM in real time, Anthropic's [Discord channel plugin](https://github.com/anthropics/claude-plugins-official/tree/main/external_plugins/discord) can use the same bot. It reads `DISCORD_BOT_TOKEN` from the shell, so you can run:

```bash
DISCORD_BOT_TOKEN="$(agent-secret get agent/discord-bot-token)" claude --channels plugin:discord@claude-plugins-official
```

## Tests

```bash
uv run --with pytest --with hypothesis python -m pytest tests/test_discord.py -q
```

A fake transport stands in for the API, so the tests make no network calls. Property tests check these invariants:

- message chunks fit the 2000-character limit, counted in UTF-16 units, and never lose or reorder a visible character;
- snowflake cursors round-trip, and message links parse back to their ids;
- paging returns exactly the messages Discord's documented `before`/`after` rules select, whatever order a page arrives in;
- no write leaves without `--yes`;
- the token never reaches the terminal or a host other than the API;
- downloads can't leave their folder.
