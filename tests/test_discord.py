"""bin/discord drives Discord's bot API; these tests pin it without a network.

A fake transport stands in for https://discord.com/api/v10 and records every
request. Example tests pin each command; Hypothesis pins the invariants:

- chunk_text: every piece fits the limit in UTF-16 units, none is blank, and
  no non-whitespace character is lost or reordered;
- snowflakes: ms -> snowflake -> ms round-trips, and a cursor never passes the
  snowflake it came from; message links parse back to the ids they hold;
- history(): whatever order a page arrives in, it returns exactly the messages
  the documented before/after semantics select, oldest first, once each (a
  differential check against a direct filter of the fake's history);
- writes: without --yes no command sends anything but GETs, and it exits 3;
- the token never reaches stdout or stderr, rides only to discord.com/api,
  and never follows a redirect; attachment downloads carry no token;
- POST and PATCH repeat only when the caller marks the repeat safe; every
  message create carries a fresh nonce with enforce_nonce and pings no one;
- downloads stay inside the target folder;
- uploads: the size check counts the exact multipart body the upload sends
  (a differential check against encode_multipart).
"""
from __future__ import annotations

import argparse
import email
import email.policy
import email.utils
import http.server
import importlib.machinery
import importlib.util
import io
import json
import os
import random
import re
import stat
import subprocess
import sys
import threading
import unicodedata
import urllib.parse
import urllib.request
import datetime as dt
from dataclasses import dataclass
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

SCRIPT = Path(__file__).resolve().parent.parent / "bin" / "discord"


def _load():
    loader = importlib.machinery.SourceFileLoader("discord_cli", str(SCRIPT))
    spec = importlib.util.spec_from_loader("discord_cli", loader)
    module = importlib.util.module_from_spec(spec)
    # dataclasses looks the module up in sys.modules while it builds a class.
    sys.modules["discord_cli"] = module
    loader.exec_module(module)
    return module


dc = _load()

# Shaped like a real bot token (three dot-joined parts), so load_token accepts it.
TOKEN = "SENTINEL-bot-token-must-never-leak.AbCdEf.0123456789abcdef-SENTINEL"
GUILD = "100000000000000001"
CATEGORY_ID = "200000000000000009"
GENERAL = "200000000000000001"
RANDOM = "200000000000000002"
DM_CHANNEL = "200000000000000099"
APP = "300000000000000001"
USER = "400000000000000001"
GUILD2 = "100000000000000002"
OTHER_GENERAL = "200000000000000011"
BASE_ID = 1_300_000_000_000_000_000  # a 2026-era snowflake
DOCUMENTED_PERMISSIONS = (1 << 6) | (1 << 10) | (1 << 11) | (1 << 14) | (1 << 15) | (1 << 16) | (1 << 38)


@dataclass
class Call:
    method: str
    path: str
    query: dict
    headers: dict
    body: bytes | None

    def json(self):
        return json.loads(self.body) if self.body else None


class Clock:
    def __init__(self):
        self.t = 1000.0
        self.slept: list[float] = []

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += seconds


def parse_multipart(body: bytes, content_type: str) -> dict:
    msg = email.message_from_bytes(
        b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body, policy=email.policy.HTTP
    )
    out = {}
    for part in msg.iter_parts():
        params = part["Content-Disposition"].params
        out[params["name"]] = (params.get("filename"), part.get_payload(decode=True))
    return out


class FakeDiscord:
    """In-memory REST API: one server, a few channels, one channel's history.

    Pages follow the documented Get Channel Messages semantics (before: the
    newest `limit` older than it; after: the oldest `limit` newer than it), sent
    in `order`. Discord sends newest first; the other orders prove the client
    doesn't depend on it.
    """

    def __init__(self, ids=(), order="newest-first", flags=0, guild_count=1, seed=0, servers=1, members=1):
        self.calls: list[Call] = []
        self.scripted: list[tuple] = []
        self.order = order
        self.rng = random.Random(seed)
        self.app = {"id": APP, "name": "Claude", "flags": flags, "bot_public": True,
                    "approximate_guild_count": guild_count}
        self.me = {"id": APP, "username": "claude-bot", "bot": True}
        self.guilds = [{"id": GUILD, "name": "Test Server"}]
        self.channels = [
            {"id": CATEGORY_ID, "name": "Text", "type": 4, "position": 0, "guild_id": GUILD},
            {"id": GENERAL, "name": "general", "type": 0, "position": 0, "parent_id": CATEGORY_ID,
             "guild_id": GUILD},
            {"id": RANDOM, "name": "random", "type": 0, "position": 1, "parent_id": CATEGORY_ID,
             "guild_id": GUILD},
        ]
        self.by_guild = {GUILD: self.channels}
        if servers > 1:  # near-miss and duplicate names, to prove names must match exactly
            self.guilds.append({"id": GUILD2, "name": "Other Server"})
            self.by_guild[GUILD2] = [{"id": OTHER_GENERAL, "name": "general", "type": 0, "guild_id": GUILD2}]
            self.channels += [
                {"id": "200000000000000021", "name": "general", "type": 4, "position": 2, "guild_id": GUILD},
                {"id": "200000000000000022", "name": "general-2", "type": 0, "position": 3, "guild_id": GUILD},
            ]
        self.history = {GENERAL: [self.message(GENERAL, i) for i in sorted(ids)], RANDOM: []}
        self.members = [{"user": {"id": str(int(USER) + i), "username": f"user{i}"}, "nick": None}
                        for i in range(members)]
        self.threads: list[dict] = []
        self.sent: list[dict] = []
        self.nonces: dict[str, dict] = {}
        self.next_id = BASE_ID + 10**15
        self.server_now = lambda: dt.datetime.now(dt.timezone.utc)  # Discord's clock, sent as Date
        self.created_at = lambda: self.server_now()

    @staticmethod
    def message(channel, mid, content=None, attachments=()):
        return {"id": str(mid), "channel_id": channel, "type": 0,
                "content": f"message {mid}" if content is None else content,
                "author": {"id": USER, "username": "max"}, "attachments": list(attachments), "embeds": []}

    def script(self, status, body=None, headers=None):
        self.scripted.append((status, headers or {}, body))

    def __call__(self, method, url, headers, body):
        parts = urllib.parse.urlsplit(url)
        # Pinned to the real host, not to dc.API, so a change to API can't pass unnoticed.
        assert (parts.scheme, parts.hostname, parts.port) == ("https", "discord.com", None), url
        assert parts.path.startswith("/api/v10/"), url
        call = Call(method, parts.path[len("/api/v10"):], urllib.parse.parse_qs(parts.query), dict(headers), body)
        self.calls.append(call)
        if self.scripted:
            status, rheaders, payload = self.scripted.pop(0)
            raw = payload if isinstance(payload, bytes) else b"" if payload is None else json.dumps(payload).encode()
            return status, rheaders, raw
        status, payload = self.route(call)
        date = email.utils.format_datetime(self.server_now().astimezone(dt.timezone.utc), usegmt=True)
        return status, {"Date": date}, b"" if payload is None else json.dumps(payload).encode()

    def route(self, call: Call):
        m, p, q = call.method, call.path, call.query
        if (m, p) == ("GET", "/users/@me"):
            return 200, self.me
        if (m, p) == ("GET", "/applications/@me"):
            return 200, self.app
        if (m, p) == ("PATCH", "/applications/@me"):
            self.app = {**self.app, "flags": call.json()["flags"]}
            return 200, self.app
        if (m, p) == ("GET", "/users/@me/guilds"):
            after, limit = int(q.get("after", ["0"])[0]), int(q.get("limit", ["200"])[0])
            return 200, sorted((g for g in self.guilds if int(g["id"]) > after), key=lambda g: int(g["id"]))[:limit]
        if (m, p) == ("POST", "/users/@me/channels"):
            return 200, {"id": DM_CHANNEL, "type": 1, "recipients": [{"id": USER, "username": "max"}]}
        if (m, p) == ("GET", f"/users/{USER}"):
            return 200, {"id": USER, "username": "max"}
        chans = re.match(r"^/guilds/(\d+)/channels$", p)
        if m == "GET" and chans and chans.group(1) in self.by_guild:
            return 200, self.by_guild[chans.group(1)]
        if (m, p) == ("GET", f"/guilds/{GUILD}/members"):
            after, limit = int(q.get("after", ["0"])[0]), int(q.get("limit", ["1"])[0])
            assert 1 <= limit <= 1000
            return 200, [x for x in self.members if int(x["user"]["id"]) > after][:limit]
        if (m, p) == ("GET", f"/guilds/{GUILD}/threads/active"):
            return 200, {"threads": self.threads, "members": []}
        if (m, p) == ("GET", f"/guilds/{GUILD}/members/search"):
            return 200, [{"user": {"id": USER, "username": "max"}, "nick": None}]
        if (m, p) == ("GET", f"/guilds/{GUILD}/messages/search"):
            return 200, self.search(q)
        hit = re.match(r"^/channels/(\d+)(/.*)?$", p)
        if hit:
            cid, rest = hit.group(1), hit.group(2) or ""
            if m == "GET" and rest == "":
                if cid == DM_CHANNEL:
                    return 200, {"id": cid, "type": 1, "recipients": [{"username": "max"}]}
                ch = next((c for c in self.channels if c["id"] == cid), None)
                return (200, ch) if ch else (404, {"message": "Unknown Channel", "code": 10003})
            if m == "GET" and rest == "/messages":
                return 200, self.page(cid, q)
            if m == "POST" and rest == "/messages":
                return 200, self.create(cid, call)
            one = re.match(r"^/messages/(\d+)$", rest)
            if one:
                found = next((x for x in self.history.get(cid, []) if x["id"] == one.group(1)), None)
                if m == "GET":
                    return (200, found) if found else (404, {"message": "Unknown Message", "code": 10008})
                if m == "PATCH":
                    return 200, {**(found or {}), **call.json()}
                if m == "DELETE":
                    return 204, None
            if m in ("PUT", "DELETE") and re.match(r"^/messages/\d+/reactions/[^/]+/@me$", rest):
                return 204, None
        return 404, {"message": f"no fake route for {m} {p}", "code": 0}

    def page(self, cid, q):
        msgs = self.history.get(cid, [])
        limit = int(q.get("limit", ["50"])[0])
        if "before" in q:
            sel = [x for x in msgs if int(x["id"]) < int(q["before"][0])][-limit:]
        elif "after" in q:
            sel = [x for x in msgs if int(x["id"]) > int(q["after"][0])][:limit]
        elif "around" in q:
            pivot = int(q["around"][0])
            older = [x for x in msgs if int(x["id"]) < pivot]
            newer = [x for x in msgs if int(x["id"]) >= pivot]
            half = limit // 2
            sel = older[len(older) - half:] + newer[: limit - half]
        else:
            sel = msgs[-limit:]
        sel = list(sel)
        if self.order == "newest-first":
            sel.reverse()
        elif self.order == "shuffled":
            self.rng.shuffle(sel)
        return sel

    def create(self, cid, call: Call):
        ctype = call.headers.get("Content-Type", "")
        if ctype.startswith("multipart/"):
            parts = parse_multipart(call.body, ctype)
            body = json.loads(parts.pop("payload_json")[1])
            body["_files"] = parts
        else:
            body = call.json()
        nonce = body.get("nonce")
        if body.get("enforce_nonce") and nonce in self.nonces:
            return self.nonces[nonce]
        self.next_id += 1
        msg = {"id": str(self.next_id), "channel_id": cid, "content": body.get("content", ""),
               "timestamp": self.created_at().isoformat()}
        self.sent.append(body)
        if nonce:
            self.nonces[nonce] = msg
        return msg

    def search(self, q):
        text = (q.get("content") or [""])[0].lower()
        hits = sorted((x for msgs in self.history.values() for x in msgs if text in x["content"].lower()),
                      key=lambda x: int(x["id"]), reverse=True)
        offset, limit = int(q.get("offset", ["0"])[0]), int(q.get("limit", ["25"])[0])
        return {"total_results": len(hits), "doing_deep_historical_index": False,
                "messages": [[h] for h in hits[offset: offset + limit]]}


def run(fake, *argv, stdin="", clock=None):
    clock = clock or Clock()
    out, err = io.StringIO(), io.StringIO()
    code = dc.main(
        list(argv),
        client_factory=lambda: dc.Client(TOKEN, transport=fake, sleep=clock.sleep, clock=clock.now),
        stdin=io.StringIO(stdin), stdout=out, stderr=err,
    )
    return code, out.getvalue(), err.getvalue()


def ids(n: int, start: int = BASE_ID) -> list[int]:
    return [start + i * 4096 for i in range(n)]


# --------------------------------------------------------------------------- chunking

TEXT = st.text(st.characters(codec="utf-8"), max_size=700)


# Text rich in what chunking must not break: code fences, flags, accents, ZWJ emoji.
TRICKY = st.lists(st.sampled_from([
    "a", "b", " ", "\n", "```", "```py\n", "e\u0301", "\U0001F1FA\U0001F1F8", "\U0001F44D\U0001F3FD",
    "\U0001F468\u200d\U0001F469\u200d\U0001F467", "\u65e5", "\r\n", "`", " \u0301",
]), max_size=400).map("".join)
squash = lambda s: "".join(s.split())  # noqa: E731


@settings(max_examples=300, deadline=None)
@given(text=st.one_of(TEXT, TRICKY), limit=st.integers(2, 160))
def test_chunks_fit_are_never_blank_and_lose_nothing(text, limit):
    parts = dc.chunk_parts(text, limit)
    pieces = dc.chunk_text(text, limit)
    assert pieces == [r + b + c for r, b, c in parts]
    assert all(dc.u16len(p) <= limit for p in pieces)
    assert all(b.strip() for _, b, _ in parts)
    # The bodies are the text itself, in order: only fence lines are added around them.
    assert squash("".join(b for _, b, _ in parts)) == squash(text)
    assert all(r in ("",) or (r.startswith("```") and r.endswith("\n")) for r, _, _ in parts)
    assert all(c in ("", "```", "\n```") for _, _, c in parts)
    if limit < dc.FENCE_MIN_LIMIT:
        assert all(r == c == "" for r, _, c in parts)
    else:
        assert all(dc._fence_after(p, None) is None for p in pieces[:-1]), "a piece left a code block open"
    # Each body is the slice of text that starts where the last slice ended. Its end
    # is a safe cut, unless the back half of its window held none.
    pos = 0
    for _, body, _ in parts:
        start = text.index(body, pos)
        end = pos = start + len(body)
        if end < len(text) and not dc.safe_cut(text, end):
            assert not any(dc.safe_cut(text, j) for j in range(start + (end - start) // 2 + 1, end + 1))


@given(text=TEXT.filter(str.strip))
def test_text_that_fits_stays_one_piece(text):
    if dc.u16len(text) <= dc.CONTENT_LIMIT:
        assert dc.chunk_text(text) == [text]


def test_chunks_never_split_flags_emoji_or_accents():
    """B4: the cuts that the property above allows only when nothing else fits."""
    flags = "\U0001F1FA\U0001F1F8" * 600  # 600 US flags: 1200 code points, 2400 UTF-16 units
    pieces = dc.chunk_text(flags)
    assert len(pieces) == 2 and "".join(pieces) == flags
    assert all(len(p) % 2 == 0 and p.startswith("\U0001F1FA") for p in pieces)
    family = "\U0001F468\u200d\U0001F469\u200d\U0001F467"
    pieces = dc.chunk_text(family * 300)
    assert all(p.startswith("\U0001F468") and p.endswith("\U0001F467") for p in pieces)
    accents = "e\u0301" * 1500
    assert all(not p.startswith("\u0301") for p in dc.chunk_text(accents))
    thai, hangul = "\u0e01\u0e33" * 1500, "\u1100\u1161\u11a8" * 1000
    space_accent = "a" * 1500 + " \u0301" + "b" * 600  # a break after the space would strand the accent
    assert all(not p.startswith("\u0301") for p in dc.chunk_text(space_accent))
    assert all(not p.startswith("\u0e33") for p in dc.chunk_text(thai))
    assert all(p.startswith("\u1100") for p in dc.chunk_text(hangul))


def test_a_code_block_cut_in_two_closes_and_reopens_with_its_language():
    code = "```python\n" + "".join(f"x{i} = {i}\n" for i in range(400)) + "```\nafter"
    pieces = dc.chunk_text(code)
    assert len(pieces) >= 2 and all(dc.u16len(p) <= dc.CONTENT_LIMIT for p in pieces)
    assert pieces[0].startswith("```python\n") and pieces[0].endswith("```")
    assert all(p.startswith("```python\n") for p in pieces[1:])
    assert all(dc._fence_after(p, None) is None for p in pieces)
    assert pieces[-1].endswith("```\nafter")


# What UAX #29 treats specially, for the differential test against the regex module.
GRAPHEME_PARTS = st.sampled_from([
    "a", " ", "\n", "\r", "`", "e", "\u0301", "\u093f", "\u200d", "\u200c", "\ufe0f", "\U0001F3FD",
    "\U0001F1FA", "\U0001F1F8", "\U000E0067", "\U0001F468", "\U0001F44D", "\u0e01", "\u0e33", "\u0eb3",
    "\u1100", "\u1161", "\u11a8", "\uac00", "\uac01", "\ua960", "\ud7b0", "\ud7cb", "\u0600", "\u0d4e",
    "\U000110BD", "\u0915", "\u094d", "\u0937", "\uff76", "\uff9e", "\u00ad", "\u034f",
    "\u0951", "\u1780", "\u17d2", "\u1000", "\u1039", "\U000113D1",
])


@settings(max_examples=600, deadline=None)
@given(text=st.lists(st.one_of(GRAPHEME_PARTS, st.characters(codec="utf-8").filter(
    lambda c: unicodedata.category(c) != "Cn")), max_size=40).map("".join))
def test_every_safe_cut_is_a_grapheme_boundary(text):
    """B4/NEW-7: differential against the regex module's \\X (UAX #29). safe_cut may refuse a
    real boundary (it is stricter around ZWJ, backticks, controls and Indic conjuncts),
    but every cut it allows must be one. Characters this Python doesn't know are left out:
    the regex module's newer Unicode tables would disagree about them."""
    regex = pytest.importorskip("regex")
    bounds = {0} | {m.end() for m in regex.finditer(r"\X", text)}
    for i in range(len(text) + 1):
        if dc.safe_cut(text, i):
            assert i in bounds, (text, i)


def test_chunks_break_after_newlines_and_count_astral_characters_twice():
    text = "a" * 1500 + "\n" + "b" * 1000
    assert dc.chunk_text(text) == ["a" * 1500 + "\n", "b" * 1000]
    emoji = "\N{GRINNING FACE}" * 1001  # 2002 UTF-16 units
    pieces = dc.chunk_text(emoji)
    assert len(pieces) == 2 and all(dc.u16len(p) <= 2000 for p in pieces)


# --------------------------------------------------------------------------- snowflakes, links, cursors

MS = st.integers(dc.DISCORD_EPOCH_MS, dc.DISCORD_EPOCH_MS + (1 << 41) - 1)
SNOW = st.integers(10**16, 10**19).map(str)


@given(MS)
def test_ms_round_trips_through_a_snowflake(ms):
    assert dc.snowflake_ms(dc.ms_snowflake(ms)) == ms


@given(st.integers(0, (1 << 63) - 1))
def test_a_cursor_never_passes_its_snowflake(s):
    assert dc.ms_snowflake(dc.snowflake_ms(s)) <= s


@given(SNOW, SNOW, SNOW)
def test_message_links_parse_back(g, c, m):
    t = dc.parse_target(dc.message_link(g, c, m))
    assert (t.guild_id, t.channel_id, t.message_id) == (g, c, m)
    dm = dc.parse_target(dc.message_link(None, c, m))
    assert (dm.guild_id, dm.channel_id, dm.message_id) == ("@me", c, m)


def test_link_forms_and_names():
    for link in (f"https://discord.com/channels/{GUILD}/{GENERAL}", f"<https://ptb.discord.com/channels/{GUILD}/{GENERAL}>",
                 f"discord.com/channels/{GUILD}/{GENERAL}/", f"https://discordapp.com/channels/{GUILD}/{GENERAL}"):
        assert dc.parse_target(link) == dc.Target(GENERAL, GUILD, None)
    assert dc.parse_target(GENERAL) == dc.Target(GENERAL)
    assert dc.parse_target("#general") is None and dc.parse_target("12345") is None


def test_parse_when_reads_iso_times_and_ids():
    import datetime as dt
    noon_utc = int(dt.datetime(2026, 11, 7, 12, tzinfo=dt.timezone.utc).timestamp() * 1000)
    assert noon_utc == 1_794_052_800_000
    assert dc.snowflake_ms(dc.parse_when("2026-11-07T12:00:00Z")) == noon_utc
    assert dc.snowflake_ms(dc.parse_when("2026-11-07T07:00:00-05:00")) == noon_utc
    local_midnight = int(dt.datetime(2026, 11, 7).astimezone().timestamp() * 1000)
    assert dc.snowflake_ms(dc.parse_when("2026-11-07")) == local_midnight
    assert dc.parse_when(GENERAL) == int(GENERAL)
    assert dc.parse_when(dc.message_link(GUILD, GENERAL, USER)) == int(USER)
    with pytest.raises(dc.UsageError):
        dc.parse_when("last tuesday")


# --------------------------------------------------------------------------- history (differential)

HISTORY_IDS = st.lists(st.integers(0, 10**6), unique=True, max_size=320).map(
    lambda xs: sorted(BASE_ID + x * 4096 for x in xs)
)


@settings(max_examples=200, deadline=None)
@given(history_ids=HISTORY_IDS, data=st.data())
def test_history_returns_what_the_documented_semantics_select(history_ids, data):
    order = data.draw(st.sampled_from(["newest-first", "oldest-first", "shuffled"]))
    limit = data.draw(st.one_of(st.none(), st.integers(1, 350)))
    cursors = [st.none(), st.integers(BASE_ID - 10, BASE_ID + 10**6 * 4096 + 10)]
    if history_ids:
        cursors.append(st.sampled_from(history_ids))
    before, after = data.draw(st.one_of(*cursors)), data.draw(st.one_of(*cursors))
    fake = FakeDiscord(history_ids, order=order, seed=len(history_ids))
    client = dc.Client(TOKEN, transport=fake, sleep=lambda s: None)
    got = [int(m["id"]) for m in dc.history(client, GENERAL, limit=limit, before=before, after=after)]
    if after is not None and before is None:
        cand = [i for i in history_ids if i > after]
        want = cand[:limit] if limit else cand
    else:
        cand = [i for i in history_ids if (before is None or i < before) and (after is None or i > after)]
        want = cand[-limit:] if limit else cand
    assert got == want
    assert all(len(c.query.get("limit", ["0"])) == 1 and 1 <= int(c.query["limit"][0]) <= 100 for c in fake.calls)


def test_read_prints_oldest_first_and_resolves_names():
    fake = FakeDiscord(ids(5))
    code, out, _ = run(fake, "read", "Test Server/#general", "-n", "3")
    assert code == 0
    shown = re.findall(r"\((\d+)\)", out)
    assert shown == [str(i) for i in ids(5)[2:]]
    code, out, _ = run(fake, "read", "#general", "-n", "1", "--json")
    assert code == 0 and json.loads(out)[0]["id"] == str(ids(5)[-1])
    code, _, err = run(fake, "read", "#nope")
    assert code == 2 and "no channel named #nope" in err


def test_read_warns_when_every_message_is_empty():
    fake = FakeDiscord()
    fake.history[GENERAL] = [FakeDiscord.message(GENERAL, i, content="") for i in ids(3)]
    code, _, err = run(fake, "read", GENERAL)
    assert code == 0 and "message-content intent is probably off" in err


# --------------------------------------------------------------------------- the dry-run gate

def write_commands():
    link = dc.message_link(GUILD, GENERAL, str(ids(1)[0]))
    return [
        ["send", GENERAL, "hello"],
        ["send", "Test Server/#general", "hi there"],
        ["send", link, "a reply"],
        ["dm", USER, "hi"],
        ["dm", f"<@{USER}>", "hi"],
        ["edit", link, "new text"],
        ["edit", GENERAL, str(ids(1)[0]), "new text"],
        ["delete", link],
        ["react", link, "\N{THUMBS UP SIGN}"],
        ["react", GENERAL, str(ids(1)[0]), "\N{THUMBS UP SIGN}", "--remove"],
        ["setup"],
    ]


@pytest.mark.parametrize("argv", write_commands(), ids=lambda a: " ".join(a[:2]))
def test_without_yes_nothing_but_gets_and_exit_3(argv):
    fake = FakeDiscord(ids(1))
    code, out, _ = run(fake, *argv)
    assert code == dc.DRY_RUN_EXIT, out
    assert "DRY RUN, nothing sent" in out
    assert {c.method for c in fake.calls} <= {"GET"}


@settings(max_examples=60, deadline=None)
@given(text=st.text(st.characters(codec="utf-8"), min_size=1, max_size=5000).filter(str.strip))
def test_send_without_yes_never_writes_whatever_the_text(text):
    fake = FakeDiscord()
    code, _, _ = run(fake, "send", GENERAL, "-", stdin=text)  # stdin: text may start with "-"
    assert code == dc.DRY_RUN_EXIT
    assert {c.method for c in fake.calls} <= {"GET"} and not fake.sent


# --------------------------------------------------------------------------- writes with --yes

def test_long_send_posts_every_chunk_with_a_fresh_nonce_and_no_pings():
    text = "\n".join(f"line {i} @everyone " + "x" * 60 for i in range(70))
    fake = FakeDiscord(ids(1))
    code, out, _ = run(fake, "send", dc.message_link(GUILD, GENERAL, str(ids(1)[0])), text, "--yes")
    assert code == 0
    posts = [c.json() for c in fake.calls if c.method == "POST"]
    assert len(posts) == len(dc.chunk_text(text)) >= 3
    nonces = [p["nonce"] for p in posts]
    assert len(set(nonces)) == len(nonces) and all(len(n) <= 25 for n in nonces)
    assert all(p["enforce_nonce"] is True for p in posts)
    assert all(p["allowed_mentions"] == {"parse": [], "replied_user": False} for p in posts)
    assert posts[0]["message_reference"] == {"message_id": str(ids(1)[0])}
    assert all("message_reference" not in p for p in posts[1:])
    assert out.count("sent https://discord.com/channels/") == len(posts)


def test_allow_flags_open_mentions():
    fake = FakeDiscord()
    run(fake, "send", GENERAL, "hi", "--yes", "--allow-mentions", "--allow-everyone")
    body = next(c.json() for c in fake.calls if c.method == "POST")
    assert body["allowed_mentions"] == {"parse": ["users", "roles", "everyone"], "replied_user": True}


def test_files_ride_on_the_first_message_as_multipart(tmp_path):
    note = tmp_path / "note.txt"
    note.write_bytes(b"hello file\n")
    fake = FakeDiscord()
    code, _, _ = run(fake, "send", GENERAL, "x" * 2500, "--file", str(note), "--yes")
    assert code == 0
    first, second = fake.sent
    assert first["attachments"] == [{"id": 0, "filename": "note.txt"}]
    assert first["_files"]["files[0]"] == ("note.txt", b"hello file\n")
    assert "_files" not in second and "attachments" not in second


def test_files_alone_need_no_text(tmp_path):
    pic = tmp_path / "pic.png"
    pic.write_bytes(b"\x89PNG")
    fake = FakeDiscord()
    code, _, _ = run(fake, "send", GENERAL, "--file", str(pic), "--yes")
    assert code == 0 and "content" not in fake.sent[0] and fake.sent[0]["_files"]["files[0]"][0] == "pic.png"


def test_a_lost_response_is_retried_without_a_duplicate():
    fake = FakeDiscord()
    dropped = {"done": False}

    def flaky(method, url, headers, body):
        answer = fake(method, url, headers, body)
        if method == "POST" and not dropped["done"]:
            dropped["done"] = True
            raise dc.TransportError("connection reset after the server acted")
        return answer

    code, out, _ = run(flaky, "send", GENERAL, "once only", "--yes")
    assert code == 0
    assert len(fake.sent) == 1 and out.count("sent ") == 1
    assert len([c for c in fake.calls if c.method == "POST"]) == 2


def test_dm_opens_the_channel_then_posts():
    fake = FakeDiscord()
    code, out, _ = run(fake, "dm", USER, "hello", "--yes")
    assert code == 0
    assert [(c.method, c.path) for c in fake.calls if c.method != "GET"] == [
        ("POST", "/users/@me/channels"), ("POST", f"/channels/{DM_CHANNEL}/messages")]
    assert f"https://discord.com/channels/@me/{DM_CHANNEL}/" in out


def test_edit_delete_and_react_hit_the_right_routes():
    mid = str(ids(1)[0])
    link = dc.message_link(GUILD, GENERAL, mid)
    fake = FakeDiscord(ids(1))
    assert run(fake, "edit", link, "fixed", "--yes")[0] == 0
    assert run(fake, "delete", GENERAL, mid, "--yes")[0] == 0
    assert run(fake, "react", link, "\N{THUMBS UP SIGN}", "--yes")[0] == 0
    assert run(fake, "react", link, "<:party:123456789012345678>", "--yes", "--remove")[0] == 0
    writes = [(c.method, c.path) for c in fake.calls if c.method != "GET"]
    assert writes == [
        ("PATCH", f"/channels/{GENERAL}/messages/{mid}"),
        ("DELETE", f"/channels/{GENERAL}/messages/{mid}"),
        ("PUT", f"/channels/{GENERAL}/messages/{mid}/reactions/%F0%9F%91%8D/@me"),
        ("DELETE", f"/channels/{GENERAL}/messages/{mid}/reactions/party:123456789012345678/@me"),
    ]
    patch = next(c.json() for c in fake.calls if c.method == "PATCH")
    assert patch == {"content": "fixed", "allowed_mentions": {"parse": [], "replied_user": False}}


def test_edit_refuses_text_longer_than_one_message():
    code, _, err = run(FakeDiscord(ids(1)), "edit", GENERAL, str(ids(1)[0]), "x" * 2001, "--yes")
    assert code == 2 and "must fit in one message" in err


# --------------------------------------------------------------------------- retries and rate limits

def client_for(transport, clock=None):
    clock = clock or Clock()
    return dc.Client(TOKEN, transport=transport, sleep=clock.sleep, clock=clock.now), clock


def test_post_and_patch_never_repeat_unless_marked_safe():
    for method in ("POST", "PATCH"):
        fake = FakeDiscord()
        fake.script(500, {"message": "boom"})
        client, _ = client_for(fake)
        with pytest.raises(dc.DiscordError):
            client.request(method, "/applications/@me", body={})
        assert len(fake.calls) == 1

    def down(*_):
        raise dc.TransportError("reset")

    client, _ = client_for(down)
    with pytest.raises(dc.DiscordError):
        client.request("POST", "/users/@me/channels", body={})
    fake = FakeDiscord()
    fake.script(502, {"message": "bad gateway"})
    client, _ = client_for(fake)
    assert client.request("PATCH", "/applications/@me", body={"flags": 0}, retry_unsafe=True)["id"] == APP
    assert len(fake.calls) == 2


def test_gets_retry_server_errors_then_give_up():
    fake = FakeDiscord()
    for _ in range(10):
        fake.script(503, {"message": "unavailable"})
    client, clock = client_for(fake)
    with pytest.raises(dc.DiscordError) as e:
        client.request("GET", "/users/@me")
    assert e.value.status == 503 and len(fake.calls) == client.max_retries + 1 and len(clock.slept) == client.max_retries


def test_429_waits_what_discord_asks():
    fake = FakeDiscord()
    fake.script(429, {"message": "slow down", "retry_after": 1.5, "global": True})
    client, clock = client_for(fake)
    assert client.request("GET", "/users/@me")["id"] == APP
    assert clock.slept == [1.5]
    fake.script(429, {"retry_after": 0.25, "global": True}, {"x-ratelimit-global": "true"})
    client.request("GET", "/applications/@me")
    assert clock.slept == [1.5, 0.25]


def test_a_long_429_fails_fast_instead_of_hanging():
    fake = FakeDiscord()
    fake.script(429, {"message": "banned for an hour", "retry_after": 3600})
    client, clock = client_for(fake)
    with pytest.raises(dc.DiscordError) as e:
        client.request("GET", "/users/@me")
    assert e.value.status == 429 and clock.slept == []


def test_an_empty_bucket_waits_for_its_reset():
    fake = FakeDiscord()
    fake.script(200, {"id": "1"}, {"x-ratelimit-remaining": "0", "x-ratelimit-reset-after": "2.5"})
    client, clock = client_for(fake)
    client.request("GET", f"/channels/{GENERAL}/messages")
    client.request("GET", f"/channels/{GENERAL}/messages")
    assert clock.slept == [2.5]
    client.request("GET", f"/channels/{RANDOM}/messages")  # another major id: its own bucket
    assert clock.slept == [2.5]


def test_an_unexpected_shape_is_a_clear_error_not_a_crash():
    fake = FakeDiscord()
    fake.script(202, {"message": "accepted"})
    code, _, err = run(fake, "guilds")
    assert code == 1 and "expected a list, got dict" in err


def test_route_keys_keep_only_the_major_id():
    assert dc.route_key("GET", f"/channels/{GENERAL}/messages/123456789012345678") == \
        f"GET /channels/{GENERAL}/messages/:id"
    assert dc.route_key("GET", "/users/123456789012345678") == "GET /users/:id"


def test_search_waits_out_a_202_and_flattens_hits():
    fake = FakeDiscord(ids(40))
    fake.script(202, {"message": "Index not yet available. Try again later", "code": 110000, "retry_after": 2})
    code, out, err = run(fake, "search", GUILD, "message", "-n", "30")  # an id: the 202 meets the search call
    assert code == 0
    assert len(re.findall(r"^\[", out, re.M)) == 30 and "30 shown of 40" in err
    searches = [c for c in fake.calls if c.path.endswith("/messages/search")]
    assert [c.query["offset"][0] for c in searches] == ["0", "0", "25"]
    assert all(int(c.query["limit"][0]) <= 25 for c in searches)


# --------------------------------------------------------------------------- the token

FAILURES = [
    (401, {"message": "401: Unauthorized", "code": 0}),
    (403, {"message": "Missing Access", "code": 50001}),
    (500, {"message": "Internal Server Error"}),
    (429, {"message": "slow", "retry_after": 3600}),
    (400, {"message": f"echoed Bot {TOKEN} back"}),
    "network",
]
COMMANDS = [["whoami"], ["guilds"], ["read", GENERAL], ["send", GENERAL, "hi", "--yes"], ["setup", "--yes"]]


@pytest.mark.parametrize("failure", FAILURES, ids=lambda f: str(f if isinstance(f, str) else f[0]))
@pytest.mark.parametrize("argv", COMMANDS, ids=lambda a: a[0])
def test_the_token_never_reaches_the_terminal(failure, argv):
    def transport(method, url, headers, body):
        assert headers["Authorization"] == f"Bot {TOKEN}"
        if failure == "network":
            raise dc.TransportError("connection reset by peer")
        status, payload = failure
        return status, {}, json.dumps(payload).encode()

    code, out, err = run(transport, *argv)
    assert code in (1, 2)
    assert TOKEN not in out + err and "discord:" in err
    assert repr(dc.Client(TOKEN)) == "Client(<token hidden>)"


def test_every_request_goes_to_the_api_with_the_bot_header():
    fake = FakeDiscord(ids(3))
    for argv in (["whoami"], ["guilds"], ["channels", GUILD, "--threads"], ["read", GENERAL, "--all"],
                 ["members", GUILD, "--query", "ma"], ["send", GENERAL, "hi", "--yes"]):
        assert run(fake, *argv)[0] == 0
    assert fake.calls
    for c in fake.calls:
        assert c.headers["Authorization"] == f"Bot {TOKEN}"
        assert c.headers["User-Agent"].startswith("DiscordBot (https://github.com/MaxGhenis/dotfiles, ")


def test_the_api_opener_never_follows_a_redirect(monkeypatch):
    seen = []

    class Landing(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(dict(self.headers))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    landing = http.server.HTTPServer(("127.0.0.1", 0), Landing)

    class Bounce(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{landing.server_port}/landing")
            self.end_headers()

        def log_message(self, *args):
            pass

    bounce = http.server.HTTPServer(("127.0.0.1", 0), Bounce)
    for server in (landing, bounce):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    # Same handler chain as the real opener, minus any proxy the environment sets.
    monkeypatch.setattr(dc, "_API_OPENER", urllib.request.build_opener(urllib.request.ProxyHandler({}), dc._NoRedirect))
    try:
        status, _, _ = dc.urllib_transport("GET", f"http://127.0.0.1:{bounce.server_port}/x",
                                           {"Authorization": f"Bot {TOKEN}"}, None, timeout=5)
    finally:
        for server in (landing, bounce):
            server.shutdown()
            server.server_close()
    assert status == 302 and seen == []


def test_attachment_downloads_send_no_token_and_only_hit_the_cdn(monkeypatch):
    captured = {}

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b"data"

    def fake_urlopen(req, timeout=None):
        captured.update(url=req.full_url, headers=dict(req.header_items()))
        return Resp()

    monkeypatch.setattr(dc._CDN_OPENER, "open", fake_urlopen)
    assert dc.fetch_url("https://cdn.discordapp.com/attachments/1/2/a.png?ex=1&hm=2") == b"data"
    assert not any(k.lower() == "authorization" for k in captured["headers"])
    for bad in ("http://cdn.discordapp.com/a.png", "https://evil.example/a.png", "file:///etc/passwd"):
        with pytest.raises(dc.DiscordError):
            dc.fetch_url(bad)


# --------------------------------------------------------------------------- downloads

@given(st.text(max_size=400))
def test_safe_filenames_cannot_leave_the_folder(name):
    out = dc.safe_filename(name, "fallback")
    assert out and "/" not in out and "\\" not in out and not out.startswith((".", "-"))
    assert len(out.encode("utf-8")) <= dc.NAME_BYTES  # fits ext4 (255 bytes) and APFS (255 units)
    assert out == "fallback" or all(c.isprintable() for c in out)


def test_download_saves_sanitized_unique_names(tmp_path, monkeypatch):
    mid = ids(1)[0]
    fake = FakeDiscord()
    fake.history[GENERAL] = [FakeDiscord.message(GENERAL, mid, attachments=[
        {"filename": "../../evil.sh", "url": "https://cdn.discordapp.com/a/1", "size": 4},
        {"filename": "notes.txt", "url": "https://cdn.discordapp.com/a/2", "size": 4},
        {"filename": "notes.txt", "url": "https://cdn.discordapp.com/a/3", "size": 4},
    ])]
    monkeypatch.setattr(dc, "fetch_url", lambda url, timeout=60.0: url.encode())
    code, out, _ = run(fake, "download", dc.message_link(GUILD, GENERAL, str(mid)), "--dir", str(tmp_path / "dl"))
    assert code == 0
    assert sorted(p.name for p in (tmp_path / "dl").iterdir()) == ["evil.sh", "notes (2).txt", "notes.txt"]
    assert (tmp_path / "dl" / "notes (2).txt").read_bytes() == b"https://cdn.discordapp.com/a/3"
    assert not (tmp_path / "evil.sh").exists()


# --------------------------------------------------------------------------- setup, invite, whoami

def test_setup_dry_runs_then_turns_on_the_limited_intents():
    fake = FakeDiscord(flags=1 << 23)
    code, out, _ = run(fake, "setup")
    assert code == dc.DRY_RUN_EXIT and not [c for c in fake.calls if c.method == "PATCH"]
    code, out, _ = run(fake, "setup", "--yes")
    assert code == 0 and "turned on: message-content, members" in out
    patch = next(c.json() for c in fake.calls if c.method == "PATCH")
    assert patch == {"flags": (1 << 23) | (1 << 19) | (1 << 15)}
    assert f"client_id={APP}" in out and f"permissions={DOCUMENTED_PERMISSIONS}" in out
    assert "Public Bot is on" in out


def test_setup_leaves_on_intents_alone_and_skips_members_on_request():
    fake = FakeDiscord(flags=(1 << 19) | (1 << 15))
    assert run(fake, "setup", "--yes")[0] == 0
    fake2 = FakeDiscord(flags=0)
    run(fake2, "setup", "--yes", "--no-members")
    assert [c.json() for c in fake.calls + fake2.calls if c.method == "PATCH"] == [{"flags": 1 << 19}]


def test_setup_will_not_self_grant_past_100_servers():
    fake = FakeDiscord(flags=0, guild_count=150)
    code, out, _ = run(fake, "setup", "--yes")
    assert code == 1 and "Discord must approve" in out
    assert not [c for c in fake.calls if c.method == "PATCH"]


def test_invite_url_matches_the_documented_bits():
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(dc.invite_url(APP)).query)
    assert query == {"client_id": [APP], "scope": ["bot"], "permissions": [str(DOCUMENTED_PERMISSIONS)],
                     "integration_type": ["0"]}
    q2 = urllib.parse.parse_qs(urllib.parse.urlsplit(dc.invite_url(APP, 2048, GUILD)).query)
    assert q2["guild_id"] == [GUILD] and q2["disable_guild_select"] == ["true"] and q2["permissions"] == ["2048"]
    assert dc.permissions_value("view_channel,send-messages") == (1 << 10) | (1 << 11)
    with pytest.raises(dc.UsageError):
        dc.permissions_value("administrator")
    code, out, _ = run(FakeDiscord(), "invite", "--guild", "Test Server")
    assert code == 0 and f"guild_id={GUILD}" in out


def test_whoami_reports_intents():
    code, out, _ = run(FakeDiscord(flags=1 << 19), "whoami")
    assert code == 0 and "message-content: on (limited)" in out and "members: off" in out


def test_channels_prints_a_tree():
    code, out, _ = run(FakeDiscord(), "channels", "Test Server")
    lines = out.splitlines()
    assert code == 0 and lines[0].endswith("category      Text")
    assert lines[1].split() == [GENERAL, "text", "#general"] and lines[2].split() == [RANDOM, "text", "#random"]


# --------------------------------------------------------------------------- the token source

def test_token_sources():
    class Got:
        def __init__(self, rc, out):
            self.returncode, self.stdout, self.stderr = rc, out, ""

    assert dc.load_token({"DISCORD_BOT_TOKEN": f"Bot {TOKEN}"}, run=None) == TOKEN
    calls = []
    assert dc.load_token({}, run=lambda argv, **kw: calls.append(argv) or Got(0, f"{TOKEN}\n")) == TOKEN
    assert calls == [["agent-secret", "get", "agent/discord-bot-token"]]
    with pytest.raises(dc.UsageError) as e:
        dc.load_token({}, run=lambda argv, **kw: Got(1, ""))
    assert "agent-secret set agent/discord-bot-token" in str(e.value)

    def not_executable(argv, **kw):
        raise PermissionError(13, "Permission denied", "agent-secret")

    with pytest.raises(dc.UsageError):
        dc.load_token({}, run=not_executable)


@pytest.mark.parametrize("bad", [f"{TOKEN}\nsecond-line", f"{TOKEN[:20]}\r{TOKEN[20:]}", f"{TOKEN} x", "tok\x00en"])
def test_a_token_with_a_line_break_is_refused_without_echoing_it(bad):
    with pytest.raises(dc.UsageError) as e:
        dc.load_token({"DISCORD_BOT_TOKEN": bad}, run=None)
    assert "line break" in str(e.value)
    assert not any(seg in str(e.value) for seg in re.split(r"[.\s]+", bad) if len(seg) >= 8)


def test_the_real_entry_point_without_a_token(tmp_path):
    fake_secret = tmp_path / "agent-secret"
    fake_secret.write_text("#!/bin/sh\nexit 1\n")
    fake_secret.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k != "DISCORD_BOT_TOKEN"}
    env["PATH"] = str(tmp_path)
    done = subprocess.run([sys.executable, str(SCRIPT), "whoami"], capture_output=True, text=True, env=env, timeout=60)
    assert done.returncode == 2 and "agent-secret set agent/discord-bot-token" in done.stderr
    helped = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True, timeout=60)
    assert helped.returncode == 0 and "discord setup" in helped.stdout
    assert subprocess.run([sys.executable, str(SCRIPT), "--version"], capture_output=True, text=True).stdout.startswith("discord ")


# =========================================================================== review fixes (1.1.0)
# Each test names the finding it pins: A* (security), B* (Discord's docs and
# paging), C* (odd input and test gaps), from the review of PR #11.


def serve(handler_cls):
    """A loopback HTTP server on a thread; returns (server, base_url)."""
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


def stop(*servers):
    for server in servers:
        server.shutdown()
        server.server_close()


class Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass


# --------------------------------------------------------------------------- the token's route (A1, A2, C19)

def test_the_api_constant_and_the_real_opener_are_pinned():
    """C19: the fake checks the host itself, and the opener the CLI uses holds no redirect follower."""
    assert dc.API == "https://discord.com/api/v10"
    handlers = dc._API_OPENER.handlers
    assert any(isinstance(h, dc._NoRedirect) for h in handlers)
    assert not any(type(h) is urllib.request.HTTPRedirectHandler for h in handlers)
    assert any(isinstance(h, dc._CdnRedirect) for h in dc._CDN_OPENER.handlers)


def test_an_unexpected_exception_is_one_redacted_line_not_a_traceback():
    """A1/C3: http.client rejects a header holding a line break with a ValueError
    whose text quotes the header; main() must catch it and redact every form."""
    def transport(method, url, headers, body):
        raise ValueError(f"Invalid header value {('Bot ' + TOKEN + chr(10) + 'x').encode()!r}")

    code, out, err = run(transport, "whoami")
    assert code == 1 and err.startswith("discord: unexpected ValueError")
    assert "SENTINEL-bot-token" not in out + err and "0123456789abcdef" not in err
    assert "Traceback" not in err


def test_an_echoed_token_is_redacted_before_the_error_is_cut():
    """A2: the token straddling the 300-character cut once printed all but its tail."""
    def leaked(err):  # any 6 characters of the token in a row
        return [TOKEN[i:i + 6] for i in range(len(TOKEN) - 5) if TOKEN[i:i + 6] in err]

    for pad in range(200, 300, 7):  # the cut lands before, inside and after each part of the token
        fake = FakeDiscord()
        fake.script(400, {"message": "x" * pad + f" Bot {TOKEN} trailing"})
        code, _, err = run(fake, "whoami")
        assert code == 1 and not leaked(err), pad
        fake = FakeDiscord()
        fake.script(403, b"<html>" + b"y" * pad + f"Authorization: Bot {TOKEN}".encode())
        code, _, err = run(fake, "whoami")
        assert code == 1 and not leaked(err), pad


def test_redact_catches_quoted_and_partial_forms():
    secret = "MTAx.GabcDE.SENTINELsecretHMAC\nsecond"
    text = f"a {secret!r} b {secret.encode()!r} c SENTINELsecretHMAC d"
    out = dc.redact(text, [secret])
    assert "SENTINELsecretHMAC" not in out and "GabcDE" not in out


# --------------------------------------------------------------------------- no answer (A9, C4)

def truncating_server(record):
    class Handler(Quiet):
        def do_POST(self):
            record.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.send_header("Content-Length", "500")
            self.end_headers()
            self.wfile.write(b'{"id": "1"')  # 10 of 500 bytes, then the connection closes
            self.close_connection = True

        do_GET = do_POST

    return serve(Handler)


def test_a_body_cut_short_is_no_answer_so_the_nonce_retry_runs(monkeypatch):
    """A9/C4: IncompleteRead (an HTTPException, not an OSError) used to escape as a traceback."""
    got = []
    server, base = truncating_server(got)
    monkeypatch.setattr(dc, "_API_OPENER", urllib.request.build_opener(urllib.request.ProxyHandler({}), dc._NoRedirect))
    try:
        with pytest.raises(dc.TransportError) as e:
            dc.urllib_transport("POST", base + "/x", {"Content-Type": "application/json"}, b"{}", timeout=5)
        assert "IncompleteRead" in str(e.value)

        def transport(method, url, headers, body):
            return dc.urllib_transport(method, base + "/api", headers, body, timeout=5)

        clock = Clock()
        client = dc.Client(TOKEN, transport=transport, sleep=clock.sleep, clock=clock.now)
        body = dc.message_payloads("once", mentions={"parse": []}, seed="s")[0]
        with pytest.raises(dc.DiscordError) as e:
            client.request("POST", f"/channels/{GENERAL}/messages", body=body, retry_unsafe=True)
    finally:
        stop(server)
    sent = [json.loads(b) for b in got[1:]]
    assert len(sent) == client.max_retries + 1, "every retry carries the same body"
    assert all(s["nonce"] == body["nonce"] and s["enforce_nonce"] for s in sent)
    assert "may have gone through" in str(e.value)


def test_a_non_json_success_is_a_clear_error():
    """C2."""
    fake = FakeDiscord()
    fake.script(200, b"<html><title>Captive portal</title></html>")
    code, _, err = run(fake, "guilds")
    assert code == 1 and "non-JSON answer: Captive portal" in err


def test_a_redirect_is_an_error_not_success():
    """C23: the API opener returns a 3xx instead of following it; that must not read as success."""
    fake = FakeDiscord()
    fake.script(302, b"", {"Location": "https://elsewhere.example/"})
    code, _, err = run(fake, "whoami")
    assert code == 1 and "HTTP 302" in err


# --------------------------------------------------------------------------- retries, rate limits, 202 (A7, B2, B3, C13, C22)

def test_a_message_post_stops_retrying_inside_the_nonce_window():
    """A7/B10: no resend later than POST_RETRY_BUDGET after the first try."""
    clock = Clock()
    times = []

    def transport(method, url, headers, body):
        times.append(clock.t)
        if len(times) == 1:
            raise dc.TransportError("reset after Discord acted")
        return 429, {"x-ratelimit-remaining": "0", "x-ratelimit-reset-after": "50"}, b'{"retry_after": 50}'

    client = dc.Client(TOKEN, transport=transport, sleep=clock.sleep, clock=clock.now)
    body = dc.message_payloads("hi", mentions={"parse": []}, seed="s")[0]
    with pytest.raises(dc.DiscordError) as e:
        client.request("POST", f"/channels/{GENERAL}/messages", body=body, retry_unsafe=True)
    assert max(times) - times[0] <= dc.POST_RETRY_BUDGET
    assert "may have gone through" in str(e.value)


def test_a_bucket_reset_past_the_cap_fails_fast_and_long_waits_are_announced():
    """B3: an exhausted bucket's wait is capped like a 429's, and waits of 5 s or more say so."""
    fake = FakeDiscord()
    fake.script(200, {"id": "1"}, {"x-ratelimit-remaining": "0", "x-ratelimit-reset-after": "3600"})
    clock = Clock()
    notes = []
    client = dc.Client(TOKEN, transport=fake, sleep=clock.sleep, clock=clock.now, on_wait=lambda s, w: notes.append(w))
    client.request("GET", f"/channels/{GENERAL}/messages")
    with pytest.raises(dc.DiscordError) as e:
        client.request("GET", f"/channels/{GENERAL}/messages")
    assert e.value.status == 429 and clock.slept == []
    fake.script(429, {"retry_after": 7})
    client.request("GET", "/users/@me")
    assert clock.slept == [7] and notes == ["rate limit"]


def test_routes_sharing_a_discord_bucket_wait_together():
    """B3: X-RateLimit-Bucket ties two routes to one limit."""
    fake = FakeDiscord()
    shared = {"x-ratelimit-bucket": "abc123"}
    fake.script(200, {"id": "1"}, shared)
    fake.script(200, {"id": "1"}, {**shared, "x-ratelimit-remaining": "0", "x-ratelimit-reset-after": "2"})
    client, clock = client_for(fake)
    client.request("PUT", f"/channels/{GENERAL}/messages/{BASE_ID}/reactions/a/@me")
    client.request("PUT", f"/channels/{GENERAL}/messages/{BASE_ID}/reactions/b/@me")
    client.request("PUT", f"/channels/{GENERAL}/messages/{BASE_ID}/reactions/a/@me")
    assert clock.slept == [2.0]


def test_a_429_with_only_a_retry_after_header_is_honored():
    """C23."""
    fake = FakeDiscord()
    fake.script(429, b"", {"retry-after": "3"})
    client, clock = client_for(fake)
    assert client.request("GET", "/users/@me")["id"] == APP and clock.slept == [3.0]


def test_a_429_with_no_rate_limit_details_fails_at_once():
    """C13: a Cloudflare block page asks for nothing; retrying it only deepens the block."""
    fake = FakeDiscord()
    fake.script(429, b"<html><title>Access denied</title></html>")
    client, clock = client_for(fake)
    with pytest.raises(dc.DiscordError) as e:
        client.request("GET", "/users/@me")
    assert "Cloudflare" in str(e.value) and clock.slept == [] and len(fake.calls) == 1


def test_a_202_with_retry_after_0_waits_a_growing_short_delay_then_gives_up():
    """B2 and C22: retry_after 0 means "after a short delay"; a 202 that never ends fails."""
    fake = FakeDiscord()
    for _ in range(10):
        fake.script(202, {"message": "Index not yet available", "code": 110000, "retry_after": 0})
    client, clock = client_for(fake)
    with pytest.raises(dc.DiscordError) as e:
        client.request("GET", f"/guilds/{GUILD}/messages/search", retry_202=True)
    assert e.value.status == 202
    assert clock.slept == [1.0, 2.0, 4.0, 8.0, 16.0]


def test_a_large_upload_is_resent_once_at_most(tmp_path):
    """C18: a reset mid-upload re-sent the whole body six times."""
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * 1000)
    tries = []

    def down(method, url, headers, body):
        tries.append(len(body))
        raise dc.TransportError("Broken pipe")

    client, _ = client_for(down)
    body = dc.message_payloads("", mentions={"parse": []}, seed="s")[0]
    with pytest.raises(dc.DiscordError):
        client.request("POST", f"/channels/{GENERAL}/messages", body=body, files=[f], retry_unsafe=True)
    assert len(tries) == 2


# --------------------------------------------------------------------------- the --yes gate (A8, C20)

def gate_cases(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("attached")
    link = dc.message_link(GUILD, GENERAL, str(ids(1)[0]))
    return [
        ["send", GENERAL, "hi", "--file", str(f)],
        ["send", GENERAL, "--file", str(f)],
        ["dm", USER, "hi", "--file", str(f)],
        ["dm", USER, "--file", str(f)],
        ["send", GENERAL, "@everyone", "--allow-everyone", "--allow-mentions"],
        ["send", GENERAL, "x", "--reply-to", str(ids(1)[0])],
        ["send", GENERAL, "x", "--again"],
        ["send", link, "reply", "--allow-mentions"],
        ["edit", link, "--allow-everyone", "new"],
        ["react", link, "\N{THUMBS UP SIGN}", "--remove"],
        ["setup", "--no-members"],
    ]


def test_every_flag_combination_still_dry_runs_without_yes(tmp_path):
    """C20: the gate held only for the plain forms the old tests tried."""
    for argv in gate_cases(tmp_path):
        fake = FakeDiscord(ids(1))
        code, out, _ = run(fake, *argv)
        assert code == dc.DRY_RUN_EXIT and "DRY RUN, nothing sent" in out, argv
        assert {c.method for c in fake.calls} <= {"GET"} and not fake.sent, argv


@settings(max_examples=60, deadline=None)
@given(flags=st.lists(st.sampled_from(["--allow-mentions", "--allow-everyone", "--again"]), unique=True),
       reply=st.booleans())
def test_the_gate_is_a_property_of_the_flags(flags, reply):
    argv = ["send", GENERAL, "text", *flags] + (["--reply-to", str(ids(1)[0])] if reply else [])
    fake = FakeDiscord(ids(1))
    assert run(fake, *argv)[0] == dc.DRY_RUN_EXIT
    assert {c.method for c in fake.calls} <= {"GET"}


@pytest.mark.parametrize("almost", ["--y", "--ye", "--yes=1", "--YES"])
def test_only_the_exact_yes_opens_the_gate(almost):
    """A8: argparse used to accept --y and --ye as --yes."""
    fake = FakeDiscord()
    with pytest.raises(SystemExit) as e:
        run(fake, "send", GENERAL, "hello", almost)
    assert e.value.code == 2 and not fake.sent


def test_text_spelled_like_a_flag_never_opens_the_gate():
    """A8: `send C "$MSG"` with MSG=--yes posts nothing, and doesn't fall back to stdin."""
    fake = FakeDiscord()
    code, _, err = run(fake, "send", GENERAL, "--yes", stdin="piped text")
    assert code == 2 and "no text" in err and not fake.sent
    code, out, _ = run(fake, "send", GENERAL, "--", "--yes")
    assert code == dc.DRY_RUN_EXIT and "--yes" in out and not fake.sent


@pytest.mark.parametrize("text", ["-hey", "-hello", "-help", "-h1", "-hello world", "-h is the help flag"])
def test_dash_h_text_is_an_error_not_help_with_exit_0(text):
    """C15: argparse read -hey as -h and exited 0, which looked like success."""
    with pytest.raises(SystemExit) as e:
        run(FakeDiscord(), "send", GENERAL, text)
    assert e.value.code == 2
    code, out, _ = run(FakeDiscord(), "send", GENERAL, "--", text)
    assert code == dc.DRY_RUN_EXIT and text in out


def test_help_still_works(capsys):
    with pytest.raises(SystemExit) as e:
        dc.main(["send", "-h"])
    out = capsys.readouterr().out
    assert e.value.code == 0 and "--reply-to" in out and re.search(r"^ +-h, --help +show", out, re.M)
    assert "[HELP]" not in out


def test_the_dash_h_check_spares_long_options_and_text_after_dashes():
    fake = FakeDiscord(ids(3))
    assert run(fake, "search", "Test Server", "--has", "link")[0] == 0
    code, out, _ = run(fake, "send", GENERAL, "--", "-hey -h")
    assert code == dc.DRY_RUN_EXIT and "-hey -h" in out and not fake.sent


def test_options_may_sit_between_positionals():
    """C15: `edit LINK --yes TEXT` failed as "unrecognized arguments"."""
    mid = str(ids(1)[0])
    link = dc.message_link(GUILD, GENERAL, mid)
    fake = FakeDiscord(ids(1))
    assert run(fake, "edit", link, "--yes", "new text")[0] == 0
    assert run(fake, "react", GENERAL, "--yes", mid, "\N{THUMBS UP SIGN}")[0] == 0
    assert run(fake, "delete", GENERAL, "--yes", mid)[0] == 0
    assert run(fake, "react", link, "--remove", "\N{THUMBS UP SIGN}", "--yes")[0] == 0
    assert [c.method for c in fake.calls if c.method != "GET"] == ["PATCH", "PUT", "DELETE", "DELETE"]


# --------------------------------------------------------------------------- stdin (C5, C7)

class NeverEnds(io.StringIO):
    """An agent shell's stdin: not a terminal, and it never reaches EOF."""

    def read(self, *a):
        raise AssertionError("read stdin uninvited; this would hang forever")


@pytest.mark.parametrize("argv", [["send", GENERAL], ["dm", USER], ["edit", dc.message_link(GUILD, GENERAL, str(BASE_ID))]])
def test_missing_text_is_an_error_and_never_reads_stdin(argv):
    """C5."""
    out, err = io.StringIO(), io.StringIO()
    code = dc.main(argv, client_factory=lambda: dc.Client(TOKEN, transport=FakeDiscord(ids(1))),
                   stdin=NeverEnds(), stdout=out, stderr=err)
    assert code == 2 and "no text" in err.getvalue()


def test_dash_reads_stdin_strictly_as_utf8():
    """C7: invalid UTF-8 raised a UnicodeDecodeError traceback."""
    class BytesStdin:
        def __init__(self, raw):
            self.buffer = io.BytesIO(raw)

        def isatty(self):
            return False

    for raw, want in ((b"caf\xc3\xa9 ok", 3), (b"caf\xe9 au lait", 2)):
        out, err = io.StringIO(), io.StringIO()
        code = dc.main(["send", GENERAL, "-"], client_factory=lambda: dc.Client(TOKEN, transport=FakeDiscord()),
                       stdin=BytesStdin(raw), stdout=out, stderr=err)
        assert code == want, err.getvalue()
    assert "isn't valid UTF-8" in err.getvalue()


def test_a_lone_surrogate_in_the_text_is_refused():
    code, _, err = run(FakeDiscord(), "send", GENERAL, "bad \udce9 text")
    assert code == 2 and "UTF-8" in err


# --------------------------------------------------------------------------- double posts across runs (A6)

def test_rerunning_a_failed_long_send_repeats_nothing():
    """A6: chunk 1 posted, chunk 2 failed; the natural re-run used to post chunk 1 again."""
    text = "\n".join("y" * 150 for _ in range(30))  # 3 messages
    fake = FakeDiscord()
    real_create = fake.create
    fail = {"left": 1}

    def create(cid, call):
        if len(fake.sent) == 1 and fail["left"]:
            fail["left"] -= 1
            return {"__status": 403}
        return real_create(cid, call)

    def transport(method, url, headers, body):
        status, h, raw = fake(method, url, headers, body)
        if raw and b'"__status"' in raw:
            return 403, {}, b'{"message": "Missing Permissions", "code": 50013}'
        return status, h, raw

    fake.create = create
    code, out, err = run(transport, "send", GENERAL, text, "--yes")
    assert code == 1 and out.count("sent ") == 1
    assert "1 of 3 messages went out" in err and "reuses its nonces" in err

    def a_minute_passes():
        for msg in fake.nonces.values():
            msg["timestamp"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat()

    a_minute_passes()
    code, out, _ = run(transport, "send", GENERAL, text, "--yes")
    assert code == 0 and len(fake.sent) == 3, "the re-run posted only the two that were missing"
    assert out.count("already posted") == 1 and out.count("sent ") == 2
    a_minute_passes()
    code, out, _ = run(transport, "send", GENERAL, text, "--yes")
    assert code == 0 and len(fake.sent) == 3 and out.count("already posted") == 3


def test_again_posts_a_true_repeat():
    fake = FakeDiscord()
    run(fake, "send", GENERAL, "ok", "--yes")
    run(fake, "send", GENERAL, "ok", "--yes")
    assert len(fake.sent) == 1
    run(fake, "send", GENERAL, "ok", "--yes", "--again")
    assert len(fake.sent) == 2


def test_nonces_differ_by_channel_text_reply_and_files(tmp_path):
    f = tmp_path / "f.txt"
    f.write_text("1")
    base = dict(channel_id=GENERAL, text="hi", files=[], reply_to=None, mentions={"parse": []})
    seeds = {dc.send_seed(**base)}
    for change in ({"channel_id": RANDOM}, {"text": "hi!"}, {"files": [f]}, {"reply_to": USER},
                   {"mentions": {"parse": ["users"]}}):
        seeds.add(dc.send_seed(**{**base, **change}))
    assert len(seeds) == 6
    one = dc.message_payloads("x" * 4500, mentions={}, seed="s")
    assert len({b["nonce"] for b in one}) == len(one) == 3 and all(len(b["nonce"]) == 25 for b in one)
    assert [b["nonce"] for b in one] == [b["nonce"] for b in dc.message_payloads("x" * 4500, mentions={}, seed="s")]


# --------------------------------------------------------------------------- names, links, ids (C9-C11, C14, C21)

def test_a_near_miss_name_fails_instead_of_posting_somewhere_else():
    """C21: exact names only; duplicates across servers and categories never resolve silently."""
    for target, why in (("#general", "several channels"), ("Test Server/#gen", "no channel named"),
                        ("#gen", "no channel named"),
                        ("Test Server/#General-", "no channel named"), ("Test Srv/#general", "no server named"),
                        ("#general/Test Server", "server first")):
        fake = FakeDiscord(servers=2)
        code, _, err = run(fake, "send", target, "hi", "--yes")
        assert code == 2 and why in err, (target, err)
        assert not fake.sent and {c.method for c in fake.calls} <= {"GET"}
    fake = FakeDiscord()
    fake.channels.append({"id": "200000000000000031", "name": "general", "type": 0, "guild_id": GUILD})
    code, _, err = run(fake, "send", "Test Server/#general", "hi", "--yes")
    assert code == 2 and "several channels are named" in err and not fake.sent
    fake = FakeDiscord(servers=2)
    assert run(fake, "send", "test server/#GENERAL", "hi", "--yes")[0] == 0  # the category "general" is skipped
    assert [c.path for c in fake.calls if c.method == "POST"] == [f"/channels/{GENERAL}/messages"]


@pytest.mark.parametrize("link", [
    f"https://discord.com/channels/{GUILD}/{GENERAL}?utm_source=share",
    f"https://discord.com/channels/{GUILD}/{GENERAL}#frag",
    f"https://www.discord.com/channels/{GUILD}/{GENERAL}",
    f"HTTPS://DISCORD.COM/channels/{GUILD}/{GENERAL}",
    f"https://canary.discord.com/channels/{GUILD}/{GENERAL}/",
    f"<https://ptb.discordapp.com/channels/{GUILD}/{GENERAL}>",
])
def test_link_variants_parse(link):
    """C10."""
    assert dc.parse_target(link) == dc.Target(GENERAL, GUILD, None)


@pytest.mark.parametrize("bad", [
    "https://discord.com/invite/abc", f"https://discord.com/channels/{GUILD}",
    f"https://discord.com.evil.example/channels/{GUILD}/{GENERAL}", f"ftp://discord.com/channels/{GUILD}/{GENERAL}",
])
def test_a_broken_discord_link_gets_a_link_error_and_no_lookup(bad):
    if "evil" in bad:  # not a Discord host at all: a name, which then fails as one
        fake = FakeDiscord()
        assert run(fake, "read", bad)[0] == 2
        return
    fake = FakeDiscord()
    code, _, err = run(fake, "read", bad)
    assert code == 2 and "isn't a link to a Discord channel" in err and fake.calls == []


def test_fullwidth_digits_are_not_ids():
    """C11: \\d took them, and the HTTP request line then crashed."""
    wide = "２" * 18
    assert dc.parse_target(wide) is None
    with pytest.raises(dc.UsageError):
        dc.user_id(wide)
    with pytest.raises(dc.UsageError):
        dc.permissions_value("²")


@pytest.mark.parametrize("emoji,segment", [
    ("abc:123456789012345678", "abc:123456789012345678"),
    ("awesome:123456789012345678", "awesome:123456789012345678"),
    (":abc:123456789012345678", "abc:123456789012345678"),
    ("<:abc:123456789012345678>", "abc:123456789012345678"),
    ("<a:abc:123456789012345678>", "abc:123456789012345678"),
    ("<a:a:123456789012345678>", "a:123456789012345678"),
    ("\N{THUMBS UP SIGN}", "%F0%9F%91%8D"),
])
def test_custom_emoji_keep_their_whole_name(emoji, segment):
    """B5/C9: the pattern's optional "a" ate the first letter of a bare name."""
    assert dc.encode_emoji(emoji) == segment


def test_an_empty_emoji_is_refused():
    code, _, err = run(FakeDiscord(ids(1)), "react", dc.message_link(GUILD, GENERAL, str(ids(1)[0])), " ")
    assert code == 2 and "empty emoji" in err


def test_when_values_clamp_instead_of_crashing_or_overflowing():
    """C14."""
    now = 1_794_052_800_000
    assert dc.snowflake_ms(dc.parse_when("0001-01-01", now)) == dc.DISCORD_EPOCH_MS
    assert dc.snowflake_ms(dc.parse_when("3000-01-01", now)) == now + 86_400_000
    assert dc.parse_when("9999-12-31T23:59:59-05:00", now) < 1 << 63
    with pytest.raises(dc.UsageError):
        dc.parse_when("  ")
    fake = FakeDiscord(ids(3))
    code, _, err = run(fake, "read", GENERAL, "--before", "")
    assert code == 2 and "empty WHEN" in err and fake.calls == []


def test_dates_reach_the_api_as_cursors():
    """C23: --before/--after given as dates at the command line."""
    fake = FakeDiscord(ids(3))
    assert run(fake, "read", GENERAL, "--after", "2026-11-07T12:00:00Z")[0] == 0
    sent = int(fake.calls[-1].query["after"][0])
    assert dc.snowflake_ms(sent) == 1_794_052_800_000


# --------------------------------------------------------------------------- read, search, members (B1, B6-B9, C1, C12, C22)

def test_a_bad_grep_fails_before_any_api_call():
    """C1: it used to page the whole history first, then crash."""
    fake = FakeDiscord(ids(5))
    code, _, err = run(fake, "read", GENERAL, "--all", "--grep", "fix(")
    assert code == 2 and "--grep" in err and fake.calls == []


def test_grep_ignores_case():
    fake = FakeDiscord()
    fake.history[GENERAL] = [FakeDiscord.message(GENERAL, i, content=c) for i, c in zip(ids(2), ["Launch FRIDAY", "x"])]
    code, out, _ = run(fake, "read", GENERAL, "--grep", "friday")
    assert code == 0 and "Launch FRIDAY" in out and "\n    x" not in out


def test_forwarded_messages_show_their_text_and_files():
    """B6: a forward keeps its text in message_snapshots; read hid it and called the channel empty."""
    mid = ids(1)[0]
    forward = FakeDiscord.message(GENERAL, mid, content="")
    forward["message_reference"] = {"type": 1, "message_id": str(BASE_ID - 1)}
    forward["message_snapshots"] = [{"message": {"content": "the launch moved to Friday", "attachments": [
        {"filename": "plan.pdf", "size": 9, "url": "https://cdn.discordapp.com/a/9"}]}}]
    fake = FakeDiscord()
    fake.history[GENERAL] = [forward]
    code, out, err = run(fake, "read", GENERAL, "--grep", "friday")
    assert code == 0 and "> the launch moved to Friday" in out and "forwarded" in out and "plan.pdf" in out
    assert "intent is probably off" not in err


def test_around_refuses_flags_it_cannot_honor_and_pages_correctly():
    """B7/C22."""
    fake = FakeDiscord(ids(300))
    pivot = str(ids(300)[150])
    for extra in (["--before", pivot], ["--after", pivot], ["--all"], ["-n", "101"]):
        code, _, err = run(fake, "read", GENERAL, "--around", pivot, *extra)
        assert code == 2 and "--around" in err, extra
    assert fake.calls == []
    client = dc.Client(TOKEN, transport=fake, sleep=lambda s: None)
    got = [int(m["id"]) for m in dc.history(client, GENERAL, limit=10, around=int(pivot))]
    assert got == ids(300)[145:155]
    assert fake.calls[-1].query == {"around": [pivot], "limit": ["10"]}


def test_history_paging_makes_no_wasted_requests():
    """C22: a mutant that re-requested overlapping pages kept the results but sent 902 requests for 1000."""
    for kwargs, want in (({"limit": None}, 11), ({"limit": None, "after": 0}, 11), ({"limit": 250}, 3)):
        fake = FakeDiscord(ids(1000))
        client = dc.Client(TOKEN, transport=fake, sleep=lambda s: None)
        dc.history(client, GENERAL, **kwargs)
        assert len(fake.calls) <= want, (kwargs, len(fake.calls))


class ShortPages(FakeDiscord):
    """Discord may return fewer hits than the limit (resources/message: Search Guild Messages)."""

    def search(self, q):
        res = super().search(q)
        res["messages"] = res["messages"][:-1]
        return res


def test_search_pages_by_the_limit_asked_and_never_repeats_a_hit():
    """B1: paging by the length of the answer re-requested overlapping windows and duplicated hits."""
    fake = ShortPages(ids(60))
    code, out, err = run(fake, "search", GUILD, "message", "-n", "60", "--jsonl")
    hits = [json.loads(line)["id"] for line in out.splitlines()]
    assert code == 0 and len(hits) == len(set(hits))
    offsets = [c.query["offset"][0] for c in fake.calls if c.path.endswith("/messages/search")]
    assert offsets == ["0", "25", "50"]


def test_search_reports_cuts_on_stderr_in_json_mode_and_sends_documented_params():
    """B8/C22: arrays as repeated keys, include_nsfw on request, and a note even for --json."""
    fake = FakeDiscord(ids(40))
    code, out, err = run(fake, "search", GUILD, "message", "-n", "5", "--json", "--nsfw",
                         "--channel", GENERAL, "--channel", RANDOM, "--author", USER, "--has", "link", "--has", "file")
    assert code == 0 and len(json.loads(out)) == 5 and "5 shown of 40" in err
    q = next(c.query for c in fake.calls if c.path.endswith("/messages/search"))
    assert q["channel_id"] == [GENERAL, RANDOM] and q["author_id"] == [USER] and q["has"] == ["link", "file"]
    assert q["include_nsfw"] == ["true"] and q["limit"] == ["25"]  # always a full page, trimmed here


def test_search_never_passes_the_offset_cap():
    class Huge(FakeDiscord):
        def search(self, q):
            offset, limit = int(q["offset"][0]), int(q["limit"][0])
            return {"total_results": 12_000, "messages": [[FakeDiscord.message(GENERAL, BASE_ID + offset + i)]
                                                          for i in range(limit)]}

    fake = Huge()
    client = dc.Client(TOKEN, transport=fake, sleep=lambda s: None)
    hits, total = dc.search_messages(client, GUILD, content="x", limit=20_000)
    assert len(hits) == dc.SEARCH_MAX_HITS and total == 12_000
    assert max(int(c.query["offset"][0]) for c in fake.calls) == dc.SEARCH_MAX_OFFSET


@pytest.mark.parametrize("argv,why", [
    (["search", GUILD, "x", "-n", "0"], "-n must be at least 1"),
    (["search", GUILD, "x" * 1025], "1024 characters"),
    (["members", GUILD, "-n", "0"], "-n must be at least 1"),
    (["members", GUILD, "--query", "ma", "-n", "-3"], "-n must be at least 1"),
])
def test_out_of_range_values_fail_locally(argv, why):
    """B9/C14."""
    fake = FakeDiscord()
    code, _, err = run(fake, *argv)
    assert code == 2 and why in err and fake.calls == []


def test_members_pages_with_the_after_cursor():
    """C22: members without --query had no test and no fake route."""
    fake = FakeDiscord(members=2500)
    code, out, _ = run(fake, "members", GUILD, "-n", "2400", "--jsonl")
    got = [json.loads(line)["user"]["id"] for line in out.splitlines()]
    assert code == 0 and len(got) == len(set(got)) == 2400
    pages = [c.query for c in fake.calls if c.path == f"/guilds/{GUILD}/members"]
    assert [p["limit"][0] for p in pages] == ["1000", "1000", "400"]
    assert pages[1]["after"] == [str(int(USER) + 999)]


def test_form_errors_name_the_field():
    """C12: 50035 printed only "Invalid Form Body"."""
    fake = FakeDiscord()
    fake.script(400, {"code": 50035, "message": "Invalid Form Body", "errors": {"message_reference": {"_errors": [
        {"code": "MESSAGE_REFERENCE_UNKNOWN_MESSAGE", "message": "Unknown message"}]}}})
    code, _, err = run(fake, "whoami")
    assert code == 1 and "message_reference: Unknown message (MESSAGE_REFERENCE_UNKNOWN_MESSAGE)" in err


def test_error_hints_reach_the_user():
    """C23."""
    fake = FakeDiscord()
    fake.script(403, {"message": "Missing Access", "code": 50001})
    code, _, err = run(fake, "whoami")
    assert code == 1 and "hint: the bot can't see that channel" in err


# --------------------------------------------------------------------------- downloads (A3-A5, C8, C23)

def download_fake(names):
    mid = ids(1)[0]
    fake = FakeDiscord()
    fake.history[GENERAL] = [FakeDiscord.message(GENERAL, mid, attachments=[
        {"filename": n, "url": f"https://cdn.discordapp.com/a/{i}", "size": 4} for i, n in enumerate(names)])]
    return fake, dc.message_link(GUILD, GENERAL, str(mid))


def test_download_never_follows_a_planted_symlink(tmp_path, monkeypatch):
    """A3: a dangling link named like an attachment used to receive the file, wherever it pointed."""
    monkeypatch.setattr(dc, "fetch_url", lambda url, timeout=60.0: b"poster's bytes")
    outside = tmp_path / "home" / ".ssh" / "authorized_keys"
    outside.parent.mkdir(parents=True)
    dl = tmp_path / "dl"
    dl.mkdir()
    (dl / "authorized_keys").symlink_to(outside)
    fake, link = download_fake(["authorized_keys"])
    code, out, _ = run(fake, "download", link, "--dir", str(dl))
    assert code == 0 and not outside.exists()
    assert out.strip() == str(dl / "authorized_keys (2)")
    assert (dl / "authorized_keys").is_symlink()


def test_download_refuses_a_symlinked_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(dc, "fetch_url", lambda url, timeout=60.0: b"x")
    real = tmp_path / "elsewhere"
    real.mkdir()
    fake, link = download_fake(["a.txt"])
    monkeypatch.chdir(tmp_path)
    (tmp_path / f"discord-{ids(1)[0]}").symlink_to(real)  # the default folder name is predictable
    code, _, err = run(fake, "download", link)
    assert code == 2 and "symbolic link" in err and list(real.iterdir()) == []
    (tmp_path / "linked").symlink_to(real)
    assert run(fake, "download", link, "--dir", str(tmp_path / "linked"))[0] == 2


def test_download_never_overwrites_and_keeps_counting(tmp_path, monkeypatch):
    """C23: three same-named files, and leftovers from an earlier run, all survive."""
    monkeypatch.setattr(dc, "fetch_url", lambda url, timeout=60.0: url.encode())
    dl = tmp_path / "dl"
    dl.mkdir()
    (dl / "notes.txt").write_text("old")
    (dl / "notes (2).txt").write_text("older")
    fake, link = download_fake(["notes.txt"] * 3)
    code, _, _ = run(fake, "download", link, "--dir", str(dl))
    assert code == 0
    assert sorted(p.name for p in dl.iterdir()) == ["notes (2).txt", "notes (3).txt", "notes (4).txt",
                                                     "notes (5).txt", "notes.txt"]
    assert (dl / "notes.txt").read_text() == "old" and (dl / "notes (2).txt").read_text() == "older"


def test_hostile_names_are_short_dashless_and_one_failure_spares_the_rest(tmp_path, monkeypatch):
    """A4/C8: a 130-emoji name crashed download and skipped the files after it."""
    def fetch(url, timeout=60.0):
        if url.endswith("/1"):
            raise dc.DiscordError(404, "attachment download failed: Not Found")
        return b"ok"

    monkeypatch.setattr(dc, "fetch_url", fetch)
    long_name = "\N{GRINNING FACE}" * 130 + ".png"
    fake, link = download_fake([long_name, "gone.txt", "--yes", "日" * 200 + ".txt"])
    dl = tmp_path / "dl"
    code, out, err = run(fake, "download", link, "--dir", str(dl))
    assert code == 1 and "gone.txt" in err
    names = sorted(p.name for p in dl.iterdir())
    assert len(names) == 3 and "yes" in names
    assert all(len(n.encode()) <= dc.NAME_BYTES for n in names)
    assert sum(n.endswith(".png") for n in names) == 1 and sum(n.endswith(".txt") for n in names) == 1


def test_download_folder_problems_are_clear_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(dc, "fetch_url", lambda url, timeout=60.0: b"x")
    fake, link = download_fake(["a.txt"])
    blocker = tmp_path / "file"
    blocker.write_text("not a folder")
    code, _, err = run(fake, "download", link, "--dir", str(blocker))
    assert code == 2 and "isn't a folder" in err


def test_cdn_redirects_stay_on_the_cdn_over_https():
    """A5: the allowlist used to check only the first URL."""
    handler = dc._CdnRedirect()
    req = urllib.request.Request("https://cdn.discordapp.com/a/1")
    for bad in ("http://cdn.discordapp.com/a/2", "https://evil.example/a", "https://cdn.discordapp.com.evil.example/a"):
        with pytest.raises(dc.DiscordError):
            handler.redirect_request(req, None, 302, "Found", {}, bad)
    nxt = handler.redirect_request(req, None, 302, "Found", {}, "https://media.discordapp.net/a/2")
    assert nxt.full_url == "https://media.discordapp.net/a/2"
    assert not any(k.lower() == "authorization" for k, _ in nxt.header_items())


def test_forwarded_attachments_download_too(tmp_path, monkeypatch):
    monkeypatch.setattr(dc, "fetch_url", lambda url, timeout=60.0: b"pdf")
    mid = ids(1)[0]
    fwd = FakeDiscord.message(GENERAL, mid, content="")
    fwd["message_snapshots"] = [{"message": {"attachments": [{"filename": "plan.pdf",
                                                              "url": "https://cdn.discordapp.com/a/9"}]}}]
    fake = FakeDiscord()
    fake.history[GENERAL] = [fwd]
    code, _, _ = run(fake, "download", dc.message_link(GUILD, GENERAL, str(mid)), "--dir", str(tmp_path / "d"))
    assert code == 0 and (tmp_path / "d" / "plan.pdf").read_bytes() == b"pdf"


# --------------------------------------------------------------------------- --file (C8, C18, C23)

def test_file_problems_fail_the_dry_run_too(tmp_path):
    """C8: an unreadable file passed the dry run and crashed the --yes run after the DM opened."""
    locked = tmp_path / "locked.txt"
    locked.write_text("secret")
    locked.chmod(0)
    try:
        if os.access(locked, os.R_OK):
            pytest.skip("running as a user who can read anything")
        for argv in (["send", GENERAL, "hi", "--file", str(locked)], ["dm", USER, "hi", "--file", str(locked), "--yes"]):
            fake = FakeDiscord()
            code, _, err = run(fake, *argv)
            assert code == 2 and "can't read" in err and fake.calls == []
    finally:
        locked.chmod(stat.S_IRUSR | stat.S_IWUSR)
    code, _, err = run(FakeDiscord(), "send", GENERAL, "hi", "--file", str(tmp_path))
    assert code == 2 and "is a folder" in err
    code, _, err = run(FakeDiscord(), "send", GENERAL, "hi", "--file", str(tmp_path / "missing"))
    assert code == 2 and "no such file" in err
    many = []
    for i in range(11):
        (tmp_path / f"{i}.txt").write_text("x")
        many += ["--file", str(tmp_path / f"{i}.txt")]
    code, _, err = run(FakeDiscord(), "send", GENERAL, "hi", *many)
    assert code == 2 and "at most 10 files" in err


def test_upload_size_limits(tmp_path):
    """C18: Discord takes 25 MiB per message, and 20 MiB per file outside boosted servers."""
    big = tmp_path / "big.bin"
    with open(big, "wb") as fh:  # sparse: no real disk use
        fh.truncate(21 * 1024 * 1024)
    code, out, _ = run(FakeDiscord(), "send", GENERAL, "--file", str(big))
    assert code == dc.DRY_RUN_EXIT and "over Discord's default 20 MiB" in out
    huge = tmp_path / "huge.bin"
    with open(huge, "wb") as fh:
        fh.truncate(26 * 1024 * 1024)
    fake = FakeDiscord()
    code, _, err = run(fake, "send", GENERAL, "--file", str(huge), "--yes")
    assert code == 2 and "25 MiB per message" in err and fake.calls == []


def test_multipart_names_cannot_break_the_header(tmp_path):
    """C23."""
    odd = tmp_path / 'a"b\\c.txt'
    odd.write_text("x")
    body, ctype = dc.encode_multipart({"content": "hi"}, [odd])
    parts = parse_multipart(body, ctype)
    assert parts["files[0]"] == ("a_b_c.txt", b"x")


def test_edit_counts_utf16_units():
    """C23: 1001 emoji are 2002 UTF-16 units, over the limit though only 1001 code points."""
    code, _, err = run(FakeDiscord(ids(1)), "edit", GENERAL, str(ids(1)[0]), "\N{GRINNING FACE}" * 1001, "--yes")
    assert code == 2 and "must fit in one message" in err


def test_a_dm_answer_without_a_channel_id_is_an_error():
    """C16."""
    fake = FakeDiscord()
    fake.route_orig = fake.route
    fake.route = lambda call: (200, {}) if call.path == "/users/@me/channels" else fake.route_orig(call)
    code, _, err = run(fake, "dm", USER, "hi", "--yes")
    assert code == 1 and "no DM channel" in err and not fake.sent


# --------------------------------------------------------------------------- terminal output (A10/C17), Ctrl-C

def test_other_peoples_control_characters_never_reach_the_terminal():
    """A10/C17: escapes in content, names or file names could rewrite the screen or the clipboard."""
    evil = "hi\x1b[2K\r\x1b[1Afake: sent\x1b]52;c;ZXZpbA==\x07 ‮gnp.exe"
    m = FakeDiscord.message(GENERAL, ids(1)[0], content=evil,
                            attachments=[{"filename": "x\x1b[8m.txt", "size": 1, "url": "https://cdn.discordapp.com/a"}])
    m["author"] = {"id": USER, "username": "max", "global_name": "Max\x1b[8m"}
    fake = FakeDiscord()
    fake.history[GENERAL] = [m]
    fake.guilds[0]["name"] = "Test\x1b]0;title\x07 Server"
    for argv in (["read", GENERAL], ["guilds"], ["delete", dc.message_link(GUILD, GENERAL, str(ids(1)[0]))]):
        code, out, err = run(fake, *argv)
        assert not re.search("[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮]", out + err), argv
    code, out, _ = run(fake, "read", GENERAL)
    assert "\\x1b[2K" in out and "\\u202e" in out
    code, out, _ = run(fake, "read", GENERAL, "--json")
    assert json.loads(out)[0]["content"] == evil  # JSON keeps the data exact, controls included


@given(st.text())
def test_clean_leaves_no_control_characters(s):
    assert not re.search("[\x00-\x08\x0b-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]", dc.clean(s))


def test_ctrl_c_exits_130_quietly():
    def interrupted(*_):
        raise KeyboardInterrupt

    code, out, err = run(interrupted, "whoami")
    assert code == 130 and out == err == ""


@pytest.mark.parametrize("argv", [
    ["read", GENERAL, "--grep", "("], ["read", GENERAL, "--before", "0001-01-01"],
    ["send", GENERAL], ["react", dc.message_link(GUILD, GENERAL, str(BASE_ID)), ""],
    ["invite", "--permissions", "²"], ["read", "https://discord.com/channels/x/y"],
    ["download", dc.message_link(GUILD, GENERAL, str(BASE_ID)), "--dir", "/dev/null/x"],
])
def test_no_traceback_reaches_the_user(argv):
    """C1-C16: every odd input ends in one "discord:" line and an exit code."""
    fake = FakeDiscord([BASE_ID])
    fake.history[GENERAL][0]["attachments"] = [{"filename": "a", "url": "https://cdn.discordapp.com/a"}]
    code, out, err = run(fake, *argv)
    assert code in (0, 1, 2, 3) and "Traceback" not in out + err
    if code in (1, 2):
        assert err.startswith("discord: ")


# --------------------------------------------------------------------------- round-3 review fixes

def test_words_after_dashdash_are_never_options_on_any_python(tmp_path):
    """N5: parse_intermixed_args up to Python 3.12.5 read words after -- as options."""
    key = tmp_path / "id_ed25519"
    key.write_text("private key")
    fake = FakeDiscord()
    code, _, _ = run(fake, "send", "--yes", "--", GENERAL, f"--file={key}")
    assert code == 0 and fake.sent[0]["content"] == f"--file={key}" and "_files" not in fake.sent[0]
    chart = tmp_path / "chart.png"
    chart.write_bytes(b"png")
    fake = FakeDiscord()
    code, out, _ = run(fake, "send", "--file", str(chart), "--", GENERAL, "--yes")
    assert code == dc.DRY_RUN_EXIT and not fake.sent and "--yes" in out
    mid = str(ids(1)[0])
    fake = FakeDiscord(ids(1))
    code, _, _ = run(fake, "delete", "--", dc.message_link(GUILD, GENERAL, mid), "--yes")
    assert code == 2 and not any(c.method == "DELETE" for c in fake.calls)


def test_dashdash_keeps_dash_for_stdin_and_shows_real_words_in_errors(capsys):
    fake = FakeDiscord()
    code, _, _ = run(fake, "send", GENERAL, "--yes", "--", "-", stdin="from stdin")
    assert code == 0 and fake.sent[0]["content"] == "from stdin"
    with pytest.raises(SystemExit) as e:
        run(FakeDiscord(), "guilds", "--", "stray")
    err = capsys.readouterr().err
    assert e.value.code == 2 and "stray" in err and "\0" not in err


def test_an_option_cannot_take_its_value_from_after_dashdash(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        run(FakeDiscord(), "send", GENERAL, "--file", "--", str(tmp_path / "x"))
    assert e.value.code == 2 and "--file needs its value before --" in capsys.readouterr().err


def test_a_changed_file_is_a_new_send(tmp_path):
    """N1: the seed hashed name and size only, so a same-size edit came back "sent" and never posted."""
    f = tmp_path / "status.txt"
    base = dict(channel_id=GENERAL, text="", reply_to=None, mentions={"parse": []})
    f.write_text("OK")
    first = dc.send_seed(files=[f], **base)
    f.write_text("NO")
    assert dc.send_seed(files=[f], **base) != first
    fake = FakeDiscord()
    f.write_text("OK")
    run(fake, "send", GENERAL, "--file", str(f), "--yes")
    f.write_text("NO")
    run(fake, "send", GENERAL, "--file", str(f), "--yes")
    assert [b["_files"]["files[0]"][1] for b in fake.sent] == [b"OK", b"NO"]


def test_the_advice_after_a_failed_send_fits_again():
    """N2: with --again the nonces are fresh, so a re-run repeats everything."""
    text = "\n".join("y" * 150 for _ in range(30))  # 3 messages

    def transport_failing_second(fake):
        def transport(method, url, headers, body):
            if method == "POST" and len(fake.sent) == 1:
                return 403, {}, b'{"message": "Missing Permissions", "code": 50013}'
            return fake(method, url, headers, body)
        return transport

    fake = FakeDiscord()
    _, _, err = run(transport_failing_second(fake), "send", GENERAL, text, "--yes", "--again")
    assert "1 of 3 messages went out" in err and "posts every message again" in err and "reuses" not in err
    fake = FakeDiscord()
    _, _, err = run(transport_failing_second(fake), "send", GENERAL, text, "--yes")
    assert "reuses its nonces" in err and "posts every message again" not in err


def test_a_wrong_local_clock_cant_make_a_new_message_look_old():
    """N3: "already posted" compared Discord's timestamp with this machine's clock."""
    fake = FakeDiscord()
    fake.server_now = lambda: dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    code, out, _ = run(fake, "send", GENERAL, "fresh", "--yes")
    assert code == 0 and out.startswith("sent ") and "already" not in out
    code, out, _ = run(fake, "send", GENERAL, "fresh", "--yes")  # the same send again: Discord matched it
    assert code == 0 and len(fake.sent) == 1


def test_http_dates_parse_and_bad_ones_are_ignored():
    assert dc._http_date("Tue, 11 Nov 2026 04:00:00 GMT") == dt.datetime(2026, 11, 11, 4, tzinfo=dt.timezone.utc).timestamp()
    assert dc._http_date("not a date") is None and dc._http_date(None) is None


@pytest.mark.parametrize("bad", ["abc", "e", "a.b.c", "x" * 70, TOKEN.replace(".", ""), f"{TOKEN}.extra"])
def test_a_token_of_the_wrong_shape_is_refused(bad):
    """N4: a placeholder like "e" got through, then redaction ate every e in every error."""
    with pytest.raises(dc.UsageError) as e:
        dc.load_token({"DISCORD_BOT_TOKEN": bad}, run=None)
    assert "doesn't look like a bot token" in str(e.value)


def test_a_placeholder_token_leaves_errors_readable(monkeypatch):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "e")
    err = io.StringIO()
    assert dc.main(["whoami"], stdout=io.StringIO(), stderr=err) == 2
    assert "doesn't look like a bot token" in err.getvalue()
    assert dc.redact("request failed", ["a", "e"]) == "request failed"


def test_a_failed_write_leaves_no_partial_file(tmp_path, monkeypatch):
    """N6: a half-written report.pdf stayed behind and pushed the re-run to "report (2).pdf"."""
    real_fdopen = os.fdopen

    class DiskFull:
        def __init__(self, fh):
            self.fh = fh

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.fh.close()

        def write(self, data):
            self.fh.write(data[:100])
            raise OSError(28, "No space left on device")

    monkeypatch.setattr(dc.os, "fdopen", lambda fd, mode: DiskFull(real_fdopen(fd, mode)))
    with pytest.raises(OSError):
        dc.write_new_file(tmp_path, "report.pdf", b"x" * 1000)
    assert list(tmp_path.iterdir()) == []
    monkeypatch.undo()
    assert dc.write_new_file(tmp_path, "report.pdf", b"x").name == "report.pdf"


def test_names_in_lookup_errors_are_escaped():
    """N8: server and channel names reached stderr raw, escapes and bidi overrides included."""
    fake = FakeDiscord(servers=2)
    fake.guilds[1]["name"] = "Evil\x1b[31m‮Server"
    code, _, err = run(fake, "send", "#general", "hi", "--yes")
    assert code == 2 and "several channels" in err
    assert "\x1b" not in err and "‮" not in err and "\\x1b" in err and "\\u202e" in err
    assert dc.clean("؜") == "\\u061c"


class ShortTail(FakeDiscord):
    """Discord sends one hit fewer than asked, and an old, large total."""

    def search(self, q):
        res = super().search(q)
        res["messages"] = res["messages"][:-1]
        res["total_results"] = 12_000
        return res


def test_a_short_tail_ends_the_search_instead_of_thousands_of_requests():
    """N7/NEW-1: pages that shrank to the hits still missing, and no stop on a page that added
    nothing, made 9,952 requests."""
    fake = ShortTail(ids(40))
    code, out, _ = run(fake, "search", GUILD, "message", "-n", "50", "--jsonl")
    searches = [c for c in fake.calls if c.path.endswith("/messages/search")]
    assert code == 0 and len(out.splitlines()) == 38 and len(searches) == 3
    assert all(c.query["limit"] == ["25"] for c in searches)


def test_an_empty_page_ends_the_search_whatever_the_total():
    class Stale(FakeDiscord):
        def search(self, q):
            return {"total_results": 5000, "messages": []}

    fake = Stale()
    code, _, err = run(fake, "search", GUILD, "x")
    assert code == 0 and sum(c.path.endswith("/messages/search") for c in fake.calls) == 1
    assert "0 shown of 5000" in err


def test_a_low_total_cant_end_the_search_while_pages_come_back_full():
    """NEW-2: total_results lags while messages come and go."""
    class LowTotal(FakeDiscord):
        def search(self, q):
            return {**super().search(q), "total_results": 10}

    code, out, _ = run(LowTotal(ids(40)), "search", GUILD, "message", "-n", "40", "--jsonl")
    assert code == 0 and len(out.splitlines()) == 40


def test_the_10000_note_shows_when_short_pages_hit_the_cap():
    """NEW-4."""
    class Huge(FakeDiscord):
        def search(self, q):
            offset = int(q["offset"][0])
            return {"total_results": 12_000, "messages": [[FakeDiscord.message(GENERAL, BASE_ID + offset + i)]
                                                          for i in range(24)]}

    code, _, err = run(Huge(), "search", GUILD, "x", "-n", "20000", "--jsonl")
    assert code == 0 and "reaches only the first 10,000" in err


def test_a_202_that_asks_for_more_than_a_minute_fails_instead_of_retrying_early():
    """NEW-3: it slept 60 s and asked again before the time Discord gave."""
    fake = FakeDiscord()
    fake.script(202, {"code": 110000, "retry_after": 120})
    clock = Clock()
    code, _, err = run(fake, "search", GUILD, "x", clock=clock)
    assert code == 1 and "try again in 120s" in err and clock.slept == []


def test_forwards_stickers_and_system_messages_dont_suggest_a_missing_intent():
    """NEW-8: a channel of forwards or stickers warned that the content intent was off."""
    msgs = [{**FakeDiscord.message(GENERAL, i, content=""), **extra} for i, extra in zip(ids(4), [
        {"message_snapshots": [{"message": {"content": "", "embeds": [{"title": "t"}]}}]},
        {"sticker_items": [{"id": "1", "name": "wave", "format_type": 1}]},
        {"type": 7},  # a member joined
        {"poll": {"question": {"text": "?"}}},
    ])]
    fake = FakeDiscord()
    fake.history[GENERAL] = msgs
    _, _, err = run(fake, "read", GENERAL)
    assert "intent" not in err
    fake.history[GENERAL] = [{**FakeDiscord.message(GENERAL, i, content=""), "type": 7} for i in ids(3)]
    _, _, err = run(fake, "read", GENERAL)  # only join notices: nothing to learn about the intent
    assert "intent" not in err
    fake.history[GENERAL] = [FakeDiscord.message(GENERAL, i, content="") for i in ids(3)]
    _, _, err = run(fake, "read", GENERAL)
    assert "intent is probably off" in err


def test_retry_after_null_falls_back_to_the_header():
    assert dc._retry_after({"retry-after": "3"}, b'{"retry_after": null}') == 3.0


def test_the_post_budget_runs_from_a_try_that_may_have_posted_and_names_its_status():
    """Nits: a send that only met 429s can't have posted, so it may wait past 90 s; a give-up
    says what kept failing instead of "network"."""
    clock = Clock()
    answers = [(429, {}, b'{"retry_after": 50}')] * 3 + [(200, {}, b'{"id": "1"}')]
    client = dc.Client(TOKEN, transport=lambda *a: answers.pop(0), sleep=clock.sleep, clock=clock.now)
    body = dc.message_payloads("hi", mentions={"parse": []}, seed="s")[0]
    assert client.request("POST", f"/channels/{GENERAL}/messages", body=body, retry_unsafe=True) == {"id": "1"}
    assert sum(clock.slept) == 150
    clock = Clock()
    client = dc.Client(TOKEN, transport=lambda *a: (500, {}, b"{}"), sleep=clock.sleep, clock=clock.now,
                       max_retries=50)
    with pytest.raises(dc.DiscordError) as e:
        client.request("POST", f"/channels/{GENERAL}/messages", body=body, retry_unsafe=True)
    assert str(e.value).startswith("HTTP 500: gave up retrying") and "may have gone through" in str(e.value)


def test_the_search_text_limit_counts_utf16_units():
    code, _, err = run(FakeDiscord(), "search", GUILD, "\U0001F600" * 600)  # 600 code points, 1200 units
    assert code == 2 and "1024 characters" in err


def test_a_folder_swapped_for_a_link_mid_download_gets_nothing(tmp_path, monkeypatch):
    """NEW-2 (V1): the folder was checked once and each file then opened by path."""
    dl, outside = tmp_path / "dl", tmp_path / "victim" / ".ssh"
    outside.mkdir(parents=True)

    def swap_then_fetch(url, timeout=60.0):
        if not (tmp_path / "dl.real").exists():
            dl.rename(tmp_path / "dl.real")
            dl.symlink_to(outside)
        return b"ssh-ed25519 attacker"

    monkeypatch.setattr(dc, "fetch_url", swap_then_fetch)
    fake, link = download_fake(["authorized_keys"])
    code, _, _ = run(fake, "download", link, "--dir", str(dl))
    assert code == 0 and list(outside.iterdir()) == []
    assert (tmp_path / "dl.real" / "authorized_keys").read_bytes() == b"ssh-ed25519 attacker"


def test_a_folder_owned_by_someone_else_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(dc, "fetch_url", lambda url, timeout=60.0: b"x")
    monkeypatch.setattr(dc.os, "getuid", lambda: os.stat(tmp_path).st_uid + 1)
    fake, link = download_fake(["a.txt"])
    code, _, err = run(fake, "download", link, "--dir", str(tmp_path))
    assert code == 2 and "belongs to another user" in err and not (tmp_path / "a.txt").exists()


def test_an_upload_cut_off_mid_way_points_at_the_file_size(tmp_path):
    """C18 (V1): it read as a plain network failure."""
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * 1000)

    def transport(method, url, headers, body):
        if method == "POST":
            raise dc.TransportError("BrokenPipeError: [Errno 32] Broken pipe")
        return FakeDiscord()(method, url, headers, body)

    code, _, err = run(transport, "send", GENERAL, "--file", str(f), "--yes")
    assert code == 1 and "upload limit" in err and "may have gone through" in err


def test_the_error_code_stays_on_the_first_line():
    e = dc.DiscordError(403, "Missing Permissions\n  1 of 3 messages went out", code=50013)
    assert str(e).splitlines()[0] == "HTTP 403: Missing Permissions (code 50013)"


def test_an_agent_secret_that_wont_run_says_so():
    def not_executable(argv, **kw):
        raise PermissionError(13, "Permission denied", "agent-secret")

    with pytest.raises(dc.UsageError) as e:
        dc.load_token({}, run=not_executable)
    assert "couldn't run agent-secret" in str(e.value) and "Permission denied" in str(e.value)


def test_servers_page_past_200():
    """C22 (V1): nothing pinned the guild cursor."""
    fake = FakeDiscord()
    fake.guilds = [{"id": str(int(GUILD) + i), "name": f"server {i}"} for i in range(450)]
    code, out, _ = run(fake, "guilds", "--json")
    got = [g["id"] for g in json.loads(out)]
    assert code == 0 and len(got) == len(set(got)) == 450
    assert sum(c.path == "/users/@me/guilds" for c in fake.calls) == 3


def stalling_server(how):
    class Handler(Quiet):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Length", "500")
            self.end_headers()
            self.wfile.write(b'{"id": "1"')
            self.wfile.flush()
            if how == "stall":
                threading.Event().wait(2)  # past the client's 1 s timeout
            else:  # reset
                self.connection.setsockopt(__import__("socket").SOL_SOCKET, __import__("socket").SO_LINGER,
                                           __import__("struct").pack("ii", 1, 0))
            self.close_connection = True

    return serve(Handler)


@pytest.mark.parametrize("how", ["stall", "reset"])
def test_a_stalled_or_reset_body_is_no_answer(how, monkeypatch):
    """C23 (V1): a bare TimeoutError or ConnectionResetError from read() is A9's bug class."""
    server, base = stalling_server(how)
    monkeypatch.setattr(dc, "_API_OPENER", urllib.request.build_opener(urllib.request.ProxyHandler({}), dc._NoRedirect))
    try:
        with pytest.raises(dc.TransportError):
            dc.urllib_transport("POST", base + "/x", {"Content-Type": "application/json"}, b"{}", timeout=1)
    finally:
        stop(server)


def test_dm_with_a_file_sends_the_file(tmp_path):
    """C23 (V1): nothing sent a dm with --file --yes."""
    f = tmp_path / "note.txt"
    f.write_text("hello")
    fake = FakeDiscord()
    code, _, _ = run(fake, "dm", USER, "see attached", "--file", str(f), "--yes")
    posts = [c for c in fake.calls if c.method == "POST" and c.path == f"/channels/{DM_CHANNEL}/messages"]
    assert code == 0 and len(posts) == 1 and fake.sent[0]["_files"]["files[0]"] == ("note.txt", b"hello")


def test_the_edit_dry_run_shows_both_texts():
    mid = str(ids(1)[0])
    code, out, _ = run(FakeDiscord(ids(1)), "edit", dc.message_link(GUILD, GENERAL, mid), "new words")
    assert code == dc.DRY_RUN_EXIT and f"now:  message {mid}" in out and "new:  new words" in out


def test_threads_show_under_their_channel():
    fake = FakeDiscord()
    fake.threads = [{"id": "300000000000000001", "name": "a thread", "type": 11, "parent_id": GENERAL,
                     "guild_id": GUILD}]
    code, out, _ = run(fake, "channels", "Test Server", "--threads")
    lines = out.splitlines()
    general = next(i for i, line in enumerate(lines) if "#general" in line)
    assert code == 0 and "#a thread" in lines[general + 1] and lines[general + 1].index("#a") > lines[general].index("#g")


@pytest.mark.parametrize("error", [
    __import__("http.client").client.IncompleteRead(b"par", 10),
    ConnectionResetError(54, "Connection reset by peer"),
])
def test_a_failed_attachment_fetch_skips_only_that_file(tmp_path, monkeypatch, error):
    """C23 (V1): an IncompleteRead from the CDN reached the catch-all and stopped the rest."""
    def opener(req, timeout=60.0):
        if getattr(req, "full_url", req).endswith("/0"):
            raise error
        return io.BytesIO(b"fine")

    monkeypatch.setattr(dc._CDN_OPENER, "open", opener)
    fake, link = download_fake(["bad.bin", "good.bin"])
    code, out, err = run(fake, "download", link, "--dir", str(tmp_path / "dl"))
    assert code == 1 and "bad.bin" in err and (tmp_path / "dl" / "good.bin").read_bytes() == b"fine"


def test_dash_at_a_terminal_is_refused_instead_of_waiting():
    class Terminal(NeverEnds):  # reading it would wait for someone to type
        def isatty(self):
            return True

    out, err = io.StringIO(), io.StringIO()
    code = dc.main(["send", GENERAL, "-"], client_factory=lambda: dc.Client(TOKEN, transport=FakeDiscord()),
                   stdin=Terminal(), stdout=out, stderr=err)
    assert code == 2 and "stdin is a terminal" in err.getvalue()


# --------------------------------------------------------------------------- round-4 review fixes

def test_dashdash_before_the_command_is_refused(tmp_path, capsys):
    """NEW-F2: `discord -- send ...` skipped the command's own parsing, so on Python 3.12.7+
    `discord -- send C hi --yes` posted and `--file=KEY` uploaded the key."""
    key = tmp_path / "id_ed25519"
    key.write_text("private key")
    for argv in (["--", "send", "--yes", GENERAL, f"--file={key}"], ["--", "send", GENERAL, "hi", "--yes"],
                 ["--version", "--", "send", GENERAL, "hi", "--yes"], ["--"]):
        fake = FakeDiscord()
        with pytest.raises(SystemExit) as e:
            run(fake, *argv)
        assert e.value.code == 2 and not fake.calls, argv
        assert "-- goes after the command" in capsys.readouterr().err


@pytest.mark.parametrize("argv, option", [
    (["read", GENERAL, "-n", "--", "5"], "-n"),
    (["search", GUILD, "x", "--sort", "--", "relevance"], "--sort"),
    (["send", GENERAL, "--file", "--", "x"], "--file"),
])
def test_an_option_whose_value_follows_dashdash_is_named(argv, option, capsys):
    """NEW-F4: argparse quoted the placeholder standing in for the word after --."""
    with pytest.raises(SystemExit) as e:
        run(FakeDiscord(), *argv)
    err = capsys.readouterr().err
    assert e.value.code == 2 and f"{option} needs its value before --" in err
    assert "\\x00" not in err and "\0" not in err


def test_errors_show_the_real_word_where_argparse_quotes_it(capsys):
    toy = argparse.ArgumentParser(prog="toy")
    toy.add_argument("count", type=int)
    with pytest.raises(SystemExit):
        dc._parse_command(toy, "toy", ["--", "five"])
    err = capsys.readouterr().err
    assert "invalid int value: 'five'" in err and "\\x00" not in err


@pytest.mark.parametrize("word, cut", [
    ("\u0915\u094d\u0937", 2),          # Devanagari KA VIRAMA SSA
    ("\u0915\u094d\u0951\u0915", 3),    # a stress mark between the virama and the consonant
    ("\u0915\u094d\u0301\u0915", 3),    # an acute accent there
    ("\u0915\u094d\u200d\u0915", 3),    # a zero-width joiner there
    ("\u1780\u17d2\u1780", 2),          # Khmer KA COENG KA
    ("\u1000\u1039\u1000", 2),          # Myanmar KA, the invisible stacker, KA
    ("\u1a20\u1a60\u1a20", 2),          # Tai Tham HIGH KA SAKOT HIGH KA
    ("\u1b13\u1b44\u1b13", 2),          # Balinese KA ADEG ADEG KA
    ("\ua98f\ua9c0\ua98f", 2),          # Javanese KA PANGKON KA
    ("\U000113D1\u0915", 1),            # a Unicode 16 Prepend joins what follows
])
def test_cuts_never_strand_half_a_conjunct(word, cut):
    """NEW-F3: a cut after Khmer COENG or Myanmar's stacker, or after a virama with a mark
    behind it, left the consonant that belongs under the one before at the top of the
    next message. Pinned here because the newest regex module doesn't apply GB9c at all."""
    assert not dc.safe_cut(word, cut)
    assert dc.safe_cut(word + word, len(word))  # between two conjuncts is fine


@pytest.mark.parametrize("unit", ["\u1780\u17d2\u179f", "\u1000\u1039\u1000", "\u0915\u094d\u0951\u0915"])
def test_long_unspaced_text_breaks_between_conjuncts(unit):
    for shift in range(len(unit)):
        text = "x" * shift + unit * 1000
        pieces = dc.chunk_text(text)
        assert len(pieces) >= 2 and "".join(pieces) == text
        at = 0
        for piece in pieces[:-1]:
            at += len(piece)
            assert (at - shift) % len(unit) == 0, (shift, at)


def test_a_folder_swapped_for_a_link_before_it_opens_is_refused(tmp_path, monkeypatch):
    """O_NOFOLLOW pin (round 4): the folder is made, then swapped for a link to someone's
    ~/.ssh before open_folder runs. Following the link would pass the owner check."""
    dl, victim = tmp_path / "dl", tmp_path / "victim" / ".ssh"
    victim.mkdir(parents=True)
    real_mkdir = Path.mkdir

    def mkdir_then_swap(self, *a, **k):
        real_mkdir(self, *a, **k)
        if self == dl:
            dl.rename(tmp_path / "dl.real")
            dl.symlink_to(victim)

    monkeypatch.setattr(Path, "mkdir", mkdir_then_swap)
    monkeypatch.setattr(dc, "fetch_url", lambda url, timeout=60.0: b"ssh-ed25519 attacker")
    fake, link = download_fake(["authorized_keys"])
    code, _, err = run(fake, "download", link, "--dir", str(dl))
    assert code == 2 and "can't use" in err and list(victim.iterdir()) == []
    with pytest.raises(OSError):
        dc.open_folder(dl)


def test_a_channel_of_forwards_alone_doesnt_suggest_a_missing_intent():
    """NEW-8 pin: one forward-only channel, so dropping the snapshot clause fails."""
    fake = FakeDiscord()
    fake.history[GENERAL] = [
        {**FakeDiscord.message(GENERAL, i, content=""),
         "message_snapshots": [{"message": {"content": "", "embeds": [{"title": "t"}, {"title": "u"}]}}]}
        for i in ids(3)]
    code, out, err = run(fake, "read", GENERAL)
    assert code == 0 and "intent" not in err
    assert out.count("forwarded") == 3 and out.count("2 embed(s)") == 3  # a forward's embeds count too


def test_the_upload_limit_counts_the_whole_request(tmp_path):
    """C18 residue: files of exactly 25 MiB passed, though the request around them is larger."""
    exact = tmp_path / "exact.bin"
    with open(exact, "wb") as fh:  # sparse: no real disk use
        fh.truncate(dc.REQUEST_LIMIT)
    fake = FakeDiscord()
    code, _, err = run(fake, "send", GENERAL, "--file", str(exact))
    assert code == 2 and "25 MiB per message" in err and not fake.sent
    small = tmp_path / "small.bin"
    with open(small, "wb") as fh:
        fh.truncate(dc.REQUEST_LIMIT - 64 * 1024)
    code, out, _ = run(FakeDiscord(), "send", GENERAL, "--file", str(small))
    assert code == dc.DRY_RUN_EXIT and "small.bin" in out


# Quotes, backslashes and line breaks (which the form escapes) and multi-byte characters, but
# only ones every file system takes: APFS refuses code points its Unicode tables don't know.
FILE_NAMES = st.text(st.sampled_from(list('aZ09 ._-"\\\r\n') + ["\u00e9", "\u65e5", "\U0001F600", "\u0301"]),
                     min_size=1, max_size=20).filter(lambda n: n not in (".", ".."))


@settings(max_examples=60, deadline=None)
@given(text=st.text(max_size=300), names=st.lists(FILE_NAMES, min_size=0, max_size=3, unique_by=str.lower),
       sizes=st.lists(st.integers(0, 4000), min_size=3, max_size=3))
def test_multipart_size_matches_the_encoded_body(tmp_path_factory, text, names, sizes):
    """Differential: the size check and the upload build the same body."""
    folder = tmp_path_factory.mktemp("multipart")
    files = []
    for name, size in zip(names, sizes):
        f = folder / name
        f.write_bytes(b"x" * size)
        files.append(f)
    payload = dc.message_payloads(text or "", mentions={"parse": []}, seed="s")[0]
    assert dc.multipart_size(payload, files) == len(dc.encode_multipart(payload, files)[0])


def test_a_refused_token_isnt_redacted_out_of_the_advice(monkeypatch):
    """N4 residue: DISCORD_BOT_TOKEN=agent-secret turned the advice into "<token> set ..."."""
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "agent-secret")
    err = io.StringIO()
    assert dc.main(["whoami"], stdout=io.StringIO(), stderr=err) == 2
    assert "agent-secret set agent/discord-bot-token" in err.getvalue() and "<token>" not in err.getvalue()
