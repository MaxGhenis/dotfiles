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
- downloads stay inside the target folder.
"""
from __future__ import annotations

import email
import email.policy
import http.server
import importlib.machinery
import importlib.util
import io
import json
import os
import random
import re
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
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
    loader.exec_module(module)
    return module


dc = _load()

TOKEN = "SENTINEL-bot-token.must.never.leak-0123456789abcdef"
GUILD = "100000000000000001"
CATEGORY_ID = "200000000000000009"
GENERAL = "200000000000000001"
RANDOM = "200000000000000002"
DM_CHANNEL = "200000000000000099"
APP = "300000000000000001"
USER = "400000000000000001"
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

    def __init__(self, ids=(), order="newest-first", flags=0, guild_count=1, seed=0):
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
        self.history = {GENERAL: [self.message(GENERAL, i) for i in sorted(ids)], RANDOM: []}
        self.sent: list[dict] = []
        self.nonces: dict[str, dict] = {}
        self.next_id = BASE_ID + 10**15

    @staticmethod
    def message(channel, mid, content=None, attachments=()):
        return {"id": str(mid), "channel_id": channel, "type": 0,
                "content": f"message {mid}" if content is None else content,
                "author": {"id": USER, "username": "max"}, "attachments": list(attachments), "embeds": []}

    def script(self, status, body=None, headers=None):
        self.scripted.append((status, headers or {}, body))

    def __call__(self, method, url, headers, body):
        assert url.startswith(dc.API + "/"), url
        parts = urllib.parse.urlsplit(url)
        call = Call(method, parts.path[len("/api/v10"):], urllib.parse.parse_qs(parts.query), dict(headers), body)
        self.calls.append(call)
        if self.scripted:
            status, rheaders, payload = self.scripted.pop(0)
            raw = payload if isinstance(payload, bytes) else b"" if payload is None else json.dumps(payload).encode()
            return status, rheaders, raw
        status, payload = self.route(call)
        return status, {}, b"" if payload is None else json.dumps(payload).encode()

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
            return 200, self.guilds
        if (m, p) == ("POST", "/users/@me/channels"):
            return 200, {"id": DM_CHANNEL, "type": 1, "recipients": [{"id": USER, "username": "max"}]}
        if (m, p) == ("GET", f"/users/{USER}"):
            return 200, {"id": USER, "username": "max"}
        if (m, p) == ("GET", f"/guilds/{GUILD}/channels"):
            return 200, self.channels
        if (m, p) == ("GET", f"/guilds/{GUILD}/threads/active"):
            return 200, {"threads": [], "members": []}
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
        msg = {"id": str(self.next_id), "channel_id": cid, "content": body.get("content", "")}
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


@settings(max_examples=300, deadline=None)
@given(text=TEXT, limit=st.integers(2, 120))
def test_chunks_fit_are_never_blank_and_lose_nothing(text, limit):
    pieces = dc.chunk_text(text, limit)
    assert all(dc.u16len(p) <= limit for p in pieces)
    assert all(p.strip() for p in pieces)
    squash = lambda s: "".join(s.split())  # noqa: E731
    assert squash("".join(pieces)) == squash(text)


@given(text=TEXT.filter(str.strip))
def test_text_that_fits_stays_one_piece(text):
    if dc.u16len(text) <= dc.CONTENT_LIMIT:
        assert dc.chunk_text(text) == [text]


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

    monkeypatch.setattr(dc.urllib.request, "urlopen", fake_urlopen)
    assert dc.fetch_url("https://cdn.discordapp.com/attachments/1/2/a.png?ex=1&hm=2") == b"data"
    assert not any(k.lower() == "authorization" for k in captured["headers"])
    for bad in ("http://cdn.discordapp.com/a.png", "https://evil.example/a.png", "file:///etc/passwd"):
        with pytest.raises(dc.DiscordError):
            dc.fetch_url(bad)


# --------------------------------------------------------------------------- downloads

@given(st.text(max_size=120))
def test_safe_filenames_cannot_leave_the_folder(name):
    out = dc.safe_filename(name, "fallback")
    assert out and "/" not in out and "\\" not in out and not out.startswith(".")
    assert len(out) <= 200


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

    assert dc.load_token({"DISCORD_BOT_TOKEN": "Bot abc"}, run=None) == "abc"
    calls = []
    assert dc.load_token({}, run=lambda argv, **kw: calls.append(argv) or Got(0, "xyz\n")) == "xyz"
    assert calls == [["agent-secret", "get", "agent/discord-bot-token"]]
    with pytest.raises(dc.UsageError) as e:
        dc.load_token({}, run=lambda argv, **kw: Got(1, ""))
    assert "agent-secret set agent/discord-bot-token" in str(e.value)


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
