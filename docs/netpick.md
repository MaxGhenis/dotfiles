# netpick

[`netpick`](../bin/netpick) tells me which network my Mac should use right now, for a workload of about 30 Claude Code sessions, other coding agents and git. It measures the Mac's live links together, such as Wi-Fi and a USB-tethered phone, and sends every probe through one link's interface. Then it ranks the links, recommends one and appends the results to a history file. It never changes networks: I switch in the Wi-Fi menu or by plugging in the phone.

## Quick start

```bash
netpick                      # measure every live link and recommend one
netpick --quick              # pings, DNS and connections only, well under 1 MB per link
netpick watch --baseline     # measure this Wi-Fi network, then each one I switch to
netpick history --rank       # rank each network's latest measurement
netpick name 0579294e "Pixel hotspot"
```

netpick runs as a uv script on Python 3.11's standard library. Measuring needs macOS; `history`, `import` and `name` run anywhere.

On my phone's hotspot, `netpick --quick` printed:

```
#  network                                                  id        conns  loss  rtt ms  up/down Mbps  via  rpm  MB
1  Wi-Fi WPA3 gw 10.243.10.226 · AS6167 Verizon Business *  0579294e    8/8  0.0%   72±19           —/—  —      —   —

Stay on Wi-Fi WPA3 gw 10.243.10.226 · AS6167 Verizon Business (netpick measured no other link).
  en0: DNS 10.243.10.226 answered 4/4, median 11 ms, max 20 ms

netpick measured 1 link, used under 1 MB and ran for 15 s; history: ~/.local/state/netpick/history.jsonl
```

Each row shows the HTTPS connections that completed, ping loss, round-trip time (mean ± standard deviation), and upload and download in Mbps. Under `via`, `nq` marks rates from networkQuality and `1-conn` rates from the bounded transfer. `rpm` gives networkQuality's responsiveness in round trips per minute, and `MB` the bulk data netpick counted for the transfer and networkQuality. An asterisk marks the link that carries traffic now, and progress lines go to stderr.

## What it measures

netpick measures in phases. Every link runs each phase at the same moment, so all links ping, then all resolve and connect, then all transfer. On a moving train, tests minutes apart gave the opposite picture from simultaneous ones.

| Phase | What runs on each link | What netpick records |
|---|---|---|
| Ping | `ping -b <if> -c 40 -i 0.25 1.1.1.1` | loss, and the mean and standard deviation of the round trip |
| DNS | two A queries for each host to the link's own DNS server, from a socket that netpick binds to the interface | answers and their times |
| Connections | `curl -I --interface <if> --resolve <host>:443:<ip>`, four times each to api.anthropic.com and github.com | the share that completed, and TLS handshake times |
| Bounded transfer | `curl --interface <if>`: 5 MB down from speed.cloudflare.com and 2.5 MB up, with an 8 s limit on each | one-connection rates |
| networkQuality | `networkQuality -I <if> -M <seconds> -c`, with a length that fits the data budget | upload, download and responsiveness |

The connection probes pin each host's address with `--resolve`, which keeps DNS out of their timing, and netpick times each network's resolver separately in the DNS phase. It takes the pinned addresses from the primary network's DNS when that DNS returns a public address, and from fixed addresses otherwise, since a captive portal's DNS can answer with a private one.

Before probing, netpick reads each link's address, gateway and security type, fetches `captive.apple.com` through the link and looks up the egress network's owner at ipinfo.io. A link that fails the captive check gets no further probes and ranks last.

## How it ranks

netpick ranks links on five measures, in this order:

1. Connections completed. On November 4 a USB-tethered phone pinged clean (0% loss, about 37 ms) but failed about half of its new TCP connections, and networkQuality failed on it three times out of three. The train's Wi-Fi lost 10 to 28% of its pings at about 330 ms, completed 10 of 10 handshakes and won.
2. Ping loss.
3. Latency. netpick adds one standard deviation to the mean round trip, so spikes count against a link.
4. Upload.
5. Download.

Each measure counts first in coarse bands, so noise inside one test can't outvote a real difference further down the list. Exact values then break ties in the same order, networkQuality's responsiveness breaks any tie left, and a missing measure ranks worst.

| Measure | Band 0 | Band 1 | Band 2 | Band 3 | Band 4 |
|---|---|---|---|---|---|
| Connections completed | all | 85% or more | 60% or more | under 60% | |
| Ping loss | 2.5% or less | 7.5% or less | 15% or less | over 15% | |
| Latency (mean + 1 sd) | 100 ms or less | 250 ms or less | 500 ms or less | over 500 ms | |
| Upload or download | 20 Mbps or more | 8 or more | 3 or more | 1 or more | under 1 |

With 40 pings, one lost ping counts as 2.5%, so the best loss band allows one.

netpick tells me to leave a link with no internet for the best link that has it. When the current link reaches the internet too, netpick says to switch only if the best link beats it at band level. Inside a band it says to stay, so one test's noise never moves 30 sessions. When it does recommend a switch, it says how: pick the network in the Wi-Fi menu, unplug the phone to fall back to Wi-Fi, or turn Wi-Fi off to move traffic to a tethered phone. On my Mac the tether's service sits above Wi-Fi in System Settings > Network, so plugging in the phone moves all traffic to it.

Three field tests back the top of the order, and `tests/test_netpick.py` replays each one:

| Date | Links | Winner | Deciding measure |
|---|---|---|---|
| November 4, on a train | USB-tethered phone, train Wi-Fi | train Wi-Fi | connections: 10 of 10 against about half |
| November 5, on a train | phone hotspot over Wi-Fi, train Wi-Fi | hotspot | connections: 8 of 8 against 5 of 8 |
| November 5, at a conference | venue Wi-Fi, phone hotspot, a café's open Wi-Fi | venue, then hotspot, then café | latency: about 51, 226 and 286 ms |

netpick adds one standard deviation to each mean there: the café's pings averaged 132 ms against the hotspot's 152 ms but spiked to 679 ms.

## Data budget

netpick gives each link a data budget for the run, 100 MB by default (`--budget-mb`), and the bounded transfer and networkQuality both draw on it. With `--rounds`, every round draws on the same budget. netpick runs the 7.5 MB transfer when it fits in what's left and skips it otherwise.

networkQuality moves as much as a link can carry for as long as it runs. On the conference Wi-Fi, a 6-second run moved 130 MB (24 MB down and 106 MB up), so a time limit alone doesn't cap its data. netpick plans each run from the bounded transfer instead. It assumes networkQuality moves twice the transfer's one-connection rate and picks the longest run, up to 20 s, that fits the rest of the budget. When that run would last under 5 s, netpick skips networkQuality and ranks on the transfer's rates; at 100 Mbps up and down combined, the plan comes to under 4 s. With no transfer rates to plan from, netpick runs networkQuality for at most 8 s, and only when 20 MB or more of the budget remains.

While networkQuality runs, netpick reads the interface's byte counters every half second and stops the run once the link has moved the rest of the budget. It reads them from the kernel through one `sysctl` call. The counters include the sessions' own traffic, so the stop can come early but never later than one half-second check. When netpick can't read the counters, it skips networkQuality, and it stops a run at a read that fails or runs backward. networkQuality prints nothing when netpick stops it, so netpick ranks that link on the transfer's rates. Given an interface that doesn't exist, networkQuality ignored its time limit and hung for over two minutes; netpick stops it 15 s after its planned end.

netpick charges each networkQuality run the larger of two counts: networkQuality's own and the interface counters'. When curl prints no byte count for a direction of the transfer, netpick charges that direction's full size, 5 MB down or 2.5 MB up. When a counter read during or right after networkQuality fails or runs backward, netpick charges the rest of the budget, so that link runs no more transfers or networkQuality in the run. netpick notes both kinds of charge in the history and leaves the bytes it couldn't count out of the `MB` column.

With `--quick`, netpick runs only the ping, DNS and connection phases, which use well under 1 MB per link. With `--no-nq` it skips networkQuality, and with `--no-transfer` it skips the bounded transfer.

## Watching Wi-Fi switches

A Mac's Wi-Fi joins one network at a time, so netpick can't measure two Wi-Fi networks together. `netpick watch` measures them in turn while I switch. It checks the Wi-Fi gateway every 2 s, and when a new one appears, it waits up to 8 minutes for the captive check to pass while I sign in to any portal. Then it lets DNS settle for 30 s, measures, and prints the table so far. On November 5, right after a switch, 2 of 4 API calls failed their DNS lookup, and a minute later 35 of 35 succeeded.

When I switch back to a network that `watch` has measured and found online, it waits up to a minute for internet and checks 4 Claude API and 4 GitHub connections instead of measuring again. `watch` treats the gateways I list with `--seen` the same way; I separate their addresses with commas. If I leave a network, or its Wi-Fi drops, before `watch` measures it, `watch` measures it in full when the network comes back. It stops after 3 new networks or 30 minutes (`--max`, `--minutes`). At the time limit it cuts every wait and every command outside a measurement or connection check, and it starts no settle that would end after the limit. A measurement or connection check that starts before the limit runs to its end, so a watch can end late by one of them. With `--baseline`, `watch` measures the current network first, whatever I pass to `--seen` and `--max`, and when that network has no internet yet, it waits for that network as it would for a new one. It keeps waiting through a drop and skips the baseline once it finds another network in any of its gateway reads. `watch` takes its measurements minutes apart, so on a train the rows compare moments as well as networks, and netpick prints that warning under the table.

## Labels and ids

macOS 26 redacts Wi-Fi network names (SSIDs) from command-line tools. netpick labels a Wi-Fi network instead by its security type, its gateway and the owner of the egress network, as in `Wi-Fi WPA2 gw 172.21.112.1 · AS6079 RCN`. A tethered phone or Ethernet adapter takes the name of its hardware port. netpick hashes the gateway and security type (for Wi-Fi) or the port name into an 8-character id, so a network keeps its id from visit to visit. `netpick name <id> <name>` shows a name in place of the label, `netpick name <id> --clear` removes it, and `netpick name --list` lists the names.

## History

netpick appends each measurement as one JSON line to `~/.local/state/netpick/history.jsonl`, or to the path I give in `$NETPICK_HISTORY` or `--history PATH`. Each line holds the time, interface, label, egress, every probe's results and the ranking inputs. `netpick history` shows the latest 30 rows; with `--rank` it ranks each network's latest measurement, and with `--by-network` it gives each network's medians. I narrow any of them with `--since 2h` and `--network <id or text>`. When a line doesn't parse, or a field the views read holds the wrong type, `netpick history` skips it and gives the count. `netpick import` loads test captures in the format of `tests/fixtures/netpick/nettest_*.txt` and names any damaged capture it skips. netpick keeps names in `names.json` beside the history. It refuses a `--history` path that names `names.json`, directly or through symbolic links, and one that shares a file with the `names.json` beside it. When `names.json` doesn't parse or isn't a regular file, `netpick name` leaves it as it is and says so.

```
$ netpick history --rank
#  network                                                id        conns  loss   rtt ms  up/down Mbps  via  rpm  MB  measured
1  Wi-Fi WPA2 gw 172.21.112.1                             34849952    8/8  0.0%    30±22        114/13  nq    47   —  6h ago
2  Wi-Fi WPA3 gw 10.243.10.226 · AS6167 Verizon Business  0579294e    8/8  0.0%    72±19           —/—  —      —   —  15s ago
3  Wi-Fi OPEN gw 172.16.224.1                             8e4c49c7    8/8  0.0%  132±154        15/4.5  nq    34   —  6h ago
netpick took these latest measurements at different times; recheck before acting on old rows.
```

A plain `netpick` run also lists the networks it measured in the last 2 hours that it can't reach now (I set the window with `--recent` and remove it with `--recent all`), and says when one of them beat the current pick.

## Read-only

netpick runs eight macOS tools by absolute path, and an allowlist refuses any other command, any probe that names no `en` interface and any `osascript` beyond its read-only CoreWLAN script. It reads byte counters with one `sysctl` call that sets no value. It never joins or leaves a Wi-Fi network, changes the service order or any other setting, or reads the keychain, and it stops only its own child processes. On November 4, a command-line join of a WPA3 phone hotspot (`networksetup -setairportnetwork`) failed with error -3900 and left the Mac and every session on it offline for about 90 seconds.

## Tests

```bash
uv run --no-project --with pytest --with hypothesis pytest tests/test_netpick.py tests/test_netpick_probing.py -q
NETPICK_HYPOTHESIS=thorough uv run --no-project --with pytest --with hypothesis pytest tests/test_netpick.py tests/test_netpick_probing.py -q
```

- Parser tests read the three captures from November 5 and command output from this Mac, with placeholder MAC addresses in place of the real ones. On macOS, a differential test checks netpick's byte counters against `netstat -ib`.
- Hypothesis tests the ranking on generated inputs. The same records always give the same order, input order matters only between exact ties, and improving one measure never lowers a network's rank. The connections band outranks every later measure, and values such as NaN or text rank as missing. When the current link reaches the internet, netpick never recommends a switch inside a band. A separate test checks each band's cut point and the floating-point values on either side of it.
- Hypothesis also checks that the networkQuality plan fits the budget at generated speeds, and that pooling rounds of ping summaries matches a computation over every sample.
- A fake Mac answers each command from a script after netpick's own allowlist approves it. The probing tests use it to cover the phases, the budget stop, failed counter reads and lost byte counts. They also cover failed and hung networkQuality runs, a resolver that never answers and offline links. The `watch` tests add slow commands, Wi-Fi that drops and system clock corrections, and the command-line tests add a closed pipe and Ctrl-C.
- Hypothesis also runs the fake Mac on generated inputs. At generated speeds, budgets and round counts, no run moves more than its budget plus one half-second check of networkQuality's traffic. Hypothesis checks that bound again with counter reads that fail or run backward, transfers that lose their byte counts and networkQuality reports that count too few bytes. Over generated sequences of switches and command durations, `watch` lets no wait or command run past `--minutes`, except a measurement or connection check that started before it. Over generated switches and drops, `watch` measures any network I stay on long enough and checks the connections of any tested network I stay on. Over generated portals and drops, with `--baseline` and any `--seen` and `--max`, `watch` gives the network it starts on one measurement. Over generated short visits to another network, each way directly or through a drop, `watch` skips the baseline when it finds that network in one of its gateway reads, and otherwise measures the baseline once. With `--max 0`, it announces no network as new. And no damage Hypothesis does to a history line or a capture makes `import` or a view fail.
- The thorough profile runs 5,000 examples for each property.

## Limitations

- netpick measures IPv4 only.
- A network that drops pings gets unknown loss and latency, which rank worst on those two measures.
- Two Wi-Fi networks with the same gateway address and security type share an id, and so a name.
- `watch` spots a switch when the Wi-Fi gateway address changes, so it misses a switch between two networks with the same gateway address.
- The budget stop counts the sessions' own traffic, so it can end a networkQuality run early.
- Through each link, the probes reach 1.1.1.1, api.anthropic.com, github.com, speed.cloudflare.com, ipinfo.io, captive.apple.com and the servers networkQuality picks.

## Related tools

- Apple's [`networkQuality`](https://keith.github.io/xcode-man-pages/networkQuality.8.html) measures one interface per run with `-I`; netpick runs it on each link within a data budget.
- [ifspeedtest-cli](https://github.com/russellgrapes/ifspeedtest-cli) runs iperf3 over each interface and needs iperf3 servers.
- [Speedify](https://support.speedify.com/category/1035-speedify-on-macos) bonds links through its own VPN servers rather than choosing one.
