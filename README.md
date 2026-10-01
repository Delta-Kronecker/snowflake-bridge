# Snowflake Bridge Builder

Builds Snowflake bridge lines for Tor and tests them against the live broker.

Snowflake peers are volunteer-run, so public bridge lists go stale quickly. This
tool doesn't ship a fixed list; it asks the broker which fingerprints it still
knows, generates lines for them, then probes every candidate front and reports
what actually answered.

## Requirements

- Python 3.11 or newer
- `aiortc` (only needed for the full handshake stage)
- Tor Browser's `tor.exe` and `lyrebird.exe` (only needed for the tunnel stage)

```
pip install aiortc
```

## Usage

```
python SnowflakeBridgeBuilder.py
```

One run takes a few minutes. It writes its results next to the script and prints
a summary as it goes.

Run it from the network you intend to use. Anything the local network blocks
fails the probe and drops out of the output, so the results describe your
connection rather than the author's.

### Full tunnel verification

Everything the tool does by default stops at the transport layer. To prove that
traffic actually flows, opt in to the tunnel stage:

```
SNOWFLAKE_TUNNEL=1 python SnowflakeBridgeBuilder.py
```

It then starts a real Tor client per front, with `UseBridges 1` so every circuit
is forced through the bridge under test, and requires Tor to reach 100% and a
request to come back from a Tor exit. Results go to `bridges_TUNNEL.txt`.

This stage is slow, because a Tor bootstrap takes minutes and has to download
descriptors *through the bridge*. The knobs:

| Variable | Default | Meaning |
|---|---|---|
| `SNOWFLAKE_TUNNEL` | unset | Set to any value to enable the stage |
| `SNOWFLAKE_TUNNEL_LIMIT` | `12` | How many fronts to test |
| `SNOWFLAKE_TUNNEL_WORKERS` | `3` | Tor instances in parallel |
| `SNOWFLAKE_TUNNEL_TIMEOUT` | `300` | Seconds per front |
| `SNOWFLAKE_TUNNEL_SEED` | unset | Tor `DataDirectory` to copy cached descriptors from |

Point `SNOWFLAKE_TUNNEL_SEED` at an existing Tor `DataDirectory` to make the
stage dramatically faster. Only the descriptor caches are copied, never the
`keys` directory, so guard state stays fresh and the bridge is still the one
Tor has to use. Without a seed, every run re-downloads roughly 9,000
microdescriptors over a bridge that is slow by nature, and usually stalls at
`loading_descriptors`.

## What it does

1. **Fingerprint check** — asks the broker which of the known fingerprints it
   still recognises. Fingerprints rotate as relays come and go, so a hardcoded
   list goes stale. Only fingerprints the broker accepts are kept.

2. **Front scan** — resolves each candidate front domain and notes which land on
   a Fastly edge. This only ranks candidates; it cannot tell whether a front
   routes to the broker.

3. **Generate** — writes bridge lines for each surviving fingerprint and front,
   in three profiles.

4. **Transport probe** — sends an offer to the broker through each unique
   front/fingerprint pair and records the response.

5. **Relay liveness** — completes a real WebRTC handshake and requires a repeat
   before calling a front `LIVE`.

6. **Full tunnel (opt in)** — runs a real Tor client through the bridge and
   requires a confirmed Tor exit. This is the only stage that proves browsing
   traffic works.

## Output files

| File | Contents |
|---|---|
| `bridges_safe.txt` | InviZible-compatible lines |
| `bridges_full.txt` | Full parameter set, for Tor Browser / Nyx / arti |
| `bridges_stealth.txt` | Hardened: no SNI, DTLS mimicry, connection cap |
| `bridges_VERIFIED.txt` | Every line that passed the transport probe |
| `bridges_LIVE.txt` | Completed a full handshake on repeated attempts |
| `bridges_FLAKY.txt` | Answered at least once, not reliably |
| `bridges_TUNNEL.txt` | Proven end to end by a real Tor client |
| `bridges_FAILED.txt` | Did not answer |
| `front_report.json` | Scan detail per domain |
| `bridge_probe_report.json` | Probe, liveness and tunnel detail per pair |

For InviZible, use `bridges_safe.txt` or `bridges_LIVE.txt`.

### Verdicts

| Verdict | Meaning |
|---|---|
| `TUNNEL` | Tor bootstrapped through the bridge and returned a Tor exit |
| `LIVE` | Handshake completed on at least 2 of 3 attempts |
| `FLAKY` | Answered at least once. Usable, less reliable |
| `BOOTSTRAP_PARTIAL` | The bridge carried Tor, but bootstrap never finished |
| `DEAD` | The front refused the broker outright (403/405) |
| `UNKNOWN` | No verdict was possible from this host. Not a failure |

`UNKNOWN` exists because a single transient error must not condemn a working
front. Snowflake relays are volunteer-run and drop out constantly, so `LIVE`
is graded on a ratio of attempts rather than the outcome of the last one.

`BOOTSTRAP_PARTIAL` usually means the bridge is fine and the network was not
fast enough to fetch every descriptor. It is the normal result without a seed
cache, so do not read it as a broken bridge.

## Notes and limitations

- **`LIVE` is not `TUNNEL`.** A `LIVE` front completed a WebRTC handshake and the
  broker confirmed the fingerprint, which is real evidence but still one layer
  below a working connection. Only the tunnel stage proves traffic.
- **The Snowflake proxy is not a SOCKS server.** The stream after the
  handshake is Tor's own protocol, so no SOCKS5 request can be written to it
  directly. A tunnel test must go through Tor's own `SocksPort`.
- **`ampcache` only works with an AMP cache host in the front list.** Pairing
  `ampcache` with a plain front makes the broker reject every offer with
  `Unexpected error, no answer`, which looks like a dead bridge but is a
  configuration error. The generator adds `cdn.ampproject.org` automatically.
- **A STUN list is not optional.** Without `ice=` the DataChannel can open and
  then never carry the relay handshake. Every generated line has one.
- **Only one fingerprint was valid at the time of writing.** The others are
  still in the source so the tool can pick them up if the broker accepts them
  again.
- **Results are specific to the host and moment they were produced.** Fronts
  change behaviour between runs, and a front that works today may be blocked
  tomorrow. Re-run rather than trusting a saved file.
- **Most fronts listed do not work.** A front can only reach the broker if it
  shares a CDN with it, and most of the widely used domains do not. The failing
  ones are kept in the source with a note about what they returned, so the
  reason is documented rather than rediscovered.
- **Fingerprint filtering depends on the broker.** If the broker is unreachable
  the tool exits rather than guessing, because emitting lines with unknown
  fingerprints would produce bridges that silently never work.

## How a front is judged

The broker is reached through a CDN, so a front only works if it sits on a
network that will route to the snowflake peer. The check is a real offer and
answer exchange over the front, with the SNI of the front. A front that returns
`301`, `403`, or `405` is not routing to the broker. A front that returns a
WebRTC answer is.

Two mistakes are worth documenting because both look like a broken bridge:

- **`ampcache` with a plain front.** The broker answers every offer with
  `Unexpected error, no answer`. The generated `full` and `stealth` lines put
  `cdn.ampproject.org` in the front list to avoid this; the `safe` lines use a
  plain front with no cache at all.
- **Too few STUN servers.** The DataChannel opens, `conn_done_pt` appears, and
  then nothing. This reads as a dead bridge but is a NAT traversal problem.

A negative control runs alongside: the all-zero fingerprint must be rejected on
every front. If it is not, the result is downgraded to `UNKNOWN`, because a
completed handshake would not prove the fingerprint is live.

### Confirmed working at the time of writing

| Front | Line type | Result |
|---|---|---|
| `www.google.com,cdn.ampproject.org` | `ampcache` | `TUNNEL`, exit confirmed |
| `www.python.org` | plain `front` | `TUNNEL`, exit confirmed |
| `cdn.jsdelivr.net` | plain `front` | broker returned no answer |
| `github.com` | plain `front` | broker returned no answer |

Both confirmed fronts came back through Tor exits that reported `IsTor: true`,
which is the strongest check this tool performs.

## Scope

This tool tests bridges for reachability. It does not defeat active probing,
and the generated lines are the same ones a Tor user would otherwise copy by
hand.
