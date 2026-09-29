# Snowflake Bridge Builder

Builds Snowflake bridge lines for Tor and tests them against the live broker.

Snowflake peers are volunteer-run, so public bridge lists go stale quickly. This
tool doesn't ship a fixed list; it asks the broker which fingerprints it still
knows, generates lines for them, then probes every candidate front and reports
what actually answered.

## Requirements

- Python 3.11 or newer
- `aiortc` (only needed for the full handshake stage)

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

## Output files

| File | Contents |
|---|---|
| `bridges_safe.txt` | InviZible-compatible lines |
| `bridges_full.txt` | Full parameter set, for Tor Browser / Nyx / arti |
| `bridges_stealth.txt` | Hardened: no SNI, DTLS mimicry, connection cap |
| `bridges_VERIFIED.txt` | Every line that passed the transport probe |
| `bridges_LIVE.txt` | Completed a full handshake on repeated attempts |
| `bridges_FLAKY.txt` | Answered at least once, not reliably |
| `bridges_FAILED.txt` | Did not answer |
| `front_report.json` | Scan detail per domain |
| `bridge_probe_report.json` | Probe and liveness detail per pair |

For InviZible, use `bridges_safe.txt` or `bridges_LIVE.txt`.

### Verdicts

| Verdict | Meaning |
|---|---|
| `LIVE` | Handshake completed on at least 2 of 3 attempts |
| `FLAKY` | Answered at least once. Usable, less reliable |
| `DEAD` | The front refused the broker outright (403/405) |
| `UNKNOWN` | No verdict was possible from this host. Not a failure |

`UNKNOWN` exists because a single transient error must not condemn a working
front. Snowflake relays are volunteer-run and drop out constantly, so `LIVE`
is graded on a ratio of attempts rather than the outcome of the last one.

## Notes and limitations

- **`LIVE` means the DataChannel opened, not that a full tunnel was
  established.** After the channel opens the tool writes the turbo tunnel
  magic token and a client id, which is how a real client opts in. The proxy
  does not answer this, so silence is the normal response and cannot be used as
  a signal. A full proof would require a KCP and smux session, which this tool
  does not implement.
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

The broker lives on Fastly, so a front has to sit on the same network to reach
it. Google's edge networks answer `404` for this host regardless of what is
sent, so they are not useful here.

The check is a real offer/answer exchange over the front, with the SNI of the
front and the `Host` of the broker. A front that returns `301`, `403`, or `405`
is not routing to the broker. A front that returns a WebRTC answer is.

A negative control runs alongside: the all-zero fingerprint must be rejected on
every front. If it is not, the result is downgraded to `UNKNOWN`, because a
completed handshake would not prove the fingerprint is live.

## Scope

This tool tests bridges for reachability. It does not defeat active probing,
and the generated lines are the same ones a Tor user would otherwise copy by
hand.
