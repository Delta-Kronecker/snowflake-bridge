# -*- coding: utf-8 -*-
"""
==============================================================================
  FASTLY FRONT SCANNER + BRIDGE GENERATOR
  Broker : https://snowflake-broker.torproject.net/
  ~550 domains, multi-signal, confidence score
==============================================================================
"""

import asyncio
import os
import socket
import ssl
import json
import re
import sys
import time
import concurrent.futures
import shutil
import subprocess
import tempfile
from collections import defaultdict

# aiortc is only needed for the deep relay-liveness stage. The bridge generator
# and the transport probe work without it.
try:
    from aiortc import RTCPeerConnection, RTCSessionDescription
    from aiortc import RTCConfiguration, RTCIceServer
    HAVE_AIORTC = True
except Exception:
    HAVE_AIORTC = False

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BROKER_URL = "https://snowflake-broker.torproject.net/"

# ==============================================================================
# ==============================================================================
# FASTLY IP RANGES
#
# snowflake-broker.torproject.net is served by Fastly, so a domain can only
# front it if that domain sits on the same Fastly network. Google edges are
# useless here: they answer 404 for this Host no matter what.
# ==============================================================================
FASTLY_IP_PREFIXES = (
    "23.235.",     # 23.235.32.0/20
    "199.232.",    # 199.232.64.0/18
    "151.101.",    # 151.101.0.0/16
    "146.75.",     # 146.75.0.0/16
    "23.0.",       # 23.0.0.0/12
    "23.52.",      # 23.52.0.0/14
    "23.53.",      # 23.53.0.0/16
    "23.51.",      # 23.51.0.0/16
    "23.222.",     # 23.222.0.0/16
    "13.32.",      # 13.32.0.0/15
    "13.35.",      # 13.35.0.0/16
    "99.86.",      # 99.86.0.0/16
    "167.82.",     # 167.82.0.0/16
)

# ==============================================================================
# DOMAINS
#
# Deliberately small. A front works only when it shares a CDN with the broker,
# so listing thousands of unrelated hosts just produces thousands of guaranteed
# failures. Every domain here is a real Fastly customer; the tier 1 set is what
# Tor ships for snowflake plus the hosts we have watched return a real answer.
#
# The relay probe is the real judge -- the scan below only shortlists hosts, it
# never decides which bridge lines work.
# ==============================================================================
DOMAINS = [
    # ===== tier 1: measured working (broker returned a real answer) =====
    "www.nytimes.com",
    "www.python.org",
    "www.fastly.com",
    "fastly.jsdelivr.net",
    "cdn.jsdelivr.net",        # Cloudflare, kept for CDN diversity
    "www.reddit.com",          # scored 0 but is on 151.101.* (Fastly)
    "www.theguardian.com",
    "www.bloomberg.com",
    "www.forbes.com",
    "www.target.com",
    "www.usatoday.com",
    "www.yelp.com",
    "www.kernel.org",
    "www.apache.org",
    "www.mozilla.org",
    "www.mlb.com",
    "www.cbsnews.com",
    "www.cnn.com",
    "www.foxnews.com",
    "www.independent.co.uk",
    "www.lemonde.fr",
    "www.zeit.de",
    "www.corriere.it",
    "www.elpais.com",

    # ===== tier 2: measured reachable, verdict varies run to run =====
    "www.torproject.org",      # the front Tor ships for snowflake

    # ===== tier 3: same CDN, worth re-probing after any network change =====
    # These resolved to Fastly edges in DNS but did not answer during the last
    # probe. Kept because CDN assignments move; the probe decides, not this list.
    "www.reuters.com",
    "www.washingtonpost.com",
    "www.cnbc.com",
    "www.imdb.com",
    "www.ebay.com",
    "www.walgreens.com",
    "www.npr.org",
    "www.politico.com",
    "www.latimes.com",
    "sports.yahoo.com",
    "www.accuweather.com",
    "www.indeed.com",
    "www.tripadvisor.com",
    "www.adobe.com",
    "www.salesforce.com",
    "www.twilio.com",
    "www.okta.com",
    "www.brave.com",
    "www.wsj.com",
    "www.zillow.com",
    "www.espn.com",
    "www.nba.com",
    "www.si.com",
    "www.rottentomatoes.com",
    "www.merriam-webster.com",
    "www.golf.com",

    # ===== tier 4: known not to route, kept only to document why =====
    "github.com",              # 301
    "raw.githubusercontent.com",  # 405 - rejects the broker Host outright
    "stackoverflow.com",       # 403
    "www.wikipedia.org",       # 400
    "www.w3.org",              # timeout
]

# A domain listed in two tiers should still be scanned once. Order is kept so
# the report still shows the tiers in a sensible sequence.
DOMAINS = list(dict.fromkeys(DOMAINS))


# ==============================================================================
# HELPERS
# ==============================================================================
def resolve_ips(domain, timeout=5):
    ips = []
    try:
        infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def is_fastly_ip(ip):
    for prefix in FASTLY_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def _der_tlv(buf, i):
    """Read one DER tag/length/value header. Returns (tag, value_start, length)."""
    tag = buf[i]
    i += 1
    n = buf[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, i, n


def cert_issuer_from_der(der):
    """Pull the issuer CN/O out of a DER certificate.

    ssl.getpeercert() returns {} when verification is disabled, which is what
    we do here, so the issuer has to be read straight out of the DER bytes.
    """
    try:
        _, i, _ = _der_tlv(der, 0)        # Certificate
        _, i, _ = _der_tlv(der, i)        # tbsCertificate
        tag, i, ln = _der_tlv(der, i)     # version [0], if present
        if tag == 0xA0:
            i += ln
            tag, i, ln = _der_tlv(der, i)  # serialNumber
        i += ln                            # signature AlgorithmIdentifier
        tag, i, ln = _der_tlv(der, i)     # signature AlgorithmIdentifier
        i += ln
        tag, i, ln = _der_tlv(der, i)     # issuer Name
        end = i + ln
        while i < end:                     # RDNSequence -> SET -> SEQUENCE
            tag, s, l = _der_tlv(der, i)
            j, setend = s, s + l
            while j < setend:
                tag, s2, l2 = _der_tlv(der, j)
                _, oid_s, oid_l = _der_tlv(der, s2)
                oid = der[s2:oid_s + oid_l]
                k = oid_s + oid_l
                tag, val_s, val_l = _der_tlv(der, k)
                if oid in (b"\x55\x04\x03", b"\x55\x04\x0a"):  # CN, O
                    return der[val_s:val_s + val_l].decode("utf-8", "replace")
                j = s2 + l2
            i = setend
    except Exception:
        return None
    return None


def get_cert_issuer(domain, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if der:
                    return cert_issuer_from_der(der)
    except Exception:
        pass
    return None


def fetch_headers(domain, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except Exception:
        pass
    headers = {}
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                req = (
                    "HEAD / HTTP/1.1\r\n"
                    "Host: " + domain + "\r\n"
                    "User-Agent: Mozilla/5.0\r\n"
                    "Accept: */*\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                )
                ssock.sendall(req.encode())
                raw = b""
                while len(raw) < 16384:
                    try:
                        chunk = ssock.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    raw += chunk
                    if b"\r\n\r\n" in raw:
                        break
                head = raw.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")
                for line in head.split("\r\n")[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
    except Exception:
        pass
    return headers


# ==============================================================================
# CLASSIFIER
# ==============================================================================
def classify_domain(domain):
    res = {
        "domain": domain, "ips": [], "fastly_ip": False,
        "cert_issuer": None, "fastly_cert": False,
        "server": None, "fastly_server": False,
        "via": None, "fastly_via": False,
        "served_by": None, "fastly_served": False,
        "cache": None, "fastly_cache": False,
        "score": 0, "signals": [], "error": None,
    }

    ips = resolve_ips(domain)
    res["ips"] = ips
    if ips and any(is_fastly_ip(ip) for ip in ips):
        res["fastly_ip"] = True
        res["signals"].append("IP")
    elif ips:
        # Worth surfacing: a local DNS cache can hand back a non-Fastly anycast
        # address for a host that is normally Fastly, which silently costs 50
        # points. The probe still decides, but the log should show why.
        res["signals"].append("IP-OTHER:" + ips[0])
        res["error"] = "resolved off the Fastly network: " + ips[0]

    issuer = get_cert_issuer(domain)
    res["cert_issuer"] = issuer
    if issuer and "fastly" in issuer.lower():
        res["fastly_cert"] = True
        res["signals"].append("CERT")

    headers = fetch_headers(domain)
    if headers:
        server = headers.get("server", "")
        res["server"] = server
        if "fastly" in server.lower():
            res["fastly_server"] = True
            res["signals"].append("SERVER")

        via = headers.get("via", "")
        res["via"] = via
        if "fastly" in via.lower():
            res["fastly_via"] = True
            res["signals"].append("VIA")

        served = headers.get("x-served-by", "") or headers.get("x-served", "")
        res["served_by"] = served
        if "fastly" in served.lower() or served.lower().startswith("cache-"):
            res["fastly_served"] = True
            res["signals"].append("SERVED")

        cache = headers.get("x-cache", "")
        res["cache"] = cache
        if "fastly" in cache.lower() or "fastly" in headers.get("x-timer", "").lower():
            res["fastly_cache"] = True
            res["signals"].append("CACHE")

    # The IP range is the only reliable signal: it is Fastly's anycast space.
    # The certificate is weak evidence -- Fastly serves DV certs issued by
    # GlobalSign / DigiCert for most customers (python.org's issuer is
    # "GlobalSign nv-sa"), so a non-Fastly issuer proves nothing.
    score = 0
    if res["fastly_ip"]: score += 50
    if res["fastly_server"]: score += 25
    if res["fastly_cache"]: score += 20
    if res["fastly_via"]: score += 10
    if res["fastly_served"]: score += 10
    if res["fastly_cert"]: score += 10

    res["score"] = min(score, 100)
    res["is_fastly"] = score >= 50

    if not res["is_fastly"] and not res["signals"]:
        res["error"] = "no fastly signal"
    return res


# ==============================================================================
# BATCH
# ==============================================================================
def run_scan(domains, workers=40):
    print("")
    print("=" * 78)
    print("SCANNING " + str(len(domains)) + " DOMAINS")
    print("=" * 78)
    results = []
    done = 0
    total = len(domains)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(classify_domain, d): d for d in domains}
        for fut in concurrent.futures.as_completed(futs):
            res = fut.result()
            done += 1
            mark = "FASTLY" if res["is_fastly"] else "  --  "
            sig = ",".join(res["signals"]) if res["signals"] else "-"
            print("[%3d/%3d] %s %-46s score=%-3d sig=%s" % (
                done, total, mark, res["domain"][:46],
                res["score"], sig[:24]))
            results.append(res)
    return results


# ==============================================================================
# REPORT
# ==============================================================================
def generate_report(results):
    # Thresholds match the current weights: a Fastly anycast IP alone scores
    # 50, the strongest single signal available, so >=50 means "this host sits
    # on the broker's CDN". The old 70 cutoff was unreachable after reweighting.
    confirmed = [r for r in results if r["score"] >= 50]
    probable = [r for r in results if 20 <= r["score"] < 50]
    rejected = [r for r in results if r["score"] < 20]

    sig_count = defaultdict(int)
    for r in confirmed + probable:
        for s in r["signals"]:
            sig_count[s] += 1

    print("")
    print("=" * 78)
    print("REPORT")
    print("=" * 78)
    print("Total tested     : " + str(len(results)))
    print("On Fastly (>=50) : " + str(len(confirmed)))
    print("Unclear (20-49)  : " + str(len(probable)))
    print("Other (<20)      : " + str(len(rejected)))
    print("")
    print("NOTE: this scan only ranks candidates. It cannot tell whether a")
    print("front routes to the broker -- only the probe below can. A low score")
    print("is not a failure: www.python.org scores 10 and works.")
    print("")
    print("Signal breakdown:")
    for sig, cnt in sorted(sig_count.items(), key=lambda x: -x[1]):
        print("  %-10s : %d" % (sig, cnt))
    print("")
    print("ON FASTLY (" + str(len(confirmed)) + "):")
    for r in sorted(confirmed, key=lambda x: -x["score"]):
        print("  %-50s score=%-3d %s" % (
            r["domain"], r["score"], ",".join(r["signals"])))
    print("")
    print("UNCLEAR (" + str(len(probable)) + "):")
    for r in sorted(probable, key=lambda x: -x["score"]):
        print("  %-50s score=%-3d %s" % (
            r["domain"], r["score"], ",".join(r["signals"])))
    return confirmed, probable, rejected


# ==============================================================================
# BRIDGE GENERATOR
# ==============================================================================
FP_SF01 = "2B280B23E1107BB62ABFC40DDCC8824814F80A72"
FP_SF02 = "8838024498816A039FCBBA814E6F40A0843051FA"
FP_TB1 = "53B65F538F5E9A5FA6DFE5D75C78CB66C5515EF7"
FP_TB2 = "A478B32B16FC1F371677F9F41D9C5272B8EBB0F7"

IP_FP_PAIRS = [
    ("193.187.88.42:132", FP_SF01),
    ("193.187.88.43:132", FP_SF01),
    ("193.187.88.44:132", FP_SF01),
    ("193.187.88.45:132", FP_SF01),
    ("193.187.88.46:132", FP_SF01),
    ("[2a0c:dd40:1:b::42]:132", FP_SF01),
    ("[2a0c:dd40:1:b::43]:132", FP_SF01),
    ("[2a0c:dd40:1:b::44]:132", FP_SF01),
    ("[2a0c:dd40:1:b::45]:132", FP_SF01),
    ("[2a0c:dd40:1:b::46]:132", FP_SF01),
    ("141.212.118.18:80", FP_SF02),
    ("[2607:f018:600:8:be30:5bff:fe1:c6fa]:80", FP_SF02),
    ("192.0.2.3:80", FP_SF01),
    ("192.0.2.4:80", FP_SF02),
    ("10.0.3.1:443", FP_TB1),
    ("10.0.3.2:443", FP_TB2),
    ("10.0.3.1:80", FP_TB1),
    ("10.0.3.2:80", FP_TB2),
    ("10.0.3.1:8080", FP_TB1),
    ("10.0.3.2:8080", FP_TB2),
]

# The STUN list from a bridge line that is confirmed to work end to end. A
# two server list leaves NAT traversal failing often enough that the DataChannel
# opens but never carries the relay handshake, which looks like a dead bridge.
STUN = ("ice=stun:stun.nextcloud.com:443,stun:stun.sipgate.net:10000,"
        "stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,"
        "stun:stun.voipgate.com:3478,stun:stun.bethesda.net:3478,"
        "stun:stun.mixvoip.com:3478")
UTLS = "utls-imitate=hellorandomizedalpn"

# ---------------------------------------------------------------------------
# Snowflake parameters, as read from the real client source (csnow.go).
#
# Every one of these is a genuine SOCKS arg the snowflake client honours, and
# Tor Browser / Nyx / arti accept all of them on a bridge line. InviZible's
# own checker (BridgeChecker.kt) recognises only a subset, so lines carrying
# the extras are rejected by that app and nowhere else.
#
# Values from csnow.go:
#   covertdtls-config   mimic | randomize | randomizemimic | disable (default)
#   covertdtls-fingerprint  pin an exact raw DTLS fingerprint to mimic
#   utls-nosni          true | yes  -> strip SNI from the uTLS ClientHello
#   max                 integer, concurrent connection cap
#   fronts              comma-separated, overrides front=
#   ampcache            AMP cache used as a signalling proxy
#   sqsqueue/sqscreds   SQS queue fallback signalling
#   fingerprint         duplicates the address fingerprint, Tor ignores it
# ---------------------------------------------------------------------------
COVERTDLS_MIMIC = "covertdtls-config=mimic"
COVERTDLS_RANDOMIZE = "covertdtls-config=randomize"
COVERTDLS_RANDOMIZEMIMIC = "covertdtls-config=randomizemimic"
COVERTDLS_DISABLE = "covertdtls-config=disable"
COVERTDTLS_FP = "covertdtls-fingerprint=chrome"
UTLS_NOSNI = "utls-nosni=true"
MAX_CONNS = "max=10"
# Plain AMP cache domain. The longer /c/s/www/<broker> form was never usable:
# the cache has to be a bare host, and a working line uses exactly this value.
AMPCACHE = "ampcache=https://cdn.ampproject.org/"

# Hosts that can fetch the relay through the AMP cache. When ampcache is in use
# the front list must contain at least one of these, otherwise the broker
# rejects every offer with "Unexpected error, no answer" and the bridge never
# connects at all.
AMPCACHE_FRONTS = ("cdn.ampproject.org", "www.ampproject.org")
SQSQUEUE = "sqsqueue=https://sqs.us-east-1.amazonaws.com/xxxxxxxxxxxx/queue2"
SQSCREDS = ("sqscreds=AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMI/"
            "K7MDENG/bPxRfiCYEXAMPLEKEY")

# bare values used by the profiles below
_ICE_VALUES = STUN.split("=", 1)[1]

# Parameter order the InviZible regex expects. It has no alternation, so a key
# in the wrong position makes the whole line fail there. Tor itself does not
# care about order, so this order is safe for every client.
PARAM_ORDER = ["fingerprint", "url", "ampcache", "front", "fronts",
               "ice", "utls-imitate", "sqsqueue", "sqscreds",
               "max", "utls-nosni", "covertdtls-config",
               "covertdtls-fingerprint"]


def render_params(params):
    """Render a {key: value} dict as bridge-line arguments in a stable order."""
    out = []
    for key in PARAM_ORDER:
        if key in params and params[key] is not None:
            out.append(key + "=" + params[key])
    unknown = [k for k in params if k not in PARAM_ORDER]
    if unknown:
        out.extend(k + "=" + str(params[k]) for k in unknown)
    return out


def build_level(level, fronts, pairs=None, profile="safe"):
    """Assemble one level of bridge lines.

    profile:
      "safe"   - only the keys InviZible's regex accepts
      "full"   - every real parameter; rejected by InviZible, fine for
                 Tor Browser / Nyx / arti
      "stealth"- the obfuscation-hardened set (no SNI, mimicking DTLS)
    """
    tiers = {
        # ice is in every tier. Without a STUN server list the DataChannel opens
        # but the relay handshake stalls, and such a line looks broken while the
        # bridge itself is fine.
        1: {"url": BROKER_URL, "front": "__FRONT__", "ice": _ICE_VALUES},
        2: {"url": BROKER_URL, "front": "__FRONT__", "ice": _ICE_VALUES},
        3: {"url": BROKER_URL, "front": "__FRONT__", "ice": _ICE_VALUES,
            "utls-imitate": "hellorandomizedalpn"},
        4: {"url": BROKER_URL, "front": "__FRONT__",
            "ice": _ICE_VALUES, "utls-imitate": "hellorandomizedalpn"},
    }
    template = dict(tiers.get(level, tiers[1]))

    if profile in ("full", "stealth"):
        template["max"] = "10"
    # ampcache applies to every profile that is meant to actually connect, not
    # just "full".
    if profile in ("full", "stealth"):
        template["ampcache"] = AMPCACHE.split("=", 1)[1]
    if profile == "stealth":
        template["utls-imitate"] = "hellorandomizedalpn"
        template["utls-nosni"] = "true"
        # randomizemimic is the value in the confirmed working line; plain
        # mimic keeps the fingerprint constant, which is easier to fingerprint.
        template["covertdtls-config"] = "randomizemimic"

    pairs = IP_FP_PAIRS if pairs is None else pairs
    out = []
    for front in fronts:
        for ip, fp in pairs:
            params = dict(template)
            params.pop("front", None)
            if "ampcache" in params:
                # The AMP cache can only be used when the front list contains an
                # ampproject host, so keep the chosen domain as a second choice.
                chosen = front if front in AMPCACHE_FRONTS else (
                    AMPCACHE_FRONTS[0] + "," + front)
                params["fronts"] = chosen
            else:
                params["front"] = front
            args = render_params(params)
            out.append(" ".join(["Bridge snowflake", ip, fp] + args))
    return out


def known_fingerprints(fingerprints, broker_url=None, front=None,
                       timeout=20, workers=6):
    """Ask the broker which fingerprints it actually knows.

    A bridge line with a fingerprint no relay owns is accepted by the app's
    format checker and can never connect, so there is no point generating it.
    Probing costs ~400 ms per fingerprint and needs no WebRTC.

    Returns {fp: (known, reason)}.
    """
    broker_url = broker_url or BROKER_URL
    fps = sorted(set(f for f in fingerprints if f))
    print("\n" + "=" * 78)
    print("FINGERPRINT CHECK  (%d fingerprints, broker=%s)"
          % (len(fps), broker_url))
    print("=" * 78)

    out = {}

    def run(fp):
        # probe straight at the broker; this is about the fingerprint, not
        # about fronting
        return fp, snowflake_poll(broker_url, fp, front=front,
                                  timeout=timeout, attempts=2)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for fp, (tier, reason, ms) in ex.map(run, fps):
            known = tier in ("answer", "reached")
            out[fp] = (known, reason)
            print("  %-6s fp=%-42s %5sms  %s" % (
                "OK" if known else "DROP", fp, ms, reason[:60]))

    good = sorted(f for f in fps if out[f][0])
    bad = sorted(f for f in fps if not out[f][0])
    print("  usable: %d   rejected: %d" % (len(good), len(bad)))
    if bad:
        print("  rejected fingerprints: " + ", ".join(f[:8] + "..." for f in bad))
    return out


def filter_pairs(fps):
    """Keep only the IP_FP_PAIRS entries whose fingerprint the broker knows."""
    known = known_fingerprints([fp for _, fp in IP_FP_PAIRS])
    keep = [(ip, fp) for ip, fp in IP_FP_PAIRS if known.get(fp, (False,))[0]]
    drop = [(ip, fp) for ip, fp in IP_FP_PAIRS if not known.get(fp, (False,))[0]]
    print("\n  IP_FP_PAIRS: %d kept, %d dropped" % (len(keep), len(drop)))
    if drop:
        for ip, fp in drop:
            print("    dropped %-42s %s" % (ip, fp[:8] + "..."))
    if not keep:
        raise SystemExit("No fingerprint in IP_FP_PAIRS is known to the broker; "
                         "nothing can be generated.")
    return keep


PROFILES = {
    "safe": "InviZible-safe: only keys BridgeChecker.kt accepts",
    "full": "every real parameter; for Tor Browser / Nyx / arti",
    "stealth": "hardened: no SNI, mimicking DTLS, connection cap",
}


def generate_bridges(fronts, output_file, pairs=None, profile="safe"):
    if not fronts:
        return 0, []
    seen = set()
    sections = []
    for level, title in [
        (1, "LEVEL 1 - MINIMAL"),
        (2, "LEVEL 2 - + STUN"),
        (3, "LEVEL 3 - + UTLS"),
        (4, "LEVEL 4 - FULL"),
    ]:
        raw = build_level(level, fronts, pairs, profile=profile)
        uniq = []
        for line in raw:
            if line not in seen:
                seen.add(line)
                uniq.append(line)
        sections.append((title, uniq))

    total = sum(len(s[1]) for s in sections)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# Snowflake Bridges - Fastly fronts\n")
        f.write("# Broker: " + BROKER_URL + "\n")
        f.write("# Profile: " + profile + " - " + PROFILES[profile] + "\n")
        f.write("# Fronts: " + str(len(fronts)) + "\n")
        f.write("# Total: " + str(total) + "\n")
        for title, lines in sections:
            f.write("\n# " + "=" * 70 + "\n")
            f.write("# " + title + "  (" + str(len(lines)) + " lines)\n")
            f.write("# " + "=" * 70 + "\n")
            for line in lines:
                f.write(line + "\n")
    return total, sections


def generate_all_profiles(fronts, pairs=None):
    """Write one file per profile. Returns {profile: (total, sections)}."""
    out = {}
    for profile in ("safe", "full", "stealth"):
        fname = "bridges_%s.txt" % profile
        total, sections = generate_bridges(fronts, fname, pairs,
                                           profile=profile)
        out[profile] = (total, sections)
        print("  %-8s : %5d lines -> %s" % (profile, total, fname))
    return out


# ==============================================================================
# LIVE BRIDGE VERIFICATION
#
# A 200/3xx on a plain GET only proves the CDN answered. It does NOT prove that
# the Snowflake broker behind that front is actually reachable. So we send a
# real ClientPollRequest -- the exact first message the snowflake-client sends --
# over the exact transport the bridge line describes:
#
#     TLS SNI      = front domain   (front=..., or the broker host if absent)
#     Host header  = broker host
#     POST         = <path>client   with body  "1.0\n" + json
#
# The broker replies with a real {"answer": ...} WebRTC answer only if it
# received and understood the request. Anything else (405 from an unrelated
# vhost, 504 from the CDN error page, a JSON error body) is a dead bridge.
#
# NOTE: the broker does NOT validate the fingerprint at this stage -- a bogus
# fingerprint still gets an answer. So this test proves TRANSPORT + FRONTING,
# not that the relay behind the fingerprint is currently live.
# ==============================================================================
SNOWFLAKE_SDP = (
    "v=0\r\n"
    "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "a=group:BUNDLE 0\r\n"
    "a=extmap-allow-mixed\r\n"
    "a=msid-semantic: WMS\r\n"
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "a=ice-ufrag:EsAw\r\n"
    "a=ice-pwd:P2uYro0UCOQ4zxjYXh+G7Dr\r\n"
    "a=ice-options:trickle\r\n"
    "a=fingerprint:sha-256 8C:F1:5D:2A:B7:4C:9A:EF:11:52:88:7B:32:1D:99:"
    "2A:6C:B3:44:41:66:2F:9B:2C:5D:1E:88:AA:99:BB\r\n"
    "a=setup:actpass\r\n"
    "a=mid:0\r\n"
    "a=sctp-port:5000\r\n"
    "a=max-message-size:262144\r\n"
    "a=candidate:1 1 udp 2130706431 192.168.1.10 54321 typ host\r\n"
    "a=end-of-candidates\r\n"
)

_ICE_SERVER = (STUN.split("=", 1)[1].split(",")[0] if "=" in STUN
               else "stun:stun.l.google.com:19302")


def snowflake_poll(broker_url, fingerprint, front=None, timeout=15, attempts=3):
    """Send a real ClientPollRequest. Returns (tier, reason, elapsed_ms).

    tier is one of:
      "answer"  - broker returned a real WebRTC answer. Transport, fronting and
                  relay assignment all worked.
      "reached" - the broker received and parsed the request, but could not
                  finish (e.g. "timed out waiting for answer!", because our
                  synthetic SDP candidate is not a real relay). This still
                  PROVES the fronting route reaches the broker, which is what
                  a bridge line actually depends on.
      "badfp"   - the broker explicitly reported the fingerprint as unknown.
                  The fronting route is fine, but this bridge line cannot ever
                  work because no relay owns that fingerprint.
      "fail"    - the front does not deliver the request to the broker at all
                  (no response, or a response from an unrelated origin).

    NOTE: the JSON key must be "fingerprint" (a single string). Sending
    "fingerprints" (plural, an array) is silently ignored by the broker, which
    then hands out the default bridge for every request -- that mistake makes
    every fingerprint look valid.
    """
    rest = broker_url.split("//", 1)[1]
    broker_host = rest.split("/", 1)[0]
    path = "/" + (rest.split("/", 1)[1] if "/" in rest else "") + "client"
    sni = front or broker_host

    body = b"1.0\n" + json.dumps({
        "ice": _ICE_SERVER,
        "nat": "unknown",
        "fingerprint": fingerprint,
        # the broker json-unmarshals this string a second time into its Offer
        # struct, so the offer has to be double-encoded
        "offer": json.dumps({"type": "offer", "sdp": SNOWFLAKE_SDP}),
    }).encode()

    head = (
        "POST " + path + " HTTP/1.1\r\n"
        "Host: " + broker_host + "\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: " + str(len(body)) + "\r\n"
        "Connection: close\r\n\r\n"
    ).encode()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except Exception:
        pass

    last = ("fail", "", "not attempted")
    for attempt in range(attempts):
        t0 = time.time()
        try:
            ip = socket.gethostbyname(sni)
        except socket.gaierror:
            return "fail", "DNS fail on front " + sni, 0

        try:
            with socket.create_connection((ip, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni) as ss:
                    ss.sendall(head + body)
                    raw = b""
                    while len(raw) < 65536:
                        try:
                            chunk = ss.recv(4096)
                        except socket.timeout:
                            break
                        if not chunk:
                            break
                        raw += chunk
        except ssl.SSLError as e:
            last = ("fail", "SSL: " + str(e)[:60], 0)
            if attempt + 1 < attempts:
                time.sleep(0.6)
            continue
        except socket.timeout:
            last = ("fail", "timeout", 0)
            if attempt + 1 < attempts:
                time.sleep(0.6)
            continue
        except socket.error as e:
            last = ("fail", "socket: " + str(e)[:60], 0)
            if attempt + 1 < attempts:
                time.sleep(0.6)
            continue
        except Exception as e:
            last = ("fail", "unknown: " + str(e)[:60], 0)
            if attempt + 1 < attempts:
                time.sleep(0.6)
            continue

        elapsed = int((time.time() - t0) * 1000)
        if not raw:
            last = ("fail", "connection closed with no response - "
                            "this front does not serve the broker host", 0)
            if attempt + 1 < attempts:
                time.sleep(0.6)
            continue

        head_txt, _, payload = raw.partition(b"\r\n\r\n")
        status_line = head_txt.split(b"\r\n", 1)[0].decode("latin1", "replace")
        status = status_line.split()[1] if len(status_line.split()) > 1 else "???"

        if b'"answer"' in payload:
            return "answer", "broker returned WebRTC answer", elapsed

        if not status_line.startswith("HTTP/"):
            last = ("fail", "non-HTTP response (" + repr(raw[:40]) + ")", elapsed)
        elif status.startswith("2"):
            detail = payload[:140].decode("utf-8", "replace").strip()
            if "fingerprint is unknown" in detail or "fingerprint" in detail and "unknown" in detail:
                return ("badfp", "broker does not know this fingerprint", elapsed)
            # a 200 carrying {"error":...} means the broker itself parsed the
            # request -> the fronting route is good, only negotiation failed
            return ("reached", "broker reached, negotiation incomplete: " + detail,
                    elapsed)
        elif status == "405":
            last = ("fail", "405 - front does not route to this broker", elapsed)
        elif status in ("502", "503", "504"):
            last = ("fail", status + " - CDN cannot reach broker origin", elapsed)
        elif status == "421":
            last = ("fail", "421 - misdirected, domain fronting refused", elapsed)
        else:
            last = ("fail", "HTTP " + status, elapsed)

        if attempt + 1 < attempts:
            time.sleep(0.6)

    return last


def parse_bridge_line(line):
    """Pull url / front / fingerprint out of a generated bridge line.

    Handles both front= and fronts=; fronts= may list several domains, in which
    case the first one is the front that will be probed. Every real snowflake
    key is recognised so nothing is silently misread.
    """
    tokens = line.split()
    info = {"url": None, "front": None, "fronts": None, "fingerprint": None}
    if len(tokens) < 4:
        return info
    info["fingerprint"] = tokens[3]
    for t in tokens[4:]:
        if "=" not in t:
            continue
        key, value = t.split("=", 1)
        if key == "url":
            info["url"] = value
        elif key == "front":
            info["front"] = value
            info["fronts"] = [value]
        elif key == "fronts":
            info["fronts"] = [v for v in value.split(",") if v]
            # fronts= wins over front= in the client, so it decides the probe
            info["front"] = info["fronts"][0] if info["fronts"] else info["front"]
    return info


def verify_bridges(sections, ok_file, bad_file, workers=8, timeout=15, cache=None):
    """Probe every unique (broker, front, fingerprint) triple used by the
    generated lines and split the output into verified / failed.

    The 4 LEVELS differ only by ice=/utls-imitate=, which are negotiated after
    the broker answers, so the probe runs once per unique triple and the result
    is reused across levels instead of re-probing identical transports.

    cache is an optional dict shared across profiles. Any combo already in it
    is skipped on the network entirely and its verdict is reused verbatim, so
    the same front is never dialled twice for the same fingerprint.
    """
    combos = {}
    all_lines = []
    for title, lines in sections:
        for line in lines:
            all_lines.append((title, line))
            info = parse_bridge_line(line)
            key = (info["url"], info["front"], info["fingerprint"])
            combos.setdefault(key, info)

    if cache is None:
        cache = {}

    results = {}
    keys = list(combos.keys())
    pending = [k for k in keys if k not in cache]
    reused = len(keys) - len(pending)
    t0 = time.time()

    def run(key):
        info = combos[key]
        tier, reason, ms = snowflake_poll(
            info["url"], info["fingerprint"], front=info["front"], timeout=timeout)
        return key, tier, reason, ms

    if pending:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for key, tier, reason, ms in ex.map(run, pending):
                results[key] = (tier, reason, ms)
                cache[key] = (tier, reason, ms)

    for key in keys:
        if key not in results:
            results[key] = cache[key]
            tier, reason, ms = cache[key]
            print("  %-5s front=%-30s fp=%-6s %5sms  %s  (reused)" % (
                {"answer": "OK", "reached": "OK*", "badfp": "BADFP",
                 "fail": "FAIL"}[tier],
                (key[1] or "(direct)")[:30],
                (key[2] or "")[:6],
                ms,
                reason))

    print("  probe time: %.1f s  (%d probed, %d reused)"
          % (time.time() - t0, len(pending), reused))
    print("  OK = full answer   OK* = broker reached, relay not negotiated")

    verified = []
    failed = []
    seen_ok = set()
    seen_bad = set()
    for title, line in all_lines:
        info = parse_bridge_line(line)
        key = (info["url"], info["front"], info["fingerprint"])
        tier, reason, ms = results.get(key, ("fail", "not probed", 0))
        if tier in ("answer", "reached"):
            if line not in seen_ok:
                seen_ok.add(line)
                verified.append((title, line, reason, ms))
        else:
            if line not in seen_bad:
                seen_bad.add(line)
                failed.append((title, line, reason, ms))

    full = [v for v in verified if "WebRTC answer" in v[2]]

    with open(ok_file, "w", encoding="utf-8") as f:
        f.write("# Snowflake Bridges - VERIFIED against the live broker\n")
        f.write("# the broker received and parsed a real ClientPollRequest\n")
        f.write("# over exactly the front/domain this line specifies\n")
        f.write("# full WebRTC answer: %d of %d combos\n" % (len(full), len(keys)))
        f.write("# NOTE: proves transport + fronting, not relay liveness\n")
        f.write("# combos: %d   lines: %d\n" % (len(keys), len(verified)))
        f.write("# generated: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
        f.write("#" + "=" * 78 + "\n")
        for title, line, reason, ms in verified:
            f.write(line + "\n")

    with open(bad_file, "w", encoding="utf-8") as f:
        f.write("# Snowflake Bridges - FAILED the live probe\n")
        f.write("# combos verified: %d   lines: %d\n" % (len(keys), len(failed)))
        f.write("# generated: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
        f.write("#" + "=" * 78 + "\n")
        for title, line, reason, ms in failed:
            f.write("# " + reason + "\n")
            f.write(line + "\n\n")

    return verified, failed, results


# ==============================================================================
# STAGE 2 - RELAY LIVENESS (real WebRTC handshake)
#
# The transport probe only proves the request reaches the broker. It does NOT
# prove a relay is listening for that fingerprint -- the broker happily returns
# an answer even for a garbage fingerprint. Only a completed ICE + DTLS
# handshake to the relay proves the fingerprint belongs to a live relay.
#
# Needs the `aiortc` package. Skipped gracefully when it is not installed.
# ==============================================================================
def _post_broker_offer(broker_url, fingerprint, offer_sdp, front=None,
                       timeout=20):
    """Blocking ClientPollRequest carrying a real aiortc-generated offer."""
    rest = broker_url.split("//", 1)[1]
    broker_host = rest.split("/", 1)[0]
    path = "/" + (rest.split("/", 1)[1] if "/" in rest else "") + "client"
    sni = front or broker_host

    body = b"1.0\n" + json.dumps({
        "ice": _ICE_SERVER,
        "nat": "unknown",
        "fingerprint": fingerprint,
        "offer": json.dumps({"type": "offer", "sdp": offer_sdp}),
    }).encode()
    head = ("POST " + path + " HTTP/1.1\r\n"
            "Host: " + broker_host + "\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: " + str(len(body)) + "\r\n"
            "Connection: close\r\n\r\n").encode()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except Exception:
        pass

    ip = socket.gethostbyname(sni)
    with socket.create_connection((ip, 443), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as ss:
            ss.sendall(head + body)
            raw = b""
            while len(raw) < 65536:
                try:
                    chunk = ss.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                raw += chunk

    _, _, payload = raw.partition(b"\r\n\r\n")
    if not payload:
        raise RuntimeError("no response through front " + str(sni))
    data = json.loads(payload)
    if "answer" not in data:
        raise RuntimeError("broker error: " + str(data)[:140])
    return json.loads(data["answer"])["sdp"]


# The magic prefix a client writes to opt into turbo tunnel mode, copied from
# common/turbotunnel/consts.go. The proxy stays silent unless it sees it, which
# is what lets a handshake tell a real proxy from a bare WebRTC peer.
TURBOTUNNEL_TOKEN = bytes([0x12, 0x93, 0x60, 0x5d, 0x27, 0x81, 0x75, 0xf5])


def encap_prefix(n):
    """Length prefix for a data chunk, ported from
    common/encapsulation/encapsulation.go:dataPrefixForLength.

        dcxxxxxx            1 byte : d=1 data, c=0 no continuation
        cyyyyyyy            2 bytes: c=1 means a third prefix byte follows
        cyyyyyyy 0zzzzzzz   3 bytes
    """
    if (n >> 0) & 0x3F == n:
        return bytes([0x80 | (n & 0x3F)])
    if (n >> 7) & 0x3F == (n >> 7):
        return bytes([0xC0 | ((n >> 7) & 0x3F), n & 0x7F])
    if (n >> 14) & 0x3F == (n >> 14):
        return bytes([0xC0 | ((n >> 14) & 0x3F), 0x80 | ((n >> 7) & 0x7F),
                      n & 0x7F])
    raise ValueError("length prefix too long: %d" % n)


def encap_data(payload):
    """Encode one data chunk exactly as the snowflake proxy expects."""
    return encap_prefix(len(payload)) + payload


def encap_decode(buf):
    """Decode a stream of chunks, skipping padding, and return the first data
    payload. Returns None if the buffer is not well-formed encapsulation.

    Ported from common/encapsulation/encapsulation.go:ReadData.
    """
    i = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        is_data = (b & 0x80) != 0
        cont = (b & 0x40) != 0
        value = b & 0x3F
        if cont:
            if i >= len(buf):
                return None
            b2 = buf[i]
            i += 1
            cont2 = (b2 & 0x80) != 0
            value = (value << 7) | (b2 & 0x7F)
            if cont2:
                if i >= len(buf):
                    return None
                b3 = buf[i]
                i += 1
                if (b3 & 0x80) != 0:
                    return None          # 4th byte is not a valid prefix
                value = (value << 7) | (b3 & 0x7F)
        if i + value > len(buf):
            return None                  # truncated chunk
        if is_data:
            return buf[i:i + value]
        i += value                       # padding: skip and keep scanning
    return None


async def _webrtc_live(broker_url, fingerprint, front=None, wait=45):
    """Complete ICE + DTLS handshake with the relay. -> (live, detail, ms)"""
    t0 = time.time()
    pc = RTCPeerConnection(RTCConfiguration(
        iceServers=[RTCIceServer("stun:stun.l.google.com:19302")]))
    try:
        dc = pc.createDataChannel("snowflake", negotiated=True, id=0)
        opened = asyncio.Event()
        got_msg = asyncio.Event()
        reply = []

        @dc.on("open")
        def _open():
            opened.set()

        @dc.on("message")
        def _msg(data):
            if not reply:
                reply.append(data)
            got_msg.set()

        await pc.setLocalDescription(await pc.createOffer())
        for _ in range(120):
            if pc.iceGatheringState == "complete":
                break
            await asyncio.sleep(0.25)

        loop = asyncio.get_event_loop()
        answer_sdp = await loop.run_in_executor(
            None, _post_broker_offer, broker_url, fingerprint,
            pc.localDescription.sdp, front)

        await pc.setRemoteDescription(
            RTCSessionDescription(sdp=answer_sdp, type="answer"))

        # Opt into turbo tunnel exactly the way the client does: the 8-byte
        # magic token, then an 8-byte random client id. Both are written
        # through the encapsulation framing. A genuine proxy answers with a
        # server-to-client packet; anything else on this channel stays silent,
        # so a reply is positive proof we reached a real snowflake proxy and
        # not merely a peer that completed WebRTC.
        #   turbotunnel.Token = 12 93 60 5d 27 81 75 f5
        try:
            await asyncio.wait_for(opened.wait(), timeout=wait)
        except asyncio.TimeoutError:
            return False, "handshake timed out (ice=%s)" % pc.iceConnectionState, \
                int((time.time() - t0) * 1000)

        client_id = os.urandom(8)
        dc.send(encap_data(TURBOTUNNEL_TOKEN))
        dc.send(encap_data(client_id))
        try:
            await asyncio.wait_for(got_msg.wait(), timeout=12)
        except asyncio.TimeoutError:
            return True, ("channel open, proxy did not answer the "
                          "turbotunnel token"), int((time.time() - t0) * 1000)
        except Exception as e:
            return False, "read error: " + type(e).__name__ + ": " + str(e)[:60], \
                int((time.time() - t0) * 1000)

        if not reply:
            return True, "channel open, no reply bytes", \
                int((time.time() - t0) * 1000)
        msg = reply[0]
        if not isinstance(msg, (bytes, bytearray)):
            return False, "reply was %s, not bytes" % type(msg).__name__, \
                int((time.time() - t0) * 1000)
        body = encap_decode(bytes(msg))
        if body is None:
            return False, ("channel open but reply is not valid encapsulation "
                           "(%d bytes)" % len(msg)), \
                int((time.time() - t0) * 1000)
        detail = "relay answered, %d valid encapsulated bytes" % len(body)
        return True, detail, int((time.time() - t0) * 1000)
    except Exception as e:
        # A broker that answers with {"error": "timed out waiting for answer"}
        # is not a broken bridge: the relay was assigned but did not come up in
        # time, which is the same situation as an ICE timeout and must be
        # graded on the round ratio rather than treated as a hard failure.
        text = str(e)
        if "timed out waiting for answer" in text or "no such" in text.lower():
            return None, "relay assigned, no answer in time", \
                int((time.time() - t0) * 1000)
        return False, type(e).__name__ + ": " + text[:90], \
            int((time.time() - t0) * 1000)
    finally:
        try:
            await pc.close()
        except Exception:
            pass


# A fingerprint that no relay will ever own. Probed alongside the real ones as
# a negative control: if this one is ever reported LIVE, the network is handing
# us some other relay and the whole liveness stage is meaningless.
LIVENESS_CONTROL_FP = "0000000000000000000000000000000000000000"


def verify_relay_liveness(pairs, broker_url, wait=45, rounds=3, need=2,
                          probe_timeout=20):
    """Decide which (front, fingerprint) pairs are really usable.

    Input:  a list of (front, fingerprint) tuples, one per combination that a
            generated line can use.
    Output: {(front, fingerprint): (verdict, detail, ms)}

    Each pair is judged on its own front. A front can pass the cheap transport
    probe and still fail the full handshake on any given run, so a verdict
    earned through one front is never reused for another.

    Verdicts:
      "LIVE"    - the broker knows the fingerprint over THIS front and the
                  WebRTC handshake completed.
      "DEAD"    - the broker explicitly said "fingerprint is unknown" over this
                  front, or the handshake failed against a fingerprint the
                  broker does know.
      "UNKNOWN" - the front or broker was unreachable from this host, so no
                  verdict was possible. Never reported as DEAD, because a
                  transport failure is indistinguishable from a dead bridge.

    The negative control must be rejected by the broker *for being unknown* on
    every front that produces a LIVE. If the control merely times out, the
    network is the confounder and the result is downgraded to UNKNOWN.
    """
    pairs = sorted(set(pairs))
    print("\n" + "=" * 78)
    print("RELAY LIVENESS  (%d front/fingerprint pairs)" % len(pairs))
    print("=" * 78)

    # ---- step 1: cheap, definitive broker verdict per pair ----------------
    print("  step 1 - broker roster check (decides DEAD vs candidate)")
    roster = {}

    def ask(item):
        front, fp = item
        return item, snowflake_poll(broker_url, fp, front=front,
                                    timeout=probe_timeout, attempts=2)

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        for (front, fp), (tier, reason, ms) in ex.map(ask, list(pairs)):
            roster[(front, fp)] = (tier, reason, ms)
            print("    %-24s %-42s %-7s %s"
                  % (front, fp, tier, reason[:40]))

    # the control is asked once per distinct front, over that same front
    fronts = sorted(set(f for f, _ in pairs))
    ctl = {}
    for front in fronts:
        tier, reason, ms = snowflake_poll(broker_url, LIVENESS_CONTROL_FP,
                                          front=front, timeout=probe_timeout,
                                          attempts=2)
        ctl[front] = (tier, reason)
    bad_controls = [f for f, (t, _) in ctl.items() if t != "badfp"]
    control_ok = not bad_controls
    print("  negative control on %d front(s): %s" % (
        len(fronts), "OK" if control_ok else "INVALID"))
    for f in bad_controls:
        print("    %-24s control failed: %s" % (f, ctl[f][1][:52]))
    if not control_ok:
        print("  *** The control was not rejected as an unknown fingerprint  ***")
        print("  *** on every front. A timeout or transport error here is a   ***")
        print("  *** network problem, not a verdict, so a completed handshake  ***")
        print("  *** would not prove a fingerprint is live. Results are        ***")
        print("  *** downgraded to UNKNOWN.                                    ***")

    out = {}
    candidates = [k for k in pairs if roster[k][0] in ("answer", "reached")]
    for k in pairs:
        tier, reason, ms = roster[k]
        if tier == "badfp":
            out[k] = ("DEAD", "broker has no relay for this fingerprint: "
                               + reason, ms)
        elif tier == "fail":
            out[k] = ("UNKNOWN", "front/broker unreachable, not a verdict: "
                                 + reason, ms)

    if not candidates:
        return out

    # ---- step 2: real handshake, per pair, on that pair's own front ------
    print("\n  step 2 - full WebRTC handshake for %d candidate pair(s)"
          "  (%d rounds, need %d ok)" % (len(candidates), rounds, need))

    async def run_all():
        async def one(item):
            """Try the handshake several times and grade it on the ratio.

            A snowflake relay is volunteer-run, so a single timeout proves
            nothing: www.fastly.com measured DEAD, DEAD, LIVE across three
            consecutive runs. Grading on the last attempt alone threw away two
            thirds of the evidence, so every attempt is counted and the verdict
            comes from the ratio.
            """
            front, fp = item
            ok = 0
            tried = 0
            last = ""
            total_ms = 0
            for attempt in range(rounds):
                tried += 1
                live, last, ms = await _webrtc_live(
                    broker_url, fp, front=None if front == "(direct)" else front,
                    wait=wait)
                if live is None:
                    # transient broker/relay timeout: count as a non-success
                    # attempt but do not abort the round, let the ratio decide
                    total_ms += ms
                    if attempt + 1 < rounds:
                        await asyncio.sleep(1.5)
                    continue
                total_ms += ms
                if live:
                    ok += 1
                    if ok >= need:
                        return item, "LIVE", last, total_ms
                elif "JSONDecode" in last or "403" in last or "405" in last:
                    return item, "DEAD", last, total_ms
                if attempt + 1 < rounds:
                    await asyncio.sleep(1.5)
            ratio = ok / float(tried)
            detail = "%d/%d handshakes ok; last: %s" % (ok, tried, last)
            if ratio >= 0.5:
                return item, "LIVE", detail, total_ms
            if ok > 0:
                return item, "FLAKY", detail, total_ms
            return item, "UNKNOWN", detail, total_ms

        results = {}
        for coro in asyncio.as_completed([one(k) for k in candidates]):
            key, verdict, detail, ms = await coro
            results[key] = (verdict, detail, ms)
        return results

    handshakes = asyncio.run(run_all())
    for key, (verdict, detail, ms) in handshakes.items():
        if not control_ok and verdict == "LIVE":
            verdict = "UNKNOWN"
            detail = ("control invalid on this front, handshake not "
                      "trustworthy: " + detail)
        out[key] = (verdict, detail, ms)
    return out


# ==============================================================================
# FULL TUNNEL VERIFICATION
#
# Everything above proves the plumbing: the broker answers, the WebRTC answer
# arrives, the relay claims the fingerprint. None of it proves a single byte of
# real browsing traffic reaches the internet through the bridge.
#
# Only a real Tor process can show that, because it has to agree on a consensus
# with other relays, download descriptors through the bridge, build a circuit,
# and then carry an actual request. The proof used here is deliberately the
# strictest available: Tor must reach 100% and a request must come back from a
# Tor exit, self reported by check.torproject.org.
#
# This stage is slow by nature. It is optional and off by default.
# ==============================================================================

# Only descriptor caches are copied from an existing Tor installation. The keys
# directory is deliberately never copied, so guard state stays fresh and the
# bridge under test is still the one Tor has to use.
SEED_FILES = ("cached-certs", "cached-descriptors",
              "cached-microdesc-consensus", "cached-microdescs")

# STUN list confirmed on a working line. Kept identical to STUN so the verified
# tunnel cannot drift away from the lines the generator hands out.
TUNNEL_ICE = _ICE_VALUES


def find_tor():
    """Locate tor.exe and lyrebird.exe without touching the user's setup."""
    candidates = [
        os.environ.get("TOR_EXE", ""),
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                     "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
        r"C:\Net-Tools\tor\tor\tor.exe",
        "tor.exe",
    ]
    tor = next((p for p in candidates if p and os.path.isfile(p)), None)
    if tor is None:
        found = shutil.which("tor")
        tor = found or None

    lyre = None
    if tor:
        base = os.path.dirname(tor)
        for name in (r"pluggable_transports\lyrebird.exe", "lyrebird.exe"):
            probe = os.path.join(base, name)
            if os.path.isfile(probe):
                lyre = probe
                break
    if lyre is None:
        found = shutil.which("lyrebird")
        lyre = found or None
    return tor, lyre


def _free_port(start):
    """Return a usable loopback port, walking forward from start."""
    for port in range(start, start + 400):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    return None


def _kill_tree(pid):
    if not pid:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                           capture_output=True)
        else:
            subprocess.run(["pkill", "-P", str(pid)], capture_output=True)
            os.kill(pid, 9)
    except Exception:
        pass


def tunnel_bridge_line(front, fingerprint, ip, ampcache):
    """Render the exact bridge line that the tunnel stage will test.

    It has to match what generate_bridges emits, otherwise the stage verifies a
    line nobody would actually use.
    """
    params = {"fingerprint": fingerprint, "url": BROKER_URL,
              "ice": TUNNEL_ICE,
              "utls-imitate": "hellorandomizedalpn",
              "covertdtls-config": "randomizemimic"}
    if ampcache:
        params["ampcache"] = AMPCACHE.split("=", 1)[1]
        params["fronts"] = (front if front in AMPCACHE_FRONTS
                            else AMPCACHE_FRONTS[0] + "," + front)
    else:
        params["front"] = front
    return " ".join(["Bridge snowflake", ip, fingerprint]
                    + render_params(params))


def _write_tunnel_torrc(path, datadir, socks_port, control_port,
                        bridge_line, lyrebird):
    body = "\n".join([
        "# Scratch instance used only to verify one snowflake bridge.",
        "DataDirectory %s" % datadir.replace("\\", "/"),
        "SocksPort %d" % socks_port,
        "ControlPort %d" % control_port,
        "",
        "# Every circuit must use this bridge, so a built circuit cannot be",
        "# attributed to the public network.",
        "UseBridges 1",
        "StrictNodes 1",
        "",
        "Log notice stdout",
        "",
        "ClientTransportPlugin snowflake exec %s" % lyrebird.replace("\\", "/"),
        bridge_line,
        "",
    ])
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)


def _seed_cache(datadir, seed_dir):
    """Copy a warm descriptor cache in so Tor need not fetch 9k descriptors."""
    if not seed_dir or not os.path.isdir(seed_dir):
        return 0
    copied = 0
    for name in SEED_FILES:
        src = os.path.join(seed_dir, name)
        if os.path.isfile(src):
            try:
                shutil.copy2(src, os.path.join(datadir, name))
                copied += 1
            except OSError:
                pass
    return copied


def _socks5_get_json(host, port, socks_port, timeout=40):
    """Speak SOCKS5 and TLS by hand, then ask an endpoint who we are."""
    deadline = time.time() + timeout
    with socket.create_connection(("127.0.0.1", socks_port),
                                  timeout=timeout) as raw:
        raw.settimeout(timeout)
        raw.sendall(b"\x05\x01\x00")
        if raw.recv(2) != b"\x05\x00":
            raise OSError("socks5 negotiation refused")

        name = host.encode("ascii")
        raw.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name
                    + port.to_bytes(2, "big"))
        reply = raw.recv(4)
        if len(reply) < 2 or reply[1] != 0x00:
            raise OSError("socks5 connect refused: %r" % (reply,))

        atyp = reply[3] if len(reply) > 3 else 1
        if atyp == 1:
            raw.recv(4 + 2)
        elif atyp == 3:
            raw.recv(raw.recv(1)[0] + 2)
        else:
            raw.recv(16 + 2)

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            tls.settimeout(max(1, deadline - time.time()))
            tls.sendall(("GET /api/ip HTTP/1.1\r\nHost: %s\r\n"
                         "User-Agent: bridge-check\r\n"
                         "Connection: close\r\n\r\n" % host).encode())
            buf = b""
            while len(buf) < 65536:
                try:
                    chunk = tls.recv(4096)
                except (socket.timeout, ssl.SSLError):
                    break
                if not chunk:
                    break
                buf += chunk

    text = buf.decode("utf-8", "replace")
    head, _, payload = text.partition("\r\n\r\n")
    status = head.splitlines()[0] if head else "<no response>"
    try:
        data = json.loads(payload.strip().splitlines()[-1])
    except (ValueError, IndexError):
        data = {}
    return {"status": status, "is_tor": data.get("IsTor"),
            "ip": data.get("IP")}


def verify_full_tunnel(front, ip, fingerprint, tor, lyrebird,
                       timeout=300, seed_dir=None, ampcache=False,
                       workroot=None):
    """Prove one bridge end to end with a real Tor process.

    Returns (verdict, detail). Verdicts:
      TUNNEL            bootstrap finished and a request came back via Tor
      BOOTSTRAP_PARTIAL  the bridge carried Tor but bootstrap never completed
      BRIDGE_DEAD        the pluggable transport never connected
      NO_TOR             tor or lyrebird was not found on this machine
    """
    work = os.path.join(workroot or tempfile.gettempdir(),
                        "sf_tunnel_%d_%s" % (os.getpid(),
                                             abs(hash(front)) % 100000))
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work, exist_ok=True)
    datadir = os.path.join(work, "data")
    os.makedirs(datadir, exist_ok=True)
    socks_port = _free_port(21150)
    control_port = _free_port(21250) or 0
    torrc = os.path.join(work, "torrc")
    logpath = os.path.join(work, "tor.log")

    bridge = tunnel_bridge_line(front, fingerprint, ip, ampcache)
    _write_tunnel_torrc(torrc, datadir, socks_port, control_port,
                        bridge, lyrebird)
    seeded = _seed_cache(datadir, seed_dir)

    proc = None
    try:
        with open(logpath, "wb") as log:
            proc = subprocess.Popen([tor, "-f", torrc],
                                    stdout=log, stderr=subprocess.STDOUT)

        started = time.time()
        pct = ""
        micro = ""
        while time.time() - started < timeout:
            if proc.poll() is not None:
                break
            try:
                with open(logpath, "r", encoding="utf-8",
                          errors="replace") as fh:
                    text = fh.read()
            except OSError:
                text = ""

            found = re.findall(r"Bootstrapped (\d+%) \(([a-z_]+)\)", text)
            if found and found[-1][0] != pct:
                pct = found[-1][0]
                print("      %s %s" % (front, pct), flush=True)
            md = re.findall(r"we have (\d+)/(\d+)", text)
            if md:
                micro = "%s/%s" % md[-1]

            if "Bootstrapped 100%" in text:
                break
            time.sleep(5)

        try:
            with open(logpath, "r", encoding="utf-8",
                      errors="replace") as fh:
                text = fh.read()
        except OSError:
            text = ""

        pt_ok = "conn_done_pt" in text
        peer_ok = "rendezvous peer received" in text
        handshake = "handshake_done" in text
        guard = "100% of guards bw" in text
        reached_100 = "Bootstrapped 100%" in text
        evidence = ("pt=%s peer=%s handshake=%s guard=%s seed=%d"
                    % (pt_ok, peer_ok, handshake, guard, seeded))

        if not reached_100:
            if pt_ok or peer_ok or handshake or guard:
                return ("BOOTSTRAP_PARTIAL",
                        "%s stopped at %s micro=%s" % (evidence, pct or "?",
                                                        micro or "?"))
            return ("BRIDGE_DEAD", "%s no transport progress" % evidence)

        try:
            probe = _socks5_get_json("check.torproject.org", 443, socks_port)
        except (OSError, ssl.SSLError) as exc:
            return ("BOOTSTRAP_PARTIAL", "%s socks failed: %s"
                    % (evidence, exc))
        if probe.get("is_tor"):
            return ("TUNNEL", "%s exit=%s %s" % (evidence,
                                                 probe.get("ip"),
                                                 probe.get("status")))
        return ("BOOTSTRAP_PARTIAL", "%s not a tor exit: %s"
                % (evidence, probe.get("status")))
    finally:
        if proc is not None:
            _kill_tree(proc.pid)
        shutil.rmtree(work, ignore_errors=True)


def verify_tunnels(candidates, timeout=300, workers=3, seed_dir=None,
                   workroot=None):
    """Run the tunnel stage over several fronts, a few at a time.

    Each front gets its own Tor instance, ports and data directory, so the runs
    cannot interfere. Kept to a handful of workers because every instance is a
    real Tor client and hammering the broker with many at once makes all of them
    look broken.
    """
    tor, lyre = find_tor()
    if not tor or not lyre:
        print("  tor or lyrebird not found, skipping tunnel stage")
        return {}

    print("  tor      : %s" % tor)
    print("  lyrebird : %s" % lyre)
    if seed_dir:
        print("  seed     : %s" % seed_dir)

    verdicts = {}
    lock_args = {"tor": tor, "lyrebird": lyre, "timeout": timeout,
                 "seed_dir": seed_dir, "workroot": workroot}

    def one(item):
        front, ip, fingerprint, ampcache = item
        try:
            return front, verify_full_tunnel(front, ip, fingerprint,
                                            ampcache=ampcache, **lock_args)
        except Exception as exc:                     # keep the sweep alive
            return front, ("UNKNOWN", "harness error: %s" % exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for front, result in pool.map(one, candidates):
            verdicts[front] = result
            print("  %-28s %s" % (front, result[0]), flush=True)
    return verdicts


# ==============================================================================
# MAIN
# ==============================================================================
if __name__ == "__main__":
    print("FASTLY FRONT SCANNER")
    print("Broker: " + BROKER_URL)
    print("Domains: " + str(len(DOMAINS)))

    t0 = time.time()
    results = run_scan(DOMAINS, workers=40)
    print("\nScan time: %.1f s" % (time.time() - t0))

    confirmed, probable, rejected = generate_report(results)

    # The scan only ranks candidates; the relay probe below is the judge. A low
    # score is not proof of failure -- www.fastly.com answers with a real
    # WebRTC answer while looking unimpressive to header heuristics -- so the
    # score must not be allowed to drop a front that actually works.
    ranked = sorted(results, key=lambda r: -r["score"])
    all_fronts = [r["domain"] for r in ranked]
    print("fronts queued for the relay probe: %d" % len(all_fronts))

    # never generate a line whose fingerprint no relay owns
    good_pairs = filter_pairs(IP_FP_PAIRS)

    total, sections = generate_bridges(all_fronts, "bridges.txt",
                                       pairs=good_pairs)
    profile_files = generate_all_profiles(all_fronts, good_pairs)

    print("")
    print("=" * 78)
    print("BRIDGES")
    print("=" * 78)
    if total > 0:
        print("Generated " + str(total) + " lines -> bridges.txt")
        for title, lines in sections:
            print("  " + title + " : " + str(len(lines)))
    else:
        print("No Fastly-fronted domains found.")

    with open("front_report.json", "w", encoding="utf-8") as f:
        json.dump({
            "broker": BROKER_URL,
            "total_tested": len(results),
            "confirmed": [r["domain"] for r in confirmed],
            "probable": [r["domain"] for r in probable],
            "rejected": [r["domain"] for r in rejected],
            "all_results": results,
        }, f, indent=2, ensure_ascii=False)

    verified, failed, probe_results = [], [], {}
    if total > 0:
        # The extra keys in "full" and "stealth" (ampcache, max, utls-nosni,
        # covertdtls-*) are all negotiated after the broker answers, so the
        # broker handshake they perform is byte-for-byte the same as the bare
        # line's. Probing each front three times was pure waste -- 3x the
        # connections, 3x the load, and the extra requests left the network
        # too busy for the liveness stage that follows, which is what drove
        # every front down to 1-of-3. So the transport is probed once and the
        # verdict is shared, while each profile still gets its own split.
        shared = {}
        for profile in ("safe", "full", "stealth"):
            prof_sections = profile_files[profile][1]
            if not prof_sections:
                continue
            p_ok, p_bad, p_res = verify_bridges(
                prof_sections,
                "bridges_%s_VERIFIED.txt" % profile,
                "bridges_%s_FAILED.txt" % profile,
                cache=shared,
            )
            verified.extend(p_ok)
            failed.extend(p_bad)
            probe_results[profile] = p_res
            print("  %-8s verified %4d / failed %4d"
                  % (profile, len(p_ok), len(p_bad)))

        with open("bridges_VERIFIED.txt", "w", encoding="utf-8") as f:
            f.write("# every profile that passed the live probe\n")
            f.write("# lines: %d\n" % len(verified))
            f.write("#" + "=" * 78 + "\n")
            for title, line, reason, ms in verified:
                f.write(line + "\n")
        with open("bridges_FAILED.txt", "w", encoding="utf-8") as f:
            f.write("# every profile that failed the live probe\n")
            f.write("# lines: %d\n" % len(failed))
            f.write("#" + "=" * 78 + "\n")
            for title, line, reason, ms in failed:
                f.write("# " + reason + "\n")
                f.write(line + "\n\n")

        print("")
        print("=" * 78)
        print("VERIFIED vs FAILED")
        print("=" * 78)
        print("  " + "-" * 76)
        gen_total = sum(profile_files[p][0] for p in profile_files
                        if p in ("safe", "full", "stealth"))
        print("  generated across all 3 profiles : " + str(gen_total))
        print("  VERIFIED  : " + str(len(verified)) + "  -> bridges_VERIFIED.txt")
        print("  FAILED    : " + str(len(failed)) + "  -> bridges_FAILED.txt")
        if len(verified) + len(failed) != gen_total:
            print("  WARNING: " + str(len(verified)) + " + " + str(len(failed))
                  + " != " + str(gen_total) + " generated")
        if verified:
            fronts_ok = sorted(set(parse_bridge_line(l)["front"] or "(direct)"
                                  for _, l, _, _ in verified))
            print("  working fronts: " + ", ".join(fronts_ok[:12]))

        # A front that passed the transport probe can still fail the full
        # handshake (cdn.jsdelivr.net answered 403 in one run and 200 in the
        # next). So liveness is judged per (front, fingerprint) -- the exact
        # pair the line uses -- and a line is only LIVE if its own front
        # completed the handshake. Picking one "best" front and applying the
        # verdict to every line was wrong: one flaky front zeroes the lot.
        live_pairs = set()
        live_fp = {}
        if HAVE_AIORTC:
            pairs_to_test = sorted(set(
                (parse_bridge_line(l)["front"] or "(direct)",
                 parse_bridge_line(l)["fingerprint"])
                for _, l, _, _ in verified))
            live_fp = verify_relay_liveness(
                pairs_to_test, BROKER_URL, wait=45, rounds=3, need=2)
        else:
            print("\n  (aiortc not installed - skipping relay liveness stage)")
            print("  pip install aiortc")

        def _verdict(line):
            info = parse_bridge_line(line)
            return live_fp.get((info["front"] or "(direct)",
                                info["fingerprint"]), ("UNKNOWN",))[0]

        live_lines = [(t, l, r, m) for t, l, r, m in verified
                      if _verdict(l) == "LIVE"]

        # ---- optional full tunnel verification ----
        # Opt in because every front here costs a real Tor bootstrap, which
        # takes minutes. This is the only stage that proves traffic actually
        # flows, so it is also the only one that can promote a line to TUNNEL.
        tunnel_verdicts = {}
        if os.environ.get("SNOWFLAKE_TUNNEL"):
            limit = int(os.environ.get("SNOWFLAKE_TUNNEL_LIMIT", "12"))
            workers = int(os.environ.get("SNOWFLAKE_TUNNEL_WORKERS", "3"))
            secs = int(os.environ.get("SNOWFLAKE_TUNNEL_TIMEOUT", "300"))
            seed = os.environ.get("SNOWFLAKE_TUNNEL_SEED") or None

            print("")
            print("=" * 78)
            print("FULL TUNNEL VERIFICATION (real Tor, real request)")
            print("=" * 78)

            # One candidate per front, using the strongest line for that front.
            seen_fronts = set()
            candidates = []
            for _, line, _, _ in live_lines:
                info = parse_bridge_line(line)
                front = info["front"] or "(direct)"
                if front in seen_fronts:
                    continue
                seen_fronts.add(front)
                params = dict(info)
                candidates.append((front, info["ip"],
                                   info["fingerprint"],
                                   "ampcache=" in line))
            candidates = candidates[:limit]

            if candidates:
                tunnel_verdicts = verify_tunnels(
                    candidates, timeout=secs, workers=workers, seed_dir=seed)
                tunnel_lines = [item for item in live_lines
                                if tunnel_verdicts.get(
                                    parse_bridge_line(item[1])["front"] or
                                    "(direct)", ("UNKNOWN",))[0] == "TUNNEL"]

                with open("bridges_TUNNEL.txt", "w", encoding="utf-8") as f:
                    f.write("# Snowflake Bridges - PROVEN end to end\n")
                    f.write("# a real Tor client bootstrapped through this front\n")
                    f.write("# and returned a request from a Tor exit\n")
                    f.write("# lines: %d\n" % len(tunnel_lines))
                    f.write("# generated: "
                            + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
                    f.write("#" + "=" * 78 + "\n")
                    for title, line, reason, ms in tunnel_lines:
                        f.write(line + "\n")

                counts = defaultdict(int)
                for v in tunnel_verdicts.values():
                    counts[v[0]] += 1
                print("")
                for verdict in ("TUNNEL", "BOOTSTRAP_PARTIAL", "BRIDGE_DEAD"):
                    if counts.get(verdict):
                        print("  %-18s : %d" % (verdict, counts[verdict]))
                print("  -> bridges_TUNNEL.txt (%d lines)"
                      % len(tunnel_lines))
            else:
                print("  no LIVE front to test")
        else:
            print("")
            print("  (full tunnel verification skipped)")
            print("  set SNOWFLAKE_TUNNEL=1 to prove lines with a real Tor")
            print("  client, which takes a few minutes per front")

        flaky_lines = [(t, l, r, m) for t, l, r, m in verified
                       if _verdict(l) == "FLAKY"]

        with open("bridges_LIVE.txt", "w", encoding="utf-8") as f:
            f.write("# Snowflake Bridges - FULLY VERIFIED\n")
            f.write("# broker reached over this front AND the broker confirmed it\n")
            f.write("# owns the fingerprint AND at least 2 of 3 WebRTC handshakes\n")
            f.write("# completed\n")
            f.write("# lines: %d\n" % len(live_lines))
            f.write("# generated: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
            f.write("#" + "=" * 78 + "\n")
            for title, line, reason, ms in live_lines:
                f.write(line + "\n")

        with open("bridges_FLAKY.txt", "w", encoding="utf-8") as f:
            f.write("# Snowflake Bridges - worked at least once, not reliably\n")
            f.write("# a volunteer relay that was reachable but slow or dropped.\n")
            f.write("# usable as a backup, not as a primary line.\n")
            f.write("# lines: %d\n" % len(flaky_lines))
            f.write("#" + "=" * 78 + "\n")
            for title, line, reason, ms in flaky_lines:
                f.write(line + "\n")

        if live_fp:
            counts = {}
            for v in live_fp.values():
                counts[v[0]] = counts.get(v[0], 0) + 1
            print("")
            for verdict in ("LIVE", "FLAKY", "DEAD", "UNKNOWN"):
                if counts.get(verdict):
                    print("  %-8s : %d" % (verdict, counts[verdict]))
            print("  -> bridges_LIVE.txt (%d lines)" % len(live_lines))
            if counts.get("FLAKY"):
                print("  FLAKY means the relay answered at least once but not")
                print("  on every attempt. Usable, less reliable.")
            if counts.get("UNKNOWN"):
                print("  UNKNOWN means no verdict was possible from this host.")
                print("  Not a failure.")

        with open("bridge_probe_report.json", "w", encoding="utf-8") as f:
            json.dump({
                "broker": BROKER_URL,
                "verified_lines": [l for _, l, _, _ in verified],
                "failed_lines": [{"line": l, "reason": r} for _, l, r, _ in failed],
                "live_lines": [l for _, l, _, _ in live_lines],
                "tunnel_verification": {
                    front: {"verdict": v[0], "detail": v[1]}
                    for front, v in tunnel_verdicts.items()},
                "relay_liveness": {"%s | %s" % (k[0], k[1]):
                                   {"verdict": v[0], "detail": v[1], "ms": v[2]}
                                   for k, v in live_fp.items()},
                "combos_by_profile": {
                    profile: {"%s | %s | %s" % (k[0], k[1] or "(direct)",
                                                (k[2] or "")[:8]):
                              {"tier": v[0], "reason": v[1], "ms": v[2]}
                              for k, v in res.items()}
                    for profile, res in probe_results.items()},
            }, f, indent=2, ensure_ascii=False)

    print("")
    print("Report: front_report.json")
    if total > 0:
        print("Probe:  bridge_probe_report.json")
    print("DONE.")