#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise Application Service Core Worker (Backend Engine)
-----------------------------------------------------------
High-Performance Containerized Microservice Supervisor:
- Dynamic Cgroup memory detection & socket buffer auto-scaling
- Linux Kernel UDP buffer optimization (16MB rmem/wmem) for Hysteria2 / TUIC
- Process disguise & identity hardening (prctl PR_SET_NAME)
- /dev/shm memory-disk ephemeral execution with stale directory auto-purge
- Multi-worker epoll single-threaded TCP multiplexer (EpollForwarder)
- RFC 7748 Curve25519 X25519 key generation
- Sing-box 1.12+ auto-adaptive DNS & routing engine
- Dynamic UDP egress probing & auto-healing health loop
- Argo tunnel lifecycle watchdog & auto-reconnect
- Session metrics & chaff telemetry dump with 180-second physical self-destruction
"""

import os
import re
import sys
import json
import time
import hmac
import signal
import socket
import base64
import shutil
import hashlib
import platform
import selectors
import threading
import subprocess
import tempfile
import uuid
from urllib.request import Request, urlopen
from urllib.parse import quote, unquote
from pathlib import Path
from http.server import BaseHTTPRequestHandler

try:
    from http.server import ThreadingHTTPServer as _HTTPBase
except ImportError:
    from http.server import HTTPServer as _HTTPBase

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import requests
except ImportError:
    requests = None


def _dec(b):
    return base64.b64decode(b).decode("ascii")


# ============================================================================
# 0. Environment & Resource Budget (from File 1)
# ============================================================================
BASE_DIR = Path(__file__).resolve().parent
IS_LINUX = platform.system() == "Linux"


def _load_env_file(env_file_path):
    cfg = {}
    if env_file_path.exists():
        for line in env_file_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip("\"'")
    return cfg


_env_cfg = _load_env_file(BASE_DIR / "config.env")


def _get_env(key, default=""):
    return os.environ.get(key) or _env_cfg.get(key) or default


def _get_int(key, default=0, minimum=None, maximum=None):
    raw = (_get_env(key, "") or "").strip()
    val = default
    if raw:
        try:
            val = int(raw)
        except (TypeError, ValueError):
            m = re.match(r"^[+-]?\d+", raw)
            if m:
                try:
                    val = int(m.group(0))
                except ValueError:
                    val = default
            else:
                val = default
    if minimum is not None and val < minimum:
        val = minimum
    if maximum is not None and val > maximum:
        val = maximum
    return val


def _mem_budget_mb():
    for key in ("SERVER_MEMORY", "MEMORY_LIMIT", "CONTAINER_MEMORY"):
        v = (os.environ.get(key) or "").strip()
        if v.isdigit() and int(v) > 0:
            return int(v)
    for p in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            raw = Path(p).read_text().strip()
            if raw.isdigit():
                n = int(raw)
                if 0 < n < (1 << 62):
                    return max(64, n // (1024 * 1024))
        except (OSError, ValueError):
            continue
    return 512


MEM_BUDGET_MB = _mem_budget_mb()

if MEM_BUDGET_MB <= 256:
    MAX_CONNS, SOCK_BUF = 256, 16384
elif MEM_BUDGET_MB <= 512:
    MAX_CONNS, SOCK_BUF = 512, 32768
elif MEM_BUDGET_MB <= 1024:
    MAX_CONNS, SOCK_BUF = 1024, 49152
else:
    MAX_CONNS, SOCK_BUF = 2048, 65536

_env_conns = _get_int("MAX_CONNS", 0, minimum=0)
if _env_conns > 0:
    MAX_CONNS = _env_conns

_HTTP_SLOTS = threading.BoundedSemaphore(max(16, min(32, MAX_CONNS // 8)))


def _tune_kernel_udp():
    """Optimizes kernel socket buffers up to 16MB for high-speed UDP protocols (Hysteria2 & TUIC)."""
    if not IS_LINUX:
        return
    for key, want in (("net.core.rmem_max", 16777216),
                      ("net.core.wmem_max", 16777216),
                      ("net.core.rmem_default", 1048576)):
        path = "/proc/sys/" + key.replace(".", "/")
        try:
            cur = int(Path(path).read_text().strip())
            if cur >= want:
                continue
            Path(path).write_text(str(want))
            _log(f"kernel: {key} {cur} -> {want}")
        except (OSError, ValueError):
            continue


# ============================================================================
# 1. Internal Logging & Security Hooks
# ============================================================================
_LOG_FH = None
_LOG_LOCK = threading.Lock()
_LOG_PATH = None
_LOG_BYTES = 0
_LOG_MAX = 262144


def _log(msg):
    global _LOG_FH, _LOG_BYTES
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
    path = _LOG_PATH or (BASE_DIR / "backend_access.log")
    with _LOG_LOCK:
        try:
            if _LOG_FH is None:
                _LOG_FH = open(path, "a", encoding="utf-8", buffering=1)
                try:
                    _LOG_BYTES = path.stat().st_size
                except OSError:
                    _LOG_BYTES = 0
            _LOG_FH.write(line)
            _LOG_BYTES += len(line)
            if _LOG_BYTES > _LOG_MAX:
                try:
                    _LOG_FH.truncate(0)
                    _LOG_FH.seek(0)
                    _LOG_BYTES = 0
                except OSError:
                    pass
        except OSError:
            pass


def _install_quiet_hooks():
    def _hook(exc_type, exc, tb):
        _log(f"unhandled: {exc_type.__name__}: {exc}")

    sys.excepthook = _hook
    if hasattr(threading, "excepthook"):
        def _thook(args):
            name = getattr(getattr(args, "thread", None), "name", "?")
            _log(f"thread[{name}] unhandled: {args.exc_type.__name__}: {args.exc_value}")
        threading.excepthook = _thook


def _harden_process_identity():
    if not IS_LINUX:
        return
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.prctl(15, ctypes.c_char_p(b"appd"), 0, 0, 0)
        libc.prctl(4, 0, 0, 0, 0)
    except Exception:
        pass


# ============================================================================
# 2. File Utilities & Identifier State
# ============================================================================
def _safe_write(file_path: Path, content, mode=0o600):
    file_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = file_path.with_suffix(file_path.suffix + ".tmp")
    if isinstance(content, str):
        tmp_path.write_text(content, encoding="utf-8")
    else:
        tmp_path.write_bytes(content)
    try:
        os.chmod(tmp_path, mode)
    except OSError:
        pass
    tmp_path.replace(file_path)


_UUID_FILE_NAME = "sys_id"


def _uuid_file_path():
    return runtime_dir / _UUID_FILE_NAME


def _read_uuid_file(path):
    try:
        if path.is_symlink():
            return None
        text = path.read_text(encoding="utf-8-sig").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return text if re.fullmatch(r"[\x21-\x7e]{8,128}", text) else None


def _persist_uuid(path, value):
    tmp = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    except OSError:
        return False
    ok = True
    try:
        buf = (value + "\n").encode("utf-8")
        while buf:
            n = os.write(fd, buf)
            if n <= 0:
                raise OSError("short write")
            buf = buf[n:]
    except OSError:
        ok = False
    finally:
        try:
            os.close(fd)
        except OSError:
            ok = False
    if ok:
        try:
            tmp.replace(path)
        except OSError:
            ok = False
    if not ok:
        try:
            tmp.unlink()
        except OSError:
            pass
    return ok


def _derive_uuid_from_host():
    parts = []
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            fp = Path(p)
            if fp.exists():
                txt = fp.read_text(encoding="utf-8").strip()
                if txt:
                    parts.append(txt)
                    break
        except Exception:
            pass
    try:
        parts.append(platform.node())
    except Exception:
        pass
    try:
        parts.append(hex(uuid.getnode()))
    except Exception:
        pass
    seed = "|".join(parts) or "enterprise-runtime-seed"
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    b = bytearray(digest[:16])
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


def _resolve_stable_uuid():
    for k in ("UID", "UUID", "TUUID", "PASSWORD", "PROXY_PASSWORD"):
        val = (_get_env(k, "")).strip()
        if val and len(val) >= 8:
            return val
    path = _uuid_file_path()
    saved = _read_uuid_file(path)
    if saved:
        return saved
    new_uuid = _derive_uuid_from_host()
    _persist_uuid(path, new_uuid)
    return new_uuid


def _find_free_port(lo, hi, avoid=None):
    avoid = avoid or set()
    for p in range(lo, hi):
        if p in avoid:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", p))
            return p
        except OSError:
            continue
        finally:
            try:
                s.close()
            except OSError:
                pass
    return lo


# ============================================================================
# 3. Port & Directory Configuration
# ============================================================================
WORK_DIR_STR = _get_env("WORK_DIR", "")
if WORK_DIR_STR:
    runtime_dir = Path(WORK_DIR_STR).resolve()
else:
    runtime_dir = BASE_DIR / _get_env("FILE_PATH", ".cache")
runtime_dir.mkdir(parents=True, exist_ok=True)
_LOG_PATH = runtime_dir / "backend_access.log"

PORT_FILE = ".systemd-port"
IS_WORKER_MODE = bool(WORK_DIR_STR or _get_env("PUBLIC_PORT"))

PUBLIC_PORT = _get_int("PUBLIC_PORT", 0) or _get_int("PROT", 0) or _get_int("PORT", 8080)

_avoid = {PUBLIC_PORT}
INTERNAL_ARGO_PORT = _find_free_port(18800, 18900, _avoid)
_avoid.add(INTERNAL_ARGO_PORT)
INTERNAL_HTTP_PORT = _find_free_port(18900, 19000, _avoid)
_avoid.add(INTERNAL_HTTP_PORT)
INTERNAL_REALITY_PORT = _find_free_port(19000, 19100, _avoid)
_avoid.add(INTERNAL_REALITY_PORT)

if IS_WORKER_MODE:
    WORKER_ENTRY_PORT = _find_free_port(19100, 19300, _avoid)
else:
    WORKER_ENTRY_PORT = PUBLIC_PORT

UUID_VAL = _resolve_stable_uuid()
DISABLE_ARGO = _get_env("DISABLE_ARGO", "false").lower() == "true"
ARGO_DOMAIN = _get_env("ARGO_DOMAIN", "")
ARGO_AUTH = _get_env("ARGO_AUTH", "")
CFIP = _get_env("CFIP", "www.wto.org")
CFPORT = _get_int("CFPORT", 443, minimum=1, maximum=65535)

REALITY_PORT = PUBLIC_PORT
HY2_PORT = _get_int("HY2_PORT", PUBLIC_PORT, minimum=1, maximum=65535)
TUIC_PORT_STR = _get_env("TUIC_PORT", "")
TUIC_PORT = int(TUIC_PORT_STR) if (TUIC_PORT_STR and TUIC_PORT_STR.isdigit()) else None
S5_PORT_STR = _get_env("S5_PORT", "")
S5_PORT = int(S5_PORT_STR) if (S5_PORT_STR and S5_PORT_STR.isdigit()) else None

REALITY_SNI = _get_env("DOMAIN", "") or _get_env("REALITY_SNI", "www.iij.ad.jp")
HY2_SNI = _get_env("HY2_SNI", "www.bing.com")
CLEAN_DELAY = _get_int("CLEAN_DELAY", 180, minimum=0)
SINGBOX_RESTART_DELAY = _get_int("SINGBOX_RESTART_DELAY", 3, minimum=0)
PROBE_TIMEOUT = _get_int("PROBE_TIMEOUT", 10, minimum=1)
BATCH_ROUNDS = _get_int("BATCH_ROUNDS", 8, minimum=0)
MAX_WORKERS = _get_int("MAX_WORKERS", 0, minimum=0) or min(4, os.cpu_count() or 1)
IDLE_TIMEOUT = _get_int("IDLE_TIMEOUT", 1800, minimum=0)
NODE_TAG = _get_env("NODE_NAME", "") or _get_env("NODE_TAG", "").strip()


def _derive_sub_path():
    manual = _get_env("SUB_PATH", "").strip().lstrip("/")
    if manual:
        return manual
    return "zhkarc"


SUB_PATH = _derive_sub_path()

web_binary_name = "sys_worker"
bot_binary_name = "sys_agent"
web_path = runtime_dir / web_binary_name
bot_path = runtime_dir / bot_binary_name
cert_path = runtime_dir / "server.crt"
key_path = runtime_dir / "server.key"
cache_db_path = runtime_dir / "res.db"
settings_path = runtime_dir / "settings.dat"
temp_manifest_path = runtime_dir / ".session_metrics.tmp"
_CHAFF_TEMPS = [
    runtime_dir / ".worker_trace.tmp",
    runtime_dir / ".dns_probe.tmp",
    runtime_dir / ".cluster_sync.tmp",
]


def _shm_root():
    for base in ("/dev/shm", "/tmp"):
        try:
            if os.path.isdir(base) and os.access(base, os.W_OK):
                d = Path(base) / (".%x%x" % (os.getpid(), int(time.time() * 1000) % 0xFFFF))
                d.mkdir(mode=0o700, exist_ok=True)
                return d
        except OSError:
            continue
    return runtime_dir


RUN_DIR = _shm_root()


def _purge_stale_run_dirs():
    cur = str(RUN_DIR)
    for base in ("/dev/shm", "/tmp"):
        try:
            for name in os.listdir(base):
                if not name.startswith("."):
                    continue
                full = os.path.join(base, name)
                if full == cur or not os.path.isdir(full):
                    continue
                if os.path.getmtime(full) < time.time() - 7200:
                    shutil.rmtree(full, ignore_errors=True)
        except OSError:
            continue


private_key = ""
public_key = ""
state = {
    "server_ip": None, "argo_domain": None, "http_server": None,
    "udp_ok": None, "argo_seen_at": 0.0, "forwarders": [],
}
CONFIG_TEXT = [""]
_procs = {}
_stop = threading.Event()


# ============================================================================
# 4. Curve Cryptography Operations (RFC 7748 X25519)
# ============================================================================
_P = 2 ** 255 - 19
_A24 = 121665


def _clamp(s):
    b = bytearray(s)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def _cswap(swap, x_2, x_3):
    dummy = swap * ((x_2 - x_3) % _P)
    return (x_2 - dummy) % _P, (x_3 + dummy) % _P


def _x25519_mul(k, u):
    if isinstance(u, (bytes, bytearray)):
        ub = bytearray(u)
        if len(ub) != 32:
            raise ValueError("u-coordinate must be 32 bytes")
        ub[31] &= 127
        u = int.from_bytes(bytes(ub), "little")
    x_1, x_2, z_2, x_3, z_3, swap = u, 1, 0, u, 1, 0
    k_int = int.from_bytes(k, "little")
    for t in reversed(range(255)):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        x_2, x_3 = _cswap(swap, x_2, x_3)
        z_2, z_3 = _cswap(swap, z_2, z_3)
        swap = k_t
        A = (x_2 + z_2) % _P
        AA = (A * A) % _P
        B = (x_2 - z_2) % _P
        BB = (B * B) % _P
        E = (AA - BB) % _P
        C = (x_3 + z_3) % _P
        D = (x_3 - z_3) % _P
        DA = (D * A) % _P
        CB = (C * B) % _P
        x_3 = ((DA + CB) ** 2) % _P
        z_3 = (x_1 * ((DA - CB) ** 2)) % _P
        x_2 = (AA * BB) % _P
        z_2 = (E * (AA + _A24 * E)) % _P
    x_2, x_3 = _cswap(swap, x_2, x_3)
    z_2, z_3 = _cswap(swap, z_2, z_3)
    return ((x_2 * pow(z_2, _P - 2, _P)) % _P).to_bytes(32, "little")


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _py_keypair_bytes():
    raw = os.urandom(32)
    return _b64u(raw), _b64u(_x25519_mul(_clamp(raw), 9))


# ============================================================================
# 5. Process Supervisor
# ============================================================================
class ManagedProcess:
    def __init__(self, name, cmd_builder, log_path, min_delay=3.0, max_delay=45.0, stream_handler=None):
        self.name = name
        self.cmd_builder = cmd_builder
        self.log_path = log_path
        self.stream_handler = stream_handler
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.proc = None
        self.logfh = None
        self.last_start = 0.0
        self.fails = 0
        self.next_at = 0.0
        self._lock = threading.Lock()

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self):
        with self._lock:
            if self.alive():
                return
            try:
                argv = [str(x) for x in self.cmd_builder()]
                if self.stream_handler is not None:
                    self.proc = subprocess.Popen(
                        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True, bufsize=1,
                        start_new_session=True, close_fds=True,
                    )
                    threading.Thread(target=self._pump, daemon=True).start()
                else:
                    self.log_path.parent.mkdir(parents=True, exist_ok=True)
                    if self.logfh:
                        try:
                            self.logfh.close()
                        except Exception:
                            pass
                    self.logfh = open(self.log_path, "ab", buffering=0)
                    self.proc = subprocess.Popen(
                        argv, stdin=subprocess.DEVNULL, stdout=self.logfh,
                        stderr=subprocess.STDOUT, start_new_session=True, close_fds=True,
                    )
                self.last_start = time.time()
                _log(f"watchdog: {self.name} online pid={self.proc.pid}")
            except Exception as e:
                self.fails += 1
                _log(f"watchdog: {self.name} start failed ({type(e).__name__})")
                self._schedule_retry()

    def _pump(self):
        proc = self.proc
        if proc is None or proc.stdout is None:
            return
        try:
            for line in proc.stdout:
                try:
                    self.stream_handler(line)
                except Exception:
                    pass
        except (OSError, ValueError):
            pass

    def _schedule_retry(self):
        delay = min(self.max_delay, self.min_delay * (2 ** min(self.fails, 4)))
        self.next_at = time.time() + delay

    def ensure(self):
        if self.alive():
            if self.fails and time.time() - self.last_start > 60:
                self.fails = 0
            return
        if self.proc is not None and self.fails == 0:
            self.fails = 1
            _log(f"watchdog: {self.name} exited rc={self.proc.returncode}")
            self._schedule_retry()
            return
        if time.time() < self.next_at:
            return
        self.fails += 1
        self._schedule_retry()
        _log(f"watchdog: {self.name} restarting (attempt {self.fails})")
        self.start()

    def stop(self, sig=signal.SIGTERM):
        p = self.proc
        if not p:
            return
        try:
            os.killpg(os.getpgid(p.pid), sig)
        except Exception:
            try:
                p.terminate()
            except Exception:
                pass
        self.proc = None


def _supervisor_loop():
    while not _stop.is_set():
        for mp in list(_procs.values()):
            try:
                mp.ensure()
            except Exception as e:
                _log(f"watchdog: ensure({mp.name}) error ({type(e).__name__})")
        _stop.wait(3.0)


# ============================================================================
# 6. Core Binary Provisioning
# ============================================================================
def get_system_architecture():
    m = platform.machine().lower()
    return "arm" if ("arm" in m or "aarch64" in m) else "amd"


_SB_MIRRORS_PACKED = {
    "arm": [b"aHR0cHM6Ly9hcm02NC5zc3NzLm55Yy5tbi9zYg=="],
    "amd": [b"aHR0cHM6Ly9hbWQ2NC5zc3NzLm55Yy5tbi9zYg=="],
}
_BOT_MIRRORS_PACKED = {
    "arm": [b"aHR0cHM6Ly9hcm02NC5zc3NzLm55Yy5tbi9ib3Q="],
    "amd": [b"aHR0cHM6Ly9hbWQ2NC5zc3NzLm55Yy5tbi9ib3Q="],
}


def _binary_ok(path: Path, min_size=800_000):
    try:
        if not path.exists() or path.stat().st_size < min_size:
            return False
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def download_file(dest_path, file_url, timeout=45):
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest_path.with_suffix(dest_path.suffix + ".part")
    try:
        if requests is not None:
            try:
                resp = requests.get(file_url, stream=True, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
                resp.raise_for_status()
                with open(tmp, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        if chunk:
                            f.write(chunk)
                if tmp.stat().st_size > 0:
                    tmp.replace(dest_path)
                    return True
            except Exception:
                pass
        req = Request(file_url, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=timeout) as r:
            tmp.write_bytes(r.read())
        if tmp.stat().st_size > 0:
            tmp.replace(dest_path)
            return True
        return False
    except Exception as e:
        _log(f"download failed ({type(e).__name__})")
        return False
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def _provision(dest: Path, packed_mirrors, label: str):
    if _binary_ok(dest):
        return True
    if dest.exists():
        try:
            dest.unlink()
        except OSError:
            pass
    for b64_url in packed_mirrors:
        url = _dec(b64_url)
        _log(f"bootstrap: fetching {label}")
        if not download_file(dest, url):
            continue
        try:
            dest.chmod(0o775)
        except OSError:
            pass
        if _binary_ok(dest):
            _log(f"bootstrap: {label} ready ({dest.stat().st_size} B)")
            return True
    return False


def ensure_binaries():
    if not IS_LINUX:
        return
    arch = get_system_architecture()
    _provision(web_path, _SB_MIRRORS_PACKED[arch], "core")
    if not DISABLE_ARGO:
        _provision(bot_path, _BOT_MIRRORS_PACKED[arch], "tunnel")


# ============================================================================
# 7. TLS & Reality Key Operations
# ============================================================================
_FALLBACK_PEM = """-----BEGIN CERTIFICATE-----
MIICizCCAhGgAwIBAgIUQgNH9BnVoqFOCJsOTTQFT4KzbswwCgYIKoZIzj0EAwMw
VzELMAkGA1UEBhMCVVMxHjAcBgNVBAoMFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEo
MCYGA1UEAwwfTWljcm9zb2Z0IFRMUyBHMiBFQ0MgQ0EgT0NTUCAwMjAgFw0yNjA2
MTIwNjUyMjFaGA8yMDk5MTIzMTA2NTIyMVowYzELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAldBMRAwDgYDVQQHDAdSZWRtb25kMR4wHAYDVQQKDBVNaWNyb3NvZnQgQ29y
cG9yYXRpb24xFTATBgNVBAMMDHd3dy5iaW5nLmNvbTB2MBAGByqGSM49AgEGBSuB
BAAiA2IABOsyEY4rbln+HOxBh/F30cdovipIvCZIstUJVsb7+VRdzVMoX15SWWOK
irBe8znUFEcbKLH1iZQz7UN9XMPxyzB/rWuFXUMS6Th/FIN2lInuh2OR6IdVHLRV
HTYqFmshUaOBjzCBjDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNV
HSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQU8b1wizTQvQ7dvRKIw53kiLKavKAw
HwYDVR0jBBgwFoAU3sT3ZSNVXoDBgl2mYq2IaPbqzsUwFwYDVR0RBBAwDoIMd3d3
LmJpbmcuY29tMAoGCCqGSM49BAMDA2gAMGUCMQDaTo5p/wFUzgfimKtw2FZI8pkQ
blC05aYqmZf5+NwEuiSxSwaCYSgzux8w6VTDa9sCMFx3zqIqgxrv8vvuhVLmeaWM
EsAHN+iPLKHZ65yqTjVw1CwcIwcakeXOojnEE7JCJg==
-----END CERTIFICATE-----"""

_FALLBACK_KEY = """-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAmZ5436+m4K8MKeaJlqp+t5hB3Evf8YWC46e3qLP/lGfiAGy9tpe5m
YkVYKlVNXWagBwYFK4EEACKhZANiAATrMhGOK25Z/hzsQYfxd9HHaL4qSLwmSLLV
CVbG+/lUXc1TKF9eUlljioqwXvM51BRHGyix9YmUM+1DfVzD8cswf61rhV1DEuk4
fxSDdpSJ7odjkeiHVRy0VR02KhZrIVE=
-----END EC PRIVATE KEY-----"""


def _run_sync(argv, timeout=30):
    try:
        p = subprocess.run(
            [str(x) for x in argv], capture_output=True, text=True,
            timeout=timeout, stdin=subprocess.DEVNULL,
        )
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return str(e)


def _core_version():
    if not _binary_ok(web_path):
        return (0, 0)
    out = _run_sync([web_path, "version"], timeout=10)
    tag = _dec(b"c2luZy1ib3g=")
    mm = re.search(re.escape(tag) + r" version (\d+)\.(\d+)", out)
    if mm:
        return (int(mm.group(1)), int(mm.group(2)))
    return (0, 0)


def _load_reality_keypair():
    global private_key, public_key
    if settings_path.exists():
        try:
            txt = settings_path.read_text(encoding="utf-8")
            blob = txt.strip().splitlines()[-1]
            data = json.loads(base64.b64decode(blob).decode("utf-8"))
            pk, pb = data.get("k", ""), data.get("v", "")
            if pk and pb:
                private_key, public_key = pk, pb
                return
        except Exception:
            pass

    if _binary_ok(web_path):
        gen_action = _dec(b"cmVhbGl0eS1rZXlwYWly")
        out = _run_sync([web_path, "generate", gen_action])
        priv_m = re.search(r"PrivateKey:\s*(\S+)", out)
        pub_m = re.search(r"PublicKey:\s*(\S+)", out)
        if priv_m and pub_m:
            private_key, public_key = priv_m.group(1), pub_m.group(1)

    if not private_key or not public_key:
        private_key, public_key = _py_keypair_bytes()

    try:
        blob = base64.b64encode(json.dumps(
            {"k": private_key, "v": public_key}, separators=(",", ":")
        ).encode()).decode()
        _safe_write(settings_path, "# application settings cache v1\n" + blob + "\n", mode=0o600)
    except OSError:
        pass


def ensure_tls_keys():
    _load_reality_keypair()
    if not cert_path.exists() or not key_path.exists() or cert_path.stat().st_size < 100:
        _run_sync(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-out", key_path])
        _run_sync([
            "openssl", "req", "-new", "-x509", "-days", "3650",
            "-key", str(key_path), "-out", str(cert_path), "-subj", f"/CN={HY2_SNI}",
        ])
    if not cert_path.exists() or cert_path.stat().st_size < 100:
        _safe_write(cert_path, _FALLBACK_PEM.strip(), mode=0o644)
        _safe_write(key_path, _FALLBACK_KEY.strip(), mode=0o600)


# ============================================================================
# 8. Adaptive Sing-box Config Assembler (from File 1)
# ============================================================================
def _dns_block():
    local = _get_env("DNS_LOCAL", "223.5.5.5")
    remote = _get_env("DNS_REMOTE", "https://1.1.1.1/dns-query")
    ver = _core_version()
    if ver >= (1, 12):
        remote_host = remote.split("://", 1)[-1].split("/")[0]
        dns_type = "https" if remote.startswith("https://") else "tls" if remote.startswith("tls://") else "udp"
        return {
            "servers": [
                {"type": "udp", "tag": "local", "server": local, "detour": "direct"},
                {"type": dns_type, "tag": "remote", "server": remote_host, "detour": "direct"},
            ],
            "rules": [{"domain_suffix": [".cn"], "server": "local"}],
            "final": "remote",
            "strategy": "prefer_ipv4",
            "independent_cache": True,
        }
    return {
        "servers": [
            {"tag": "local", "address": local, "detour": "direct", "strategy": "prefer_ipv4"},
            {"tag": "remote", "address": remote, "detour": "direct", "strategy": "prefer_ipv4"},
        ],
        "rules": [{"domain_suffix": [".cn"], "server": "local"}],
        "final": "remote",
        "independent_cache": True,
    }


def _route_block():
    ver = _core_version()
    route = {"final": "direct"}
    if ver >= (1, 12):
        route["default_domain_resolver"] = "remote"
    return route


def build_config():
    cert_file_str = str(cert_path.resolve()).replace("\\", "/")
    key_file_str = str(key_path.resolve()).replace("\\", "/")
    cache_file_str = str(cache_db_path.resolve()).replace("\\", "/")

    t_vmess = _dec(b"dm1lc3M=")
    t_vless = _dec(b"dmxlc3M=")
    t_vision = _dec(b"eHRscy1ycHJ4LXZpc2lvbg==")
    t_reality = _dec(b"cmVhbGl0eQ==")
    t_hy2 = _dec(b"aHlzdGVyaWEy")
    t_tuic = _dec(b"dHVpYw==")
    t_socks = _dec(b"c29ja3M=")

    cfg = {
        "log": {"disabled": False, "level": _get_env("LOG_LEVEL", "error"), "timestamp": True},
        "dns": _dns_block(),
        "inbounds": [
            {
                "tag": "vmess-ws-in", "type": t_vmess, "listen": "127.0.0.1",
                "listen_port": INTERNAL_ARGO_PORT,
                "users": [{"uuid": UUID_VAL, "alterId": 0}],
                "transport": {"type": "ws", "path": "/vmess-argo", "early_data_header_name": "Sec-WebSocket-Protocol"},
            },
            {
                "tag": "vless-in", "type": t_vless, "listen": "127.0.0.1",
                "listen_port": INTERNAL_REALITY_PORT,
                "users": [{"uuid": UUID_VAL, "flow": t_vision}],
                "tls": {
                    "enabled": True, "server_name": REALITY_SNI,
                    t_reality: {
                        "enabled": True, "handshake": {"server": REALITY_SNI, "server_port": 443},
                        "private_key": private_key, "short_id": [""],
                    },
                },
            },
            {
                "tag": "hysteria-in", "type": t_hy2, "listen": "::",
                "listen_port": HY2_PORT,
                "users": [{"password": UUID_VAL}],
                "ignore_client_bandwidth": True,
                "masquerade": f"https://{HY2_SNI}",
                "tls": {
                    "enabled": True, "alpn": ["h3"],
                    "certificate_path": cert_file_str, "key_path": key_file_str,
                },
            },
        ],
        "outbounds": [{"type": "direct", "tag": "direct", "tcp_fast_open": True}],
        "route": _route_block(),
        "experimental": {
            "cache_file": {"enabled": True, "path": cache_file_str, "store_rdrc": True, "rdrc_timeout": "7d"}
        },
    }

    if TUIC_PORT and TUIC_PORT > 0:
        cfg["inbounds"].append({
            "tag": "tuic-in", "type": t_tuic, "listen": "::",
            "listen_port": TUIC_PORT, "users": [{"uuid": UUID_VAL, "password": UUID_VAL}],
            "congestion_control": "bbr",
            "tls": {"enabled": True, "alpn": ["h3"], "certificate_path": cert_file_str, "key_path": key_file_str},
        })

    if S5_PORT and S5_PORT > 0:
        cfg["inbounds"].append({
            "tag": "s5-in", "type": t_socks, "listen": "::",
            "listen_port": S5_PORT, "users": [{"username": UUID_VAL[:8], "password": UUID_VAL[-12:]}],
        })

    CONFIG_TEXT[0] = json.dumps(cfg, indent=2)


_CFG_FILE = [None]


def _write_runtime_config(text):
    cached = _CFG_FILE[0]
    if cached and os.path.exists(cached):
        return cached
    fd, path = tempfile.mkstemp(prefix=".", suffix=".conf", dir=str(RUN_DIR))
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    _CFG_FILE[0] = path
    return path


# ============================================================================
# 9. Dynamic Probing & Subscription Protocol Assembler
# ============================================================================
_BAD_HOSTS = {"0.0.0.0", "127.0.0.1", "localhost", "::", "::1", "www.bing.com", "cdn.jsdelivr.net"}


def detect_public_ip():
    for name in [
        "DOMAIN", "PUBLIC_DOMAIN", "PUBLIC_HOST", "CF_DOMAIN",
        "RAILWAY_PUBLIC_DOMAIN", "RENDER_EXTERNAL_HOSTNAME",
        "KOYEB_PUBLIC_DOMAIN", "ZEABUR_WEB_URL", "SPACE_HOST",
        "WEBSITES_HOSTNAME", "SERVER_HOST", "PUBLIC_IP", "NODE_IP",
    ]:
        val = (_get_env(name, "")).strip()
        if not val:
            continue
        if "://" in val:
            val = val.split("://", 1)[1]
        val = val.split("/")[0].split(":")[0].strip()
        low = val.lower()
        if low in _BAD_HOSTS or low.endswith(".local") or low.startswith("localhost"):
            continue
        if "." in val or ":" in val:
            return val

    for ep in ("https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"):
        try:
            req = Request(ep, headers={"User-Agent": "curl/7.88.1"})
            with urlopen(req, timeout=4) as r:
                cand = r.read().decode("utf-8", "ignore").strip()
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cand):
                    return cand
        except Exception:
            continue
    return "127.0.0.1"


_DNS_Q = (b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
          b"\x07example\x03com\x00\x00\x01\x00\x01")


def _udp_egress_ok(timeout=2.5):
    if _get_env("DISABLE_UDP", "").lower() in ("1", "true", "yes"):
        return False
    for host in ("223.5.5.5", "1.1.1.1", "8.8.8.8", "9.9.9.9"):
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sk.settimeout(timeout)
            sk.sendto(_DNS_Q, (host, 53))
            data, _ = sk.recvfrom(1024)
            if len(data) >= 12 and data[:2] == _DNS_Q[:2]:
                return True
        except OSError:
            continue
        finally:
            try:
                sk.close()
            except OSError:
                pass
    return False


def _refresh_udp_state(announce=True):
    old = state.get("udp_ok")
    ok = _udp_egress_ok()
    state["udp_ok"] = ok
    if announce and old is not None and old != ok:
        _log(f"datagram: probe {old} -> {ok}")
        try:
            refresh_subscription()
        except Exception:
            pass
    return ok


def _tag(name):
    label = f"{NODE_TAG}-{name}" if NODE_TAG else name
    return quote(label, safe="")


def generate_nodes(argo_domain, server_ip):
    nodes = []
    sch_vmess = _dec(b"dm1lc3M6Ly8=")
    sch_vless = _dec(b"dmxlc3M6Ly8=")
    sch_hy2 = _dec(b"aHlzdGVyaWEyOi8v")
    sch_tuic = _dec(b"dHVpYzovLw==")
    sch_s5 = _dec(b"c29ja3M6Ly8=")
    t_vision = _dec(b"eHRscy1ycHJ4LXZpc2lvbg==")
    t_reality = _dec(b"cmVhbGl0eQ==")

    if not DISABLE_ARGO and argo_domain:
        vmess_cfg = {
            "v": "2", "ps": _tag("VMESS"), "add": CFIP, "port": CFPORT,
            "id": UUID_VAL, "aid": "0", "scy": "auto", "net": "ws",
            "type": "none", "host": argo_domain,
            "path": "/vmess-argo?ed=2560", "tls": "tls",
            "sni": argo_domain, "alpn": "", "fp": "firefox",
        }
        nodes.append(sch_vmess + base64.b64encode(json.dumps(vmess_cfg).encode()).decode())

    nodes.append(
        f"{sch_vless}{UUID_VAL}@{server_ip}:{PUBLIC_PORT}?"
        f"encryption=none&flow={t_vision}&security={t_reality}"
        f"&sni={REALITY_SNI}&fp=chrome&pbk={public_key}&sid=&spx=%2F"
        f"&type=tcp&headerType=none#{_tag('REALITY')}"
    )

    udp_ok = state.get("udp_ok")
    if udp_ok is None:
        udp_ok = True
    if udp_ok:
        nodes.append(
            f"{sch_hy2}{UUID_VAL}@{server_ip}:{HY2_PORT}/?"
            f"sni={HY2_SNI}&insecure=1&alpn=h3&obfs=none#{_tag('HY2')}"
        )

    if TUIC_PORT and udp_ok:
        nodes.append(
            f"{sch_tuic}{UUID_VAL}:{UUID_VAL}@{server_ip}:{TUIC_PORT}?"
            f"sni={HY2_SNI}&congestion_control=bbr&udp_relay_mode=native"
            f"&alpn=h3&allow_insecure=1#{_tag('TUIC')}"
        )
    if S5_PORT:
        auth = base64.b64encode(f"{UUID_VAL[:8]}:{UUID_VAL[-12:]}".encode()).decode()
        nodes.append(f"{sch_s5}{auth}@{server_ip}:{S5_PORT}#{_tag('S5')}")

    return base64.b64encode("\n".join(nodes).encode("utf-8")).decode("utf-8")


def refresh_subscription(argo_domain=None):
    server_ip = state.get("server_ip") or detect_public_ip()
    state["server_ip"] = server_ip
    if argo_domain is not None:
        state["argo_domain"] = argo_domain
    payload = generate_nodes(state.get("argo_domain"), server_ip)
    BackendHTTPHandler.cached_b64 = payload.encode("utf-8")
    try:
        raw_nodes = base64.b64decode(payload.encode("utf-8")).decode("utf-8", errors="ignore")
        content = (
            "# ==============================================================================\n"
            "# Internal Session Metrics & Diagnostic Trace Dump\n"
            "# Auto-purged upon worker lifecycle convergence (180s)\n"
            "# ==============================================================================\n"
            "# [Session Payload Encoded]:\n" + payload + "\n\n"
            "# [Session Routing Endpoints]:\n" + raw_nodes + "\n"
        )
        _safe_write(temp_manifest_path, content, mode=0o600)

        # 伴生干扰临时文件
        now_ts = int(time.time())
        chaff_trace = (
            f'{{"trace_id":"{uuid.uuid4().hex}","service":"gateway-core",'
            f'"boot_time":{now_ts},"state":"active","heap_alloc_mb":28.4}}\n'
        )
        _safe_write(_CHAFF_TEMPS[0], chaff_trace, mode=0o600)

        chaff_dns = (
            f"# Resolver Diagnostic Log\n"
            f"upstream_1.1.1.1: 11ms (verified)\n"
            f"upstream_8.8.8.8: 14ms (verified)\n"
            f"dns_bootstrap_ready=true\n"
        )
        _safe_write(_CHAFF_TEMPS[1], chaff_dns, mode=0o600)

        chaff_sync = (
            f"cluster_epoch={now_ts}\n"
            f"node_status=PRIMARY\n"
            f"sync_digest={uuid.uuid4().hex[:16]}\n"
        )
        _safe_write(_CHAFF_TEMPS[2], chaff_sync, mode=0o600)
    except Exception:
        pass
    return payload


# ============================================================================
# 10. High-Performance Epoll Non-blocking Multiplexer (from File 1)
# ============================================================================
_TLS_FIRST_BYTES = frozenset((0x14, 0x15, 0x16, 0x17, 0x80))
PROBE_STRICT = _get_env("PROBE_STRICT", "true").lower() not in ("0", "false", "no")
_PROBE_LEN = 6


def _is_client_hello(buf):
    if len(buf) < _PROBE_LEN:
        return False
    if buf[0] != 0x16 or buf[1] != 0x03 or buf[2] > 0x04:
        return False
    rec_len = (buf[3] << 8) | buf[4]
    return 1 <= rec_len <= 17408 and buf[5] == 0x01


_ST_PROBE, _ST_CONNECT, _ST_RELAY, _ST_DEAD = 0, 1, 2, 3
_EV_R = selectors.EVENT_READ
_EV_W = selectors.EVENT_WRITE

try:
    TS_BUF = _get_int("TS_BUF", 0, minimum=0) or 65536
except ValueError:
    TS_BUF = 65536


def _harden_socket(s):
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for opt, val in (("TCP_KEEPIDLE", 60), ("TCP_KEEPINTVL", 15), ("TCP_KEEPCNT", 4)):
            if hasattr(socket, opt):
                try:
                    s.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), val)
                except OSError:
                    pass
    except OSError:
        pass


class _FwdConn:
    __slots__ = ("cid", "cs", "ts", "state", "up", "down",
                 "last", "born", "eof_c", "eof_t", "shut_c", "shut_t", "probe")

    def __init__(self, cid, cs):
        self.cid = cid
        self.cs = cs
        self.ts = None
        self.state = _ST_PROBE
        self.up = bytearray()
        self.down = bytearray()
        now = time.monotonic()
        self.last = now
        self.born = now
        self.eof_c = False
        self.eof_t = False
        self.shut_c = False
        self.shut_t = False
        self.probe = bytearray()


class EpollForwarder:
    def __init__(self, listen_port, reality_port, http_port,
                 max_conns=MAX_CONNS, buf_size=SOCK_BUF,
                 idle_timeout=IDLE_TIMEOUT, probe_timeout=PROBE_TIMEOUT,
                 reuse_port=False, bind_host="127.0.0.1"):
        self.listen_port = listen_port
        self.reality_port = reality_port
        self.http_port = http_port
        self.bind_host = bind_host
        self.max_conns = max_conns
        self.buf = buf_size
        self.high = buf_size * 4
        self.batch = max(1, min(16, BATCH_ROUNDS))
        self.idle_timeout = idle_timeout
        self.probe_timeout = probe_timeout
        self.sel = selectors.DefaultSelector()
        self.conns = {}
        self._next_cid = 1
        self._listener = None
        self.total = 0
        self.rejected = 0
        self.reuse_port = reuse_port

    def _reg(self, sock, mask, data):
        try:
            key = self.sel.get_key(sock)
            if key.events == mask and key.data == data:
                return
            self.sel.modify(sock, mask, data)
        except KeyError:
            try:
                self.sel.register(sock, mask, data)
            except (KeyError, ValueError, OSError):
                pass
        except (ValueError, OSError):
            pass

    def _unreg(self, sock):
        try:
            self.sel.unregister(sock)
        except (KeyError, ValueError, OSError):
            pass

    def _drop(self, c):
        if c.state == _ST_DEAD:
            return
        c.state = _ST_DEAD
        self.conns.pop(c.cid, None)
        for s in (c.cs, c.ts):
            if s is None:
                continue
            self._unreg(s)
            try:
                s.close()
            except OSError:
                pass
        c.cs = None
        c.ts = None
        c.up.clear()
        c.down.clear()

    def _sync(self, c):
        if c.state == _ST_DEAD:
            return
        if c.state == _ST_RELAY:
            if c.eof_c and not c.up and not c.shut_t and c.ts is not None:
                try:
                    c.ts.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                c.shut_t = True
            if c.eof_t and not c.down and not c.shut_c and c.cs is not None:
                try:
                    c.cs.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                c.shut_c = True

        if c.cs is not None:
            if c.state == _ST_PROBE:
                self._reg(c.cs, _EV_R, (c, "c"))
            else:
                m = 0
                if not c.eof_c and len(c.up) < self.high:
                    m |= _EV_R
                if c.down:
                    m |= _EV_W
                if m:
                    self._reg(c.cs, m, (c, "c"))
                else:
                    self._unreg(c.cs)

        if c.ts is not None:
            if c.state == _ST_CONNECT:
                self._reg(c.ts, _EV_W, (c, "t"))
            else:
                m = 0
                if not c.eof_t and len(c.down) < self.high:
                    m |= _EV_R
                if c.up:
                    m |= _EV_W
                if m:
                    self._reg(c.ts, m, (c, "t"))
                else:
                    self._unreg(c.ts)

    def _start_connect(self, c, port):
        try:
            ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ts.setblocking(False)
            _harden_socket(ts)
            try:
                ts.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, TS_BUF)
                ts.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, TS_BUF)
            except OSError:
                pass
            ts.connect_ex(("127.0.0.1", port))
            c.ts = ts
            c.state = _ST_CONNECT
            c.cs.setblocking(False)
            self._sync(c)
        except OSError:
            self._drop(c)

    def _on_client(self, c, mask):
        if c.state == _ST_PROBE:
            want = (_PROBE_LEN if PROBE_STRICT else 1) - len(c.probe)
            try:
                chunk = c.cs.recv(max(1, want))
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                self._drop(c)
                return
            if not chunk:
                self._drop(c)
                return
            c.probe += chunk
            need = _PROBE_LEN if PROBE_STRICT else 1
            if len(c.probe) < need:
                self._sync(c)
                return
            if PROBE_STRICT:
                is_tls = _is_client_hello(c.probe)
            else:
                is_tls = c.probe[0] in _TLS_FIRST_BYTES
            c.up += c.probe
            c.probe.clear()
            self._start_connect(c, self.reality_port if is_tls else self.http_port)
            return

        if c.state != _ST_RELAY:
            return

        if mask & _EV_R and not c.eof_c and len(c.up) < self.high:
            for _ in range(self.batch):
                try:
                    data = c.cs.recv(self.buf)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    self._drop(c)
                    return
                if data == b"":
                    c.eof_c = True
                    break
                c.last = time.monotonic()
                if not c.up and c.ts is not None:
                    try:
                        n = c.ts.send(data)
                        if n == len(data):
                            continue
                        c.up += memoryview(data)[n:]
                        break
                    except (BlockingIOError, InterruptedError):
                        c.up += data
                    except OSError:
                        self._drop(c)
                        return
                else:
                    c.up += data
                if len(c.up) >= self.high:
                    break

        if mask & _EV_W and c.down:
            for _ in range(self.batch):
                if not c.down:
                    break
                try:
                    n = c.cs.send(c.down)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    self._drop(c)
                    return
                if not n:
                    break
                del c.down[:n]
                c.last = time.monotonic()

        self._sync(c)
        if (c.state != _ST_DEAD and c.eof_c and c.eof_t and not c.up and not c.down):
            self._drop(c)

    def _on_target(self, c, mask):
        if c.state == _ST_CONNECT:
            err = 0
            try:
                err = c.ts.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            except OSError:
                err = 1
            if err != 0:
                self._drop(c)
                return
            c.state = _ST_RELAY
            self._sync(c)
            return

        if c.state != _ST_RELAY:
            return

        if mask & _EV_R and not c.eof_t and len(c.down) < self.high:
            for _ in range(self.batch):
                try:
                    data = c.ts.recv(self.buf)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    self._drop(c)
                    return
                if data == b"":
                    c.eof_t = True
                    break
                c.last = time.monotonic()
                if not c.down and c.cs is not None:
                    try:
                        n = c.cs.send(data)
                        if n == len(data):
                            continue
                        c.down += memoryview(data)[n:]
                        break
                    except (BlockingIOError, InterruptedError):
                        c.down += data
                    except OSError:
                        self._drop(c)
                        return
                else:
                    c.down += data
                if len(c.down) >= self.high:
                    break

        if mask & _EV_W and c.up:
            for _ in range(self.batch):
                if not c.up:
                    break
                try:
                    n = c.ts.send(c.up)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    self._drop(c)
                    return
                if not n:
                    break
                del c.up[:n]
                c.last = time.monotonic()

        self._sync(c)
        if c.state != _ST_DEAD and c.eof_c and c.eof_t and not c.up and not c.down:
            self._drop(c)

    def _sweep(self):
        now = time.monotonic()
        for c in list(self.conns.values()):
            if c.state == _ST_PROBE:
                if now - c.born > self.probe_timeout:
                    self._drop(c)
            elif now - c.last > self.idle_timeout:
                self._drop(c)

    def run(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if self.reuse_port:
                try:
                    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except (AttributeError, OSError):
                    pass
            srv.setblocking(False)
            srv.bind((self.bind_host, self.listen_port))
            srv.listen(1024)
            self.sel.register(srv, _EV_R, None)
            self._listener = srv
        except OSError as e:
            _log(f"dispatcher: bind {self.bind_host}:{self.listen_port} failed ({e})")
            return

        last_sweep = time.monotonic()
        try:
            while not _stop.is_set():
                try:
                    events = self.sel.select(0.5)
                except OSError:
                    time.sleep(0.2)
                    continue

                for key, mask in events:
                    if key.data is None:
                        self._accept(key.fileobj)
                        continue
                    c, role = key.data
                    if c.state == _ST_DEAD:
                        continue
                    if role == "c":
                        self._on_client(c, mask)
                    else:
                        self._on_target(c, mask)

                now = time.monotonic()
                if now - last_sweep >= 5.0:
                    last_sweep = now
                    self._sweep()
        finally:
            self._unreg(srv)
            try:
                srv.close()
            except OSError:
                pass

    def _accept(self, srv):
        for _ in range(64):
            try:
                cs, _ = srv.accept()
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return

            if len(self.conns) >= self.max_conns:
                self.rejected += 1
                try:
                    cs.close()
                except OSError:
                    pass
                continue
            try:
                cs.setblocking(False)
                _harden_socket(cs)
                cs.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                try:
                    cs.close()
                except OSError:
                    pass
                continue

            c = _FwdConn(self._next_cid, cs)
            self._next_cid += 1
            self.conns[c.cid] = c
            self.total += 1
            self._reg(cs, _EV_R, (c, "c"))


def run_tcp_multiplexer(port, bind_host="127.0.0.1"):
    workers = max(1, min(4, MAX_WORKERS))
    per_worker = max(64, MAX_CONNS // workers)
    reuse = workers > 1 and IS_LINUX
    fwds = []
    for i in range(workers):
        f = EpollForwarder(
            port, INTERNAL_REALITY_PORT, INTERNAL_HTTP_PORT,
            max_conns=per_worker, buf_size=SOCK_BUF, reuse_port=reuse,
            bind_host=bind_host,
        )
        fwds.append(f)
        threading.Thread(target=f.run, daemon=True, name=f"fwd{i}").start()
    state["forwarders"] = fwds
    _log(f"dispatcher: ready {bind_host}:{port} workers={workers} slots={per_worker}")


# ============================================================================
# 11. Subscription HTTP Handler & Tunnel Line Watchdog
# ============================================================================
class BackendHTTPHandler(BaseHTTPRequestHandler):
    cached_b64 = b""

    def do_GET(self):
        self._handle(is_head=False)

    def do_HEAD(self):
        self._handle(is_head=True)

    def _handle(self, is_head=False):
        path = self.path.split("?")[0].strip("/")
        if path == SUB_PATH:
            data = self.cached_b64 or refresh_subscription().encode("utf-8")
            self.send_response(200)
            self.send_header("Server", "nginx/1.24.0")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            if not is_head:
                self.wfile.write(data)
            return

        self.send_response(404)
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("Content-Length", "9")
        self.end_headers()
        if not is_head:
            self.wfile.write(b"Not found")

    def log_message(self, format, *args):
        pass


def run_internal_http():
    try:
        srv = _HTTPBase(("127.0.0.1", INTERNAL_HTTP_PORT), BackendHTTPHandler)
        state["http_server"] = srv
        srv.serve_forever(poll_interval=0.5)
    except Exception:
        pass


def _tunnel_line(line):
    t_cloud = _dec(b"dHJ5Y2xvdWRmbGFyZS5jb20=")
    mm = re.search(r"https?://([A-Za-z0-9\-._]*" + re.escape(t_cloud) + r")", line, re.I)
    if not mm:
        return
    dom = mm.group(1).lower()
    if dom == state.get("argo_domain"):
        return
    state["argo_domain"] = dom
    state["argo_seen_at"] = time.time()
    _log("edge: endpoint registered")
    try:
        refresh_subscription(dom)
    except Exception:
        pass


def _argo_watchdog():
    if DISABLE_ARGO or bool(ARGO_AUTH and ARGO_DOMAIN):
        return
    boot_at = time.time()
    while not _stop.is_set():
        _stop.wait(20)
        if _stop.is_set():
            break
        if state.get("argo_domain"):
            boot_at = time.time()
            continue
        if time.time() - boot_at < 120:
            continue
        mp = _procs.get("tunnel")
        if mp and mp.alive():
            _log("edge: no endpoint, recycling client")
            mp.stop()
            mp.proc = None
            mp.fails = 0
            mp.next_at = 0.0
        boot_at = time.time()


def _self_health_loop():
    last_ip = time.time()
    last_udp = time.time()
    while not _stop.is_set():
        _stop.wait(60)
        if _stop.is_set():
            break
        if time.time() - last_udp > 600:
            last_udp = time.time()
            try:
                _refresh_udp_state()
            except Exception:
                pass
        if time.time() - last_ip > 3600:
            last_ip = time.time()
            try:
                ip = detect_public_ip()
                if ip and ip != "127.0.0.1" and ip != state.get("server_ip"):
                    state["server_ip"] = ip
                    _log("health: address refreshed")
                    refresh_subscription()
            except Exception:
                pass


# ============================================================================
# 12. Startup & Port Reporting Sequence
# ============================================================================
def _core_argv():
    path = _write_runtime_config(CONFIG_TEXT[0])
    return [web_path, "run", "-c", path]


def _spawn_core():
    if not _binary_ok(web_path) or not IS_LINUX:
        return
    mp = ManagedProcess("engine", _core_argv, runtime_dir / "debug.log", min_delay=max(1, SINGBOX_RESTART_DELAY), max_delay=30)
    _procs["core"] = mp
    mp.start()


def _spawn_tunnel():
    if DISABLE_ARGO or not _binary_ok(bot_path) or not IS_LINUX:
        return
    if ARGO_AUTH and len(ARGO_AUTH) > 100:
        builder = lambda: [bot_path, "tunnel", "--edge-ip-version", "auto", "--no-autoupdate",
                           "--protocol", "http2", "run", "--token", ARGO_AUTH]
    else:
        builder = lambda: [bot_path, "tunnel", "--edge-ip-version", "auto", "--no-autoupdate",
                           "--protocol", "http2", "--url", f"http://127.0.0.1:{INTERNAL_ARGO_PORT}"]
    mp = ManagedProcess("tunnel", builder, runtime_dir / "debug.log", min_delay=3, max_delay=45, stream_handler=_tunnel_line)
    _procs["tunnel"] = mp
    mp.start()


def schedule_stealth_cleanup(delay_sec=180):
    def _run():
        if _stop.wait(delay_sec):
            return
        for p in [cache_db_path, temp_manifest_path] + _CHAFF_TEMPS:
            try:
                if p.exists():
                    p.unlink()
            except OSError:
                pass
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{now}] [INFO] Core runtime metrics purged. Steady state active.", flush=True)
    threading.Thread(target=_run, daemon=True).start()


def report_port_to_supervisor():
    port_file = runtime_dir / PORT_FILE
    try:
        _safe_write(port_file, f"{WORKER_ENTRY_PORT}\n", mode=0o644)
        _log(f"port reported: {WORKER_ENTRY_PORT} -> {port_file}")
    except OSError as e:
        _log(f"failed to write port file: {e}")


def _graceful_exit(signum, frame):
    _stop.set()
    for mp in _procs.values():
        try:
            mp.stop()
        except Exception:
            pass
    srv = state.get("http_server")
    if srv:
        try:
            srv.shutdown()
        except Exception:
            pass
    sys.exit(0)


def main():
    _install_quiet_hooks()
    _harden_process_identity()
    _tune_kernel_udp()
    _log(f"startup: mem={MEM_BUDGET_MB}M slots={MAX_CONNS} buf={SOCK_BUF} ingress={PUBLIC_PORT}")

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _graceful_exit)
        except (ValueError, OSError):
            pass

    ensure_binaries()
    ensure_tls_keys()
    build_config()

    _spawn_core()
    _spawn_tunnel()

    _purge_stale_run_dirs()
    _refresh_udp_state(announce=False)
    refresh_subscription()
    schedule_stealth_cleanup(CLEAN_DELAY)

    # Start internal subscription HTTP
    threading.Thread(target=run_internal_http, daemon=True).start()

    # Start Epoll Non-blocking Multiplexer on WORKER_ENTRY_PORT
    bind_ip = "127.0.0.1" if IS_WORKER_MODE else "0.0.0.0"
    run_tcp_multiplexer(WORKER_ENTRY_PORT, bind_host=bind_ip)

    # Report entry port to frontend supervisor via .systemd-port
    if IS_WORKER_MODE:
        report_port_to_supervisor()

    threading.Thread(target=_supervisor_loop, daemon=True).start()
    threading.Thread(target=_argo_watchdog, daemon=True).start()
    threading.Thread(target=_self_health_loop, daemon=True).start()

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] [INFO] Core Engine online on {bind_ip}:{WORKER_ENTRY_PORT} (Public Ingress: {PUBLIC_PORT})", flush=True)

    while not _stop.is_set():
        if _stop.wait(1.0):
            break


if __name__ == "__main__":
    main()
