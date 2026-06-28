from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import select
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request
import winreg
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

APP_NAME = "RobloxBlocker"
RULE_PREFIX = "RobloxBlocker"
HOSTS_MARKER_START = "# RobloxBlocker START"
HOSTS_MARKER_END = "# RobloxBlocker END"
HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")
REG_RUN_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
REG_VALUE_NAME = "RobloxBlocker"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

DEFAULT_DOMAINS = [
    "roblox.com", "www.roblox.com", "web.roblox.com", "m.roblox.com", "api.roblox.com",
    "accountinformation.roblox.com", "accountsettings.roblox.com", "adconfiguration.roblox.com",
    "ads.roblox.com", "assetdelivery.roblox.com", "assetgame.roblox.com", "auth.roblox.com",
    "avatar.roblox.com", "billing.roblox.com", "captcha.roblox.com", "catalog.roblox.com",
    "chat.roblox.com", "chatsite.roblox.com", "clientsettings.api.roblox.com",
    "clientsettingscdn.roblox.com", "client-telemetry.roblox.com", "contacts.roblox.com",
    "contentstore.roblox.com", "create.roblox.com", "develop.roblox.com", "devforum.roblox.com",
    "economy.roblox.com", "ecs.roblox.com", "ecsv2.roblox.com", "ephemeralcounters.api.roblox.com",
    "followings.roblox.com", "friends.roblox.com", "gameinternationalization.roblox.com",
    "games.roblox.com", "gamejoin.roblox.com", "gamepersistence.roblox.com", "groups.roblox.com",
    "inventory.roblox.com", "itemconfiguration.roblox.com", "locale.roblox.com",
    "localizationtables.roblox.com", "metrics.roblox.com", "midas.roblox.com",
    "notifications.roblox.com", "points.roblox.com", "presence.roblox.com",
    "premiumfeatures.roblox.com", "privatemessages.roblox.com", "publish.roblox.com",
    "realtime.roblox.com", "search.roblox.com", "setup.roblox.com", "share.roblox.com",
    "textchat.roblox.com", "thumbnails.roblox.com", "trades.roblox.com",
    "translationroles.roblox.com", "twostepverification.roblox.com", "users.roblox.com",
    "versioncompatibility.api.roblox.com", "voice.roblox.com", "wiki.roblox.com",
    "status.roblox.com", "en.help.roblox.com", "help.roblox.com", "corp.roblox.com",
    "jobs.roblox.com", "blog.roblox.com", "news.roblox.com", "education.roblox.com",
    "brand.roblox.com", "partners.roblox.com", "developer.roblox.com", "data.roblox.com",
    "apis.roblox.com", "chatmoderation.roblox.com", "abtesting.roblox.com", "badges.roblox.com",
    "groupsmoderation.roblox.com", "usermoderation.roblox.com", "universes.roblox.com",
    "places.roblox.com", "games.api.roblox.com", "login.roblox.com", "www.roblox.ru",
    "rbxcdn.com", "js.rbxcdn.com", "static.rbxcdn.com", "setup.rbxcdn.com",
    "tr.rbxcdn.com", "images.rbxcdn.com",
    "c0.rbxcdn.com", "c1.rbxcdn.com", "c2.rbxcdn.com", "c3.rbxcdn.com",
    "c4.rbxcdn.com", "c5.rbxcdn.com", "c6.rbxcdn.com", "c7.rbxcdn.com",
    "t0.rbxcdn.com", "t1.rbxcdn.com", "t2.rbxcdn.com", "t3.rbxcdn.com",
    "t4.rbxcdn.com", "t5.rbxcdn.com", "t6.rbxcdn.com", "t7.rbxcdn.com",
    "cdn.arkoselabs.com", "roblox-api.arkoselabs.com", "client-api.arkoselabs.com",
    "rbx.com", "robloxdev.com", "simulprod.com", "rbx.io",
    "bloxstrap.org", "wiki.bloxstrap.org", "bloxstrap.com",
    "fishstrap.app", "wiki.fishstrap.app",
    "roblox.qq.com", "roblox.cn",
]

DEFAULT_IPV4_RANGES = [
    "128.116.0.0/17", "103.140.28.0/23", "128.116.0.0/24", "128.116.1.0/24", "128.116.2.0/24",
    "128.116.5.0/24", "128.116.11.0/24", "128.116.13.0/24", "128.116.21.0/24", "128.116.22.0/24",
    "128.116.31.0/24", "128.116.32.0/24", "128.116.44.0/24", "128.116.45.0/24", "128.116.46.0/24",
    "128.116.47.0/24", "128.116.48.0/24", "128.116.50.0/24", "128.116.51.0/24", "128.116.53.0/24",
    "128.116.54.0/24", "128.116.55.0/24", "128.116.56.0/24", "128.116.57.0/24", "128.116.63.0/24",
    "128.116.64.0/24", "128.116.67.0/24", "128.116.74.0/24", "128.116.80.0/24", "128.116.81.0/24",
    "128.116.84.0/24", "128.116.86.0/24", "128.116.87.0/24", "128.116.88.0/24", "128.116.92.0/24",
    "128.116.93.0/24", "128.116.94.0/24", "128.116.95.0/24", "128.116.97.0/24", "128.116.99.0/24",
    "128.116.102.0/24", "128.116.105.0/24", "128.116.115.0/24", "128.116.116.0/24",
    "128.116.117.0/24", "128.116.120.0/24", "128.116.127.0/24", "141.193.3.0/24", "205.201.62.0/24",
]

DEFAULT_IPV6_RANGES = [
    "2620:2b:e000::/48", "2620:135:6000::/40", "2620:135:6004::/48", "2620:135:6007::/48",
    "2620:135:6008::/48", "2620:135:6009::/48", "2620:135:600a::/48", "2620:135:600b::/48",
    "2620:135:600c::/48", "2620:135:600d::/48", "2620:135:600e::/48", "2620:135:6041::/48",
]

EXECUTABLE_NAMES = [
    "RobloxPlayerBeta.exe", "RobloxPlayerLauncher.exe", "RobloxCrashHandler.exe",
    "RobloxStudioBeta.exe", "RobloxStudioLauncherBeta.exe", "RobloxStudio.exe",
    "RobloxPlayer.exe", "Bloxstrap.exe", "Fishstrap.exe", "RobloxPlayerInstaller.exe",
    "RobloxStudioInstaller.exe", "RobloxPlayerLauncherBeta.exe",
]

SEARCH_ROOTS = [
    Path.home() / "AppData" / "Local" / "Roblox",
    Path.home() / "AppData" / "Local" / "Bloxstrap",
    Path.home() / "AppData" / "Local" / "Fishstrap",
    Path("C:/Program Files (x86)/Roblox"),
    Path("C:/Program Files/Roblox"),
]

KEY_DOMAINS_TO_RESOLVE = [
    "roblox.com", "www.roblox.com", "web.roblox.com", "api.roblox.com",
    "auth.roblox.com", "gamejoin.roblox.com", "rbxcdn.com", "static.rbxcdn.com",
    "assetdelivery.roblox.com", "clientsettings.api.roblox.com",
]

RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS22697"
ROBLOX_HELP_URL = (
    "https://en.help.roblox.com/hc/en-us/articles/115005744663-Troubleshooting-Education-Networks"
)
DOMAIN_SUFFIXES = (
    "roblox.com", "rbxcdn.com", "arkoselabs.com", "roblox.cn", "robloxdev.com",
    "rbx.com", "rbx.io", "bloxstrap.org", "bloxstrap.com", "fishstrap.app",
)
DOMAIN_RE = re.compile(
    r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
    r"\.(?:" + "|".join(re.escape(s) for s in DOMAIN_SUFFIXES) + r"))\b",
    re.IGNORECASE,
)

DOH_SERVER_IPV4 = [
    "8.8.8.8", "8.8.4.4",
    "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
    "94.140.14.14", "94.140.15.15",
    "185.228.168.9", "185.228.169.9",
    "76.76.2.0", "76.76.10.0",
]

DOH_SERVER_IPV6 = [
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2620:fe::fe", "2620:fe::9",
    "2620:119:35::35", "2620:119:53::53",
]

DOH_DOMAINS = [
    "dns.google", "dns64.dns.google",
    "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.cloudflare.com",
    "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
    "doh.opendns.com", "doh.familyshield.opendns.com",
    "dns.adguard.com", "dns-family.adguard.com", "dns-unfiltered.adguard.com",
    "doh.cleanbrowsing.org",
    "doh.libredns.gr",
    "dns.nextdns.io",
    "rdns.faelix.net",
]

BROWSER_POLICY_KEYS: list[tuple[int, str]] = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\BraveSoftware\Brave"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Vivaldi"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Policies\Google\Chrome"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Policies\Microsoft\Edge"),
]

WINDOWS_DNS_KEY = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"

FIREFOX_DIRS: list[Path] = [
    Path(r"C:\Program Files\Mozilla Firefox"),
    Path(r"C:\Program Files (x86)\Mozilla Firefox"),
    Path(r"C:\Program Files\Floorp"),
    Path(r"C:\Program Files (x86)\Floorp"),
    Path(r"C:\Program Files\Waterfox"),
    Path(r"C:\Program Files (x86)\Waterfox"),
    Path(r"C:\Program Files\LibreWolf"),
    Path(r"C:\Program Files (x86)\LibreWolf"),
]

_active_domains: list[str] = []
_active_ipv4: list[str] = []
_active_ipv6: list[str] = []
_blocklists_loaded = False


class BlockError(Exception):
    pass


@dataclass
class UpdateResult:
    ok: bool
    message: str
    domains: int = 0
    ipv4: int = 0
    ipv6: int = 0
    added_domains: int = 0
    added_ipv4: int = 0
    added_ipv6: int = 0


@dataclass
class AppConfig:
    blocked: bool = False
    turn_with_windows: bool = False
    turned_off: bool = False

    @classmethod
    def load(cls) -> AppConfig:
        path = config_path()
        if not path.is_file():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()
        return cls(
            blocked=bool(data.get("blocked", False)),
            turn_with_windows=bool(data.get("turn_with_windows", False)),
            turned_off=bool(data.get("turned_off", False)),
        )

    def save(self) -> None:
        path = config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")


def config_path() -> Path:
    app_data = os.environ.get("APPDATA")
    base = Path(app_data) if app_data else Path.home() / "AppData" / "Roaming"
    return base / APP_NAME / "config.json"


def blocklists_path() -> Path:
    return config_path().parent / "blocklists.json"


def get_domains() -> list[str]:
    _ensure_blocklists_loaded()
    return list(_active_domains)


def get_ipv4_ranges() -> list[str]:
    _ensure_blocklists_loaded()
    return list(_active_ipv4)


def get_ipv6_ranges() -> list[str]:
    _ensure_blocklists_loaded()
    return list(_active_ipv6)


def _ensure_blocklists_loaded() -> None:
    global _blocklists_loaded
    if not _blocklists_loaded:
        load_blocklists()


def _reset_blocklists_to_defaults() -> None:
    global _active_domains, _active_ipv4, _active_ipv6
    _active_domains = list(DEFAULT_DOMAINS)
    _active_ipv4 = list(DEFAULT_IPV4_RANGES)
    _active_ipv6 = list(DEFAULT_IPV6_RANGES)


def load_blocklists() -> None:
    global _blocklists_loaded, _active_domains, _active_ipv4, _active_ipv6
    path = blocklists_path()
    if not path.is_file():
        _reset_blocklists_to_defaults()
        _blocklists_loaded = True
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _reset_blocklists_to_defaults()
        _blocklists_loaded = True
        return
    _active_domains = sorted(set(data.get("domains") or DEFAULT_DOMAINS))
    _active_ipv4 = sorted(set(data.get("ipv4_ranges") or DEFAULT_IPV4_RANGES))
    _active_ipv6 = sorted(set(data.get("ipv6_ranges") or DEFAULT_IPV6_RANGES))
    _blocklists_loaded = True


def _save_blocklists(domains: list[str], ipv4: list[str], ipv6: list[str]) -> None:
    global _active_domains, _active_ipv4, _active_ipv6, _blocklists_loaded
    path = blocklists_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "domains": sorted(set(domains)),
        "ipv4_ranges": sorted(set(ipv4)),
        "ipv6_ranges": sorted(set(ipv6)),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _active_domains = payload["domains"]
    _active_ipv4 = payload["ipv4_ranges"]
    _active_ipv6 = payload["ipv6_ranges"]
    _blocklists_loaded = True


def _http_get(url: str, timeout: int = 30) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _fetch_roblox_prefixes() -> tuple[list[str], list[str]]:
    payload = json.loads(_http_get(RIPESTAT_URL))
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    for item in payload.get("data", {}).get("prefixes", []):
        prefix = str(item.get("prefix", "")).strip()
        if not prefix:
            continue
        if ":" in prefix:
            ipv6.add(prefix.lower())
        elif "." in prefix:
            ipv4.add(prefix)
    if not ipv4 and not ipv6:
        raise ValueError("RIPEstat returned no prefixes for AS22697")
    return sorted(ipv4), sorted(ipv6)


def _extract_domains_from_text(text: str) -> set[str]:
    found = {match.lower() for match in DOMAIN_RE.findall(text)}
    loose = re.findall(
        r"[a-z0-9][a-z0-9.-]*\.(?:roblox\.com|rbxcdn\.com|arkoselabs\.com|bloxstrap\.org|fishstrap\.app)",
        text,
        re.IGNORECASE,
    )
    found.update(item.lower() for item in loose)
    return found


def _fetch_roblox_domains() -> list[str]:
    found = set(DEFAULT_DOMAINS)
    try:
        found.update(_extract_domains_from_text(_http_get(ROBLOX_HELP_URL)))
    except (urllib.error.URLError, TimeoutError, ValueError):
        pass
    return sorted(found)


def update_blocklists() -> UpdateResult:
    _ensure_blocklists_loaded()
    old_domains = set(get_domains())
    old_ipv4 = set(get_ipv4_ranges())
    old_ipv6 = set(get_ipv6_ranges())
    warnings: list[str] = []

    try:
        ipv4, ipv6 = _fetch_roblox_prefixes()
    except Exception as exc:
        warnings.append(f"IP: {exc}")
        ipv4 = sorted(old_ipv4 or set(DEFAULT_IPV4_RANGES))
        ipv6 = sorted(old_ipv6 or set(DEFAULT_IPV6_RANGES))

    try:
        domains = _fetch_roblox_domains()
    except Exception as exc:
        warnings.append(f"Domains: {exc}")
        domains = sorted(old_domains or set(DEFAULT_DOMAINS))

    domains = sorted(set(domains) | set(DEFAULT_DOMAINS))
    ipv4 = sorted(set(ipv4) | set(DEFAULT_IPV4_RANGES))
    ipv6 = sorted(set(ipv6) | set(DEFAULT_IPV6_RANGES))

    if not ipv4 and not ipv6:
        return UpdateResult(False, "Could not fetch Roblox IP ranges. Check internet connection.")

    new_domains = set(domains) - old_domains
    new_ipv4 = set(ipv4) - old_ipv4
    new_ipv6 = set(ipv6) - old_ipv6
    _save_blocklists(domains, ipv4, ipv6)

    lines = [
        f"Domains: {len(domains)} (+{len(new_domains)} new)",
        f"IPv4: {len(ipv4)} (+{len(new_ipv4)} new)",
        f"IPv6: {len(ipv6)} (+{len(new_ipv6)} new)",
    ]
    if warnings:
        lines.append("\nWarnings:")
        lines.extend(f"- {w}" for w in warnings)

    return UpdateResult(
        ok=True,
        message="\n".join(lines),
        domains=len(domains),
        ipv4=len(ipv4),
        ipv6=len(ipv6),
        added_domains=len(new_domains),
        added_ipv4=len(new_ipv4),
        added_ipv6=len(new_ipv6),
    )


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(extra_args: list[str] | None = None) -> None:
    if getattr(sys, "frozen", False):
        target = sys.executable
        params = " ".join(extra_args or [])
    else:
        target = sys.executable
        params = f'"{app_dir() / "app.py"}" ' + " ".join(extra_args or [])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", target, params.strip(), None, 1)
    raise SystemExit(0)


def startup_command() -> str:
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --startup'
    return f'"{sys.executable}" "{app_dir() / "app.py"}" --startup'


def set_startup_enabled(enabled: bool) -> None:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_PATH, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, REG_VALUE_NAME, 0, winreg.REG_SZ, startup_command())
        else:
            try:
                winreg.DeleteValue(key, REG_VALUE_NAME)
            except FileNotFoundError:
                pass


def startup_enabled() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_PATH, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, REG_VALUE_NAME)
            return True
    except FileNotFoundError:
        return False


def find_roblox_executables() -> list[Path]:
    names = {name.lower() for name in EXECUTABLE_NAMES}
    found: dict[str, Path] = {}
    for root in SEARCH_ROOTS:
        if not root.exists():
            continue
        try:
            for path in root.rglob("*.exe"):
                if path.name.lower() in names:
                    found[str(path.resolve())] = path.resolve()
        except OSError:
            continue
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        for name in EXECUTABLE_NAMES:
            for path in Path(local_app_data).rglob(name):
                if path.is_file():
                    found[str(path.resolve())] = path.resolve()
    return sorted(found.values(), key=lambda p: str(p).lower())


def flush_dns_cache() -> None:
    subprocess.run(
        ["ipconfig", "/flushdns"],
        capture_output=True,
        creationflags=CREATE_NO_WINDOW,
        check=False,
    )


def _strip_hosts_block(content: str) -> str:
    start = content.find(HOSTS_MARKER_START)
    if start == -1:
        return content.rstrip() + "\n"
    end = content.find(HOSTS_MARKER_END, start)
    if end == -1:
        return content[:start].rstrip() + "\n"
    end += len(HOSTS_MARKER_END)
    if end < len(content) and content[end] == "\n":
        end += 1
    before = content[:start].rstrip()
    after = content[end:].lstrip("\n")
    if before and after:
        return before + "\n\n" + after
    if before:
        return before + "\n"
    if after:
        return after + ("\n" if not after.endswith("\n") else "")
    return ""


def apply_hosts_block() -> None:
    all_domains = sorted(set(get_domains()) | set(DOH_DOMAINS))
    lines = [HOSTS_MARKER_START]
    for domain in all_domains:
        lines.append(f"0.0.0.0 {domain}")
        lines.append(f"::      {domain}")
    lines.append(HOSTS_MARKER_END)
    block = "\n".join(lines) + "\n"
    original = HOSTS_PATH.read_text(encoding="utf-8", errors="replace")
    cleaned = _strip_hosts_block(original)
    HOSTS_PATH.write_text(cleaned.rstrip() + "\n\n" + block, encoding="utf-8")


def remove_hosts_block() -> None:
    if not HOSTS_PATH.is_file():
        return
    original = HOSTS_PATH.read_text(encoding="utf-8", errors="replace")
    HOSTS_PATH.write_text(_strip_hosts_block(original), encoding="utf-8")


def hosts_block_active() -> bool:
    if not HOSTS_PATH.is_file():
        return False
    try:
        content = HOSTS_PATH.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return HOSTS_MARKER_START in content and HOSTS_MARKER_END in content


def _run_netsh(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["netsh", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=CREATE_NO_WINDOW,
        check=False,
    )


def _rule_name(suffix: str) -> str:
    raw = f"{RULE_PREFIX}-{suffix}"
    if len(raw) <= 240:
        return raw
    digest = hashlib.sha1(suffix.encode("utf-8")).hexdigest()[:10]
    return f"{RULE_PREFIX}-{digest}"


def _safe_token(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in value)


def _list_firewall_rules() -> list[str]:
    result = _run_netsh(["advfirewall", "firewall", "show", "rule", "name=all"])
    names: list[str] = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("rule name:"):
            name = stripped.split(":", 1)[1].strip()
            if name.startswith(RULE_PREFIX):
                names.append(name)
    return names


def _remove_firewall_rules() -> None:
    for name in _list_firewall_rules():
        _run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={name}"])


def _add_program_rule(name: str, direction: str, program: Path) -> None:
    _run_netsh([
        "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={direction}",
        "action=block", "enable=yes", f"program={program}", "profile=any",
    ])


def _add_ip_rule(name: str, direction: str, remote_ip: str) -> None:
    _run_netsh([
        "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={direction}",
        "action=block", "enable=yes", f"remoteip={remote_ip}", "profile=any",
    ])


def _add_program_udp_rule(name: str, program: Path) -> None:
    _run_netsh([
        "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=out",
        "action=block", "enable=yes", "protocol=UDP", "remoteport=49152-65535",
        f"program={program}", "profile=any",
    ])


def _add_doh_firewall_rules() -> None:
    for idx, ip in enumerate(DOH_SERVER_IPV4):
        token = _safe_token(ip)
        for proto in ("TCP", "UDP"):
            _run_netsh([
                "advfirewall", "firewall", "add", "rule",
                f"name={_rule_name(f'DoH-v4-{idx}-{proto}-{token}')}", "dir=out",
                "action=block", "enable=yes", f"protocol={proto}",
                f"remoteip={ip}", "remoteport=443,853", "profile=any",
            ])
    for idx, ip in enumerate(DOH_SERVER_IPV6):
        token = _safe_token(ip)
        for proto in ("TCP", "UDP"):
            _run_netsh([
                "advfirewall", "firewall", "add", "rule",
                f"name={_rule_name(f'DoH-v6-{idx}-{proto}-{token}')}", "dir=out",
                "action=block", "enable=yes", f"protocol={proto}",
                f"remoteip={ip}", "remoteport=443,853", "profile=any",
            ])


def _ps_resolve(domains: list[str], dns_server: str | None = None) -> tuple[set[str], set[str]]:
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    if not domains:
        return ipv4, ipv6
    server_arg = f" -Server {dns_server}" if dns_server else ""
    domains_ps = ", ".join(f'"{d}"' for d in domains)
    script = (
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        f"@({domains_ps}) | ForEach-Object {{\n"
        f"  (Resolve-DnsName -Name $_ -Type A{server_arg}).IPAddress\n"
        f"  (Resolve-DnsName -Name $_ -Type AAAA{server_arg}).IPAddress\n"
        "}}"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            creationflags=CREATE_NO_WINDOW, timeout=30, check=False,
        )
        ipv4_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
        ipv6_re = re.compile(r"^[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}$")
        for line in r.stdout.splitlines():
            ip = line.strip()
            if ipv4_re.match(ip):
                ipv4.add(ip)
            elif ipv6_re.match(ip):
                ipv6.add(ip)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return ipv4, ipv6


def _resolve_roblox_ips() -> tuple[set[str], set[str]]:
    return _ps_resolve(KEY_DOMAINS_TO_RESOLVE, dns_server="8.8.8.8")


def apply_firewall_block(
    executables: list[Path],
    resolved_ipv4: set[str] | None = None,
    resolved_ipv6: set[str] | None = None,
) -> None:
    _remove_firewall_rules()
    for idx, exe in enumerate(executables):
        token = _safe_token(exe.stem)
        _add_program_rule(_rule_name(f"Prog-{idx}-{token}-Out"), "out", exe)
        _add_program_rule(_rule_name(f"Prog-{idx}-{token}-In"), "in", exe)
        if exe.name.lower() == "robloxplayerbeta.exe":
            _add_program_udp_rule(_rule_name(f"Prog-{idx}-{token}-UDP"), exe)
    for idx, cidr in enumerate(get_ipv4_ranges()):
        token = _safe_token(cidr)
        _add_ip_rule(_rule_name(f"IPv4-{idx}-{token}-Out"), "out", cidr)
        _add_ip_rule(_rule_name(f"IPv4-{idx}-{token}-In"), "in", cidr)
    for idx, cidr in enumerate(get_ipv6_ranges()):
        token = _safe_token(cidr)
        _add_ip_rule(_rule_name(f"IPv6-{idx}-{token}-Out"), "out", cidr)
        _add_ip_rule(_rule_name(f"IPv6-{idx}-{token}-In"), "in", cidr)
    for idx, ip in enumerate(sorted(resolved_ipv4 or set())):
        token = _safe_token(ip)
        _add_ip_rule(_rule_name(f"Live-v4-{idx}-{token}-Out"), "out", ip)
        _add_ip_rule(_rule_name(f"Live-v4-{idx}-{token}-In"), "in", ip)
    for idx, ip in enumerate(sorted(resolved_ipv6 or set())):
        token = _safe_token(ip)
        _add_ip_rule(_rule_name(f"Live-v6-{idx}-{token}-Out"), "out", ip)
        _add_ip_rule(_rule_name(f"Live-v6-{idx}-{token}-In"), "in", ip)
    _add_doh_firewall_rules()


def firewall_rules_active() -> bool:
    return bool(_list_firewall_rules())


def _apply_registry_doh_block() -> None:
    try:
        with winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE, WINDOWS_DNS_KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, "EnableAutoDoh", 0, winreg.REG_DWORD, 0)
    except OSError:
        pass

    for hive, subkey in BROWSER_POLICY_KEYS:
        try:
            with winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "DnsOverHttpsMode", 0, winreg.REG_SZ, "off")
        except OSError:
            pass


def _remove_registry_doh_block() -> None:
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, WINDOWS_DNS_KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.DeleteValue(key, "EnableAutoDoh")
    except (FileNotFoundError, OSError):
        pass

    for hive, subkey in BROWSER_POLICY_KEYS:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, "DnsOverHttpsMode")
        except (FileNotFoundError, OSError):
            pass


def _apply_firefox_doh_policy() -> None:
    for firefox_dir in FIREFOX_DIRS:
        if not firefox_dir.is_dir():
            continue
        dist_dir = firefox_dir / "distribution"
        try:
            dist_dir.mkdir(exist_ok=True)
            policy_file = dist_dir / "policies.json"
            data: dict = {}
            if policy_file.is_file():
                try:
                    data = json.loads(policy_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    data = {}
            data.setdefault("policies", {}).update({
                "DNSOverHTTPS": {"Enabled": False, "Locked": True},
                "Proxy": {"Mode": "system", "Locked": True},
            })
            policy_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError:
            pass


def _remove_firefox_doh_policy() -> None:
    for firefox_dir in FIREFOX_DIRS:
        policy_file = firefox_dir / "distribution" / "policies.json"
        if not policy_file.is_file():
            continue
        try:
            data = json.loads(policy_file.read_text(encoding="utf-8"))
            policies = data.get("policies", {})
            policies.pop("DNSOverHTTPS", None)
            policies.pop("Proxy", None)
            if not policies:
                data.pop("policies", None)
            if data:
                policy_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            else:
                policy_file.unlink(missing_ok=True)
        except (OSError, json.JSONDecodeError):
            pass


class RobloxBlocker:
    def is_active(self) -> bool:
        return hosts_block_active() or firewall_rules_active()

    def enable_block(self) -> None:
        if not is_admin():
            raise BlockError("admin_required")
        resolved_v4, resolved_v6 = _resolve_roblox_ips()
        apply_firewall_block(find_roblox_executables(), resolved_v4, resolved_v6)
        apply_hosts_block()
        _apply_registry_doh_block()
        _apply_firefox_doh_policy()
        flush_dns_cache()

    def disable_block(self) -> None:
        if not is_admin():
            raise BlockError("admin_required")
        remove_hosts_block()
        _remove_firewall_rules()
        _remove_registry_doh_block()
        _remove_firefox_doh_policy()
        remove_system_proxy()
        flush_dns_cache()

    def sync_block(self, blocked: bool) -> None:
        if blocked:
            self.enable_block()
        else:
            self.disable_block()


PROXY_PORT = 8877
_IE_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

_BLOCKED_SUFFIXES = (
    "roblox.com", "rbxcdn.com", "robloxdev.com", "rbx.com", "roblox.ru",
    "roblox.cn", "bloxstrap.org", "bloxstrap.com", "fishstrap.app",
    "arkoselabs.com", "rbx.io", "simulprod.com",
)


def _is_roblox_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in _BLOCKED_SUFFIXES)


class RobloxProxy:
    PORT = PROXY_PORT

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_running():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._thread = None

    def _serve(self) -> None:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("127.0.0.1", self.PORT))
            self._sock.listen(128)
        except OSError:
            return
        while not self._stop.is_set():
            self._sock.settimeout(1.0)
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(15.0)
            buf = b""
            while b"\r\n\r\n" not in buf and len(buf) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk

            first_line = buf.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
            parts = first_line.split()
            if len(parts) < 2:
                return

            method, target = parts[0].upper(), parts[1]

            if method == "CONNECT":
                host = target.split(":")[0]
                port = int(target.split(":")[1]) if ":" in target else 443
                if _is_roblox_host(host):
                    conn.sendall(b"HTTP/1.1 403 Blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    return
                remote = socket.create_connection((host, port), timeout=15)
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                conn.settimeout(None)
                remote.settimeout(None)
                _relay(conn, remote)
            else:
                host = ""
                for line in buf.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"host:"):
                        host = line.split(b":", 1)[1].strip().decode("utf-8", errors="ignore").split(":")[0]
                        break
                if host and _is_roblox_host(host):
                    conn.sendall(b"HTTP/1.1 403 Blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _relay(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 120)
            if not r:
                break
            for s in r:
                data = s.recv(32768)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


def set_system_proxy(host: str = "127.0.0.1", port: int = PROXY_PORT) -> None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE_SETTINGS, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
            winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*;::1;<local>")
    except OSError:
        pass
    _refresh_wininet()


def remove_system_proxy() -> None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IE_SETTINGS, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            for name in ("ProxyServer", "ProxyOverride"):
                try:
                    winreg.DeleteValue(k, name)
                except FileNotFoundError:
                    pass
    except OSError:
        pass
    _refresh_wininet()


def _refresh_wininet() -> None:
    try:
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)
        wininet.InternetSetOptionW(0, 37, 0, 0)
    except OSError:
        pass


load_blocklists()
