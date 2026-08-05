#!/usr/bin/env python3
"""
================================================================================
 Wi-Fi Credential Audit Tool
================================================================================
Description:
    Enterprise-grade, single-file Wi-Fi credential extraction and reporting
    utility for Windows, Linux, macOS, and Android (rooted). Designed for
    authorized security assessments, digital forensics, system
    administration, and incident response on systems you own or have
    explicit written authorization to audit.

Purpose:
    Enumerate saved Wi-Fi profiles on the local host, recover stored
    credentials where accessible, deduplicate results across multiple
    sources (e.g. NetworkManager + iwd), and produce audit-ready reports
    in several formats.

Supported platforms:
    - Windows (netsh)
    - Linux   (NetworkManager, wpa_supplicant, iwd)
    - macOS   (Keychain via PlistBuddy / networksetup / security)
    - Android (rooted; WifiConfigStore.xml, wpa_supplicant.conf)

Usage examples:
    sudo python3 wifi_extractor_v2.py
    sudo python3 wifi_extractor_v2.py --format txt csv json
    sudo python3 wifi_extractor_v2.py --format html md --output /tmp/audit
    sudo python3 wifi_extractor_v2.py --show-passwords --verbose
    sudo python3 wifi_extractor_v2.py --diagnostics
    sudo python3 wifi_extractor_v2.py --benchmark
    sudo python3 wifi_extractor_v2.py --self-test
    sudo python3 wifi_extractor_v2.py --ssid-filter "Corp-*" --format csv
    sudo python3 wifi_extractor_v2.py --no-dedup --format json

Author:      <your name / team>
Version:     2.0.0
License:     <internal use / company license placeholder>

Changelog:
    2.0.0 - Plugin-style extractor registry, configparser-based NetworkManager
            parsing, cross-source deduplication, ReportGenerator (txt/csv/
            json/html/md/yaml/sqlite), unified --format flag, progress
            system with Rich/tqdm/text fallback, --diagnostics/--benchmark/
            --self-test, custom exception hierarchy, structured logging,
            optional config file, filtering, password reuse/strength
            analysis, report manifest + SHA-256 hashes, optional ZIP bundling.
    1.x   - Original per-platform extractor classes (see prior revisions).
================================================================================
"""

from __future__ import annotations

# =============================================================================
# SECTION: Imports
# =============================================================================

import argparse
import concurrent.futures
import configparser
import csv
import getpass
import hashlib
import io
import json
import logging
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional
from xml.etree import ElementTree

# --- Optional third-party dependencies (never required) --------------------

try:
    import yaml  # PyYAML
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

try:
    from rich.progress import (
        Progress, BarColumn, TextColumn, TimeElapsedColumn,
        TimeRemainingColumn, SpinnerColumn,
    )
    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False

try:
    from tqdm import tqdm
    HAVE_TQDM = True
except ImportError:
    HAVE_TQDM = False

try:
    import resource  # POSIX only — peak memory
    HAVE_RESOURCE = True
except ImportError:
    HAVE_RESOURCE = False


# =============================================================================
# SECTION: Constants
# =============================================================================

SCRIPT_VERSION = "2.0.0"
SCRIPT_NAME = "wifi_extractor_v2"
DEFAULT_LOG_FILE = "wifi_export.log"
DEFAULT_CONFIG_FILENAMES = ("wifi_export.yaml", "wifi_export.yml", "wifi_export.json")
SUPPORTED_FORMATS = ("txt", "csv", "json", "html", "md", "yaml", "sqlite")
PASSWORD_MASK = "********"
FILENAME_INVALID_CHARS = r'[<>:"/\\|?*\x00-\x1f\s]'


# =============================================================================
# SECTION: Regex Patterns (compiled once, module-level — never inside loops)
# =============================================================================

RE_WIN_PROFILE_NAME = re.compile(r"(?:All User Profile|User Profile|Profile)\s*:\s*(.+)", re.IGNORECASE)
RE_WIN_KEY_CONTENT = re.compile(r"Key Content\s*:\s*(.+)", re.IGNORECASE)
RE_WIN_AUTH = re.compile(r"Authentication\s*:\s*(.+)", re.IGNORECASE)
RE_WIN_HIDDEN = re.compile(r"Hidden Network\s*:\s*(.+)", re.IGNORECASE)

RE_PLISTBUDDY_DICT = re.compile(r'^\s*"([^"]+)"\s*=>\s*Dict')
RE_NETWORKSETUP_DEVICE = re.compile(r"Device:\s*(\w+)")

RE_WPA_SSID = re.compile(r'ssid\s*=\s*"?([^"\n]+)"?')
RE_WPA_PSK = re.compile(r'psk\s*=\s*"?([0-9a-fA-F]{64}|[^"\n]+)"?')
RE_WPA_KEY_MGMT = re.compile(r"key_mgmt\s*=\s*(.+)")
RE_WPA_EAP = re.compile(r"eap\s*=\s*(.+)", re.IGNORECASE)

RE_IWD_PSK = re.compile(r"^PreSharedKey\s*=\s*(.+)$")

RE_FILENAME_SANITIZE = re.compile(FILENAME_INVALID_CHARS)

# Enterprise / EAP method detection, checked against key-mgmt / eap fields
EAP_METHOD_PATTERNS: dict[str, re.Pattern] = {
    "PEAP": re.compile(r"\bpeap\b", re.IGNORECASE),
    "TTLS": re.compile(r"\bttls\b", re.IGNORECASE),
    "TLS": re.compile(r"(?<!T)\btls\b", re.IGNORECASE),
    "FAST": re.compile(r"\bfast\b", re.IGNORECASE),
    "SIM": re.compile(r"\bsim\b", re.IGNORECASE),
    "AKA": re.compile(r"\baka\b", re.IGNORECASE),
}


# =============================================================================
# SECTION: Exceptions
# =============================================================================

class WifiExtractorError(Exception):
    """Base class for all tool-specific exceptions."""


class ExtractionError(WifiExtractorError):
    """Raised when an extractor cannot complete its extraction pass."""


class PermissionDeniedError(WifiExtractorError):
    """Raised when required elevated privileges are missing."""


class UnsupportedPlatformError(WifiExtractorError):
    """Raised when no extractor is registered for the current OS."""


class ConfigParseError(WifiExtractorError):
    """Raised when a configuration source (INI/YAML/JSON) is malformed."""

    def __init__(self, filename: str, reason: str):
        self.filename = filename
        self.reason = reason
        super().__init__(f"{filename}: {reason}")


class XMLParseError(WifiExtractorError):
    """Raised when Android XML config fails validation or parsing."""

    def __init__(self, filename: str, reason: str):
        self.filename = filename
        self.reason = reason
        super().__init__(f"{filename}: {reason}")


class CredentialParseError(WifiExtractorError):
    """Raised when a single credential entry cannot be parsed."""


class ReportGenerationError(WifiExtractorError):
    """Raised when a report format fails to render."""


class OutputWriteError(WifiExtractorError):
    """Raised when writing a report to disk fails."""


# =============================================================================
# SECTION: Data Models
# =============================================================================

@dataclass
class WifiCredential:
    """
    Structured representation of a single recovered (or attempted) Wi-Fi
    credential.

    `sources` tracks every extraction source that reported this SSID so
    that deduplication can merge duplicates without losing provenance.
    """
    ssid: str
    security_type: str
    password: str
    source: str
    sources: set[str] = field(default_factory=set)
    hidden: bool = False
    success: bool = True
    error_message: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.sources:
            self.sources = {self.source}

    def merge(self, other: "WifiCredential") -> None:
        """Merge metadata from a duplicate credential found elsewhere."""
        self.sources |= other.sources
        if self.security_type in ("Unknown", "Open") and other.security_type not in ("Unknown", "Open"):
            self.security_type = other.security_type
        if (not self.password or self.password in ("", "[None / Open Network]")) and other.password:
            self.password = other.password
        self.hidden = self.hidden or other.hidden

    def to_report_dict(self, show_passwords: bool = True) -> dict[str, Any]:
        d = asdict(self)
        d["sources"] = sorted(self.sources)
        if not show_passwords and self.password:
            d["password"] = PASSWORD_MASK
        return d


@dataclass
class ExecutionStats:
    """Aggregate statistics collected across a full run."""
    profiles_scanned: int = 0
    credentials_recovered: int = 0
    credentials_failed: int = 0
    duplicates_removed: int = 0
    sources_parsed: int = 0
    warnings: int = 0
    errors: int = 0
    files_written: int = 0

    extraction_seconds: float = 0.0
    report_seconds: float = 0.0
    output_write_seconds: float = 0.0
    total_seconds: float = 0.0

    parser_timings: dict[str, float] = field(default_factory=dict)
    peak_memory_kb: Optional[int] = None

    def profiles_per_second(self) -> float:
        if self.extraction_seconds <= 0:
            return 0.0
        return round(self.profiles_scanned / self.extraction_seconds, 2)


def _safe_getuser() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


@dataclass
class RunMetadata:
    """Host / environment metadata embedded into every report."""
    hostname: str = field(default_factory=platform.node)
    operating_system: str = field(default_factory=platform.system)
    os_version: str = field(default_factory=platform.release)
    architecture: str = field(default_factory=lambda: platform.machine())
    python_version: str = field(default_factory=platform.python_version)
    username: str = field(default_factory=_safe_getuser)
    script_version: str = SCRIPT_VERSION
    execution_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# =============================================================================
# SECTION: Utilities
# =============================================================================

def sanitize_filename(name: str) -> str:
    """Strip characters invalid in filenames on Windows/Linux/macOS."""
    cleaned = RE_FILENAME_SANITIZE.sub("_", name).strip("._")
    return cleaned or "unnamed"


def compute_sha256(path: Path) -> str:
    """Compute a SHA-256 hex digest for a file, streamed in chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def mask_password(password: str) -> str:
    """Return a masked representation of a password for console display."""
    if not password or password.startswith("["):
        return password
    return PASSWORD_MASK


def set_restrictive_permissions(path: Path) -> None:
    """On POSIX systems, restrict a report file to owner read/write only."""
    if os.name == "posix":
        try:
            path.chmod(0o600)
        except OSError as exc:
            logging.getLogger(SCRIPT_NAME).debug(f"Could not chmod {path}: {exc}")


def run_command(
    args: list[str],
    timeout: int = 30,
    input_text: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """
    Reusable wrapper around subprocess.run with consistent timeout and
    error handling. Always uses list-form arguments (never shell=True) to
    avoid shell injection via SSID names or paths.
    """
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise ExtractionError(f"Command not found: {args[0]} ({exc})") from exc
    except subprocess.TimeoutExpired as exc:
        raise ExtractionError(f"Command timed out after {timeout}s: {' '.join(args)}") from exc


def classify_security(raw_auth: str, eap_hint: str = "") -> str:
    """
    Map raw authentication strings to a normalized security classification,
    including WPA/WPA2/WPA3 and enterprise EAP methods where detectable.
    """
    text = f"{raw_auth} {eap_hint}".strip()
    if not text or text.upper() in ("NONE", "OPEN"):
        return "Open"

    upper = text.upper()
    enterprise = "ENTERPRISE" in upper or "EAP" in upper or "802.1X" in upper or "8021X" in upper

    eap_methods = [name for name, pattern in EAP_METHOD_PATTERNS.items() if pattern.search(text)]

    base = "Unknown"
    if "WPA3" in upper:
        base = "WPA3"
    elif "WPA2" in upper:
        base = "WPA2"
    elif "WPA" in upper:
        base = "WPA"
    elif "WEP" in upper:
        base = "WEP"
    elif "PSK" in upper:
        base = "WPA/WPA2-PSK"

    if enterprise:
        suffix = f" Enterprise ({'/'.join(eap_methods)})" if eap_methods else " Enterprise"
        return f"{base}{suffix}" if base != "Unknown" else f"802.1X Enterprise{(' (' + '/'.join(eap_methods) + ')') if eap_methods else ''}"

    return base if base != "Unknown" else (text.strip() or "Unknown")


def deduplicate_credentials(
    credentials: list[WifiCredential],
) -> tuple[list[WifiCredential], int]:
    """
    Merge credentials that share the same SSID across multiple extraction
    sources (e.g. NetworkManager + iwd), preserving every source that
    reported it. Returns (deduplicated_list, duplicates_removed_count).
    """
    merged: dict[str, WifiCredential] = {}
    order: list[str] = []
    duplicates = 0

    for cred in credentials:
        key = cred.ssid
        if key in merged:
            merged[key].merge(cred)
            duplicates += 1
        else:
            merged[key] = cred
            order.append(key)

    return [merged[k] for k in order], duplicates


def analyze_password_reuse(credentials: list[WifiCredential]) -> dict[str, list[str]]:
    """Return {password: [ssid, ...]} for passwords reused across 2+ networks."""
    by_password: dict[str, list[str]] = {}
    for cred in credentials:
        if not cred.success or not cred.password or cred.password.startswith("["):
            continue
        by_password.setdefault(cred.password, []).append(cred.ssid)
    return {pwd: ssids for pwd, ssids in by_password.items() if len(ssids) > 1}


def estimate_password_strength(password: str) -> str:
    """Lightweight heuristic strength rating — not a substitute for a real policy check."""
    if not password or password.startswith("["):
        return "N/A"
    length = len(password)
    classes = sum([
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[^A-Za-z0-9]", password)),
    ])
    if length < 8:
        return "Weak"
    if length < 12 or classes < 3:
        return "Moderate"
    return "Strong"


# =============================================================================
# SECTION: Configuration
# =============================================================================

DEFAULT_CONFIG: dict[str, Any] = {
    "formats": ["txt"],
    "timeout": 30,
    "log_level": "INFO",
    "mask_passwords": True,
    "show_progress": True,
    "output_dir": ".",
}


def _validate_config(cfg: dict[str, Any], source: str) -> dict[str, Any]:
    """Validate loaded config keys/types; unknown keys are ignored with a warning."""
    validated = dict(DEFAULT_CONFIG)
    log = logging.getLogger(SCRIPT_NAME)

    for key, value in cfg.items():
        if key not in DEFAULT_CONFIG:
            log.warning(f"Ignoring unknown config key '{key}' in {source}")
            continue
        if key == "formats" and not isinstance(value, list):
            raise ConfigParseError(source, "'formats' must be a list")
        if key == "timeout" and not isinstance(value, (int, float)):
            raise ConfigParseError(source, "'timeout' must be numeric")
        validated[key] = value

    return validated


def load_config(explicit_path: Optional[Path] = None) -> dict[str, Any]:
    """
    Load optional configuration from wifi_export.yaml / .yml / .json in the
    current directory (or an explicit path). Falls back silently to defaults
    if nothing is present — configuration is never mandatory. Environment
    variables prefixed WIFI_EXPORT_ override any loaded value.
    """
    log = logging.getLogger(SCRIPT_NAME)
    candidates = [explicit_path] if explicit_path else [Path(f) for f in DEFAULT_CONFIG_FILENAMES]

    cfg = dict(DEFAULT_CONFIG)
    for candidate in candidates:
        if candidate is None or not candidate.exists():
            continue
        try:
            text = candidate.read_text(encoding="utf-8")
            if candidate.suffix in (".yaml", ".yml"):
                if not HAVE_YAML:
                    log.warning(f"Found {candidate} but PyYAML is not installed — skipping")
                    continue
                loaded = yaml.safe_load(text) or {}
            else:
                loaded = json.loads(text)
            cfg = _validate_config(loaded, str(candidate))
            log.info(f"Loaded configuration from {candidate}")
            break
        except json.JSONDecodeError as exc:
            raise ConfigParseError(str(candidate), f"Invalid JSON: {exc}") from exc
        except Exception as exc:
            raise ConfigParseError(str(candidate), str(exc)) from exc

    env_map = {
        "WIFI_EXPORT_TIMEOUT": ("timeout", int),
        "WIFI_EXPORT_LOG_LEVEL": ("log_level", str),
        "WIFI_EXPORT_OUTPUT_DIR": ("output_dir", str),
    }
    for env_var, (key, caster) in env_map.items():
        if env_var in os.environ:
            try:
                cfg[key] = caster(os.environ[env_var])
                log.debug(f"Config override from {env_var}")
            except ValueError:
                log.warning(f"Ignoring invalid environment override {env_var}")

    return cfg


# =============================================================================
# SECTION: Logging
# =============================================================================

def configure_logging(verbose: bool, quiet: bool, log_file: Optional[Path]) -> logging.Logger:
    """Configure module-level logging with timestamps, level, and optional file output."""
    logger = logging.getLogger(SCRIPT_NAME)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    console.setFormatter(fmt)
    logger.addHandler(console)

    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(fmt)
            logger.addHandler(file_handler)
        except OSError as exc:
            logger.warning(f"Could not open log file {log_file}: {exc}")

    return logger


# =============================================================================
# SECTION: Progress System (Rich -> tqdm -> plain text fallback)
# =============================================================================

class ProgressReporter:
    """
    Unified progress interface. Automatically prefers Rich, then tqdm, then
    a plain textual fallback that always works with only the standard
    library. Disabled only via explicit --no-progress or --quiet; it does
    not auto-hide itself based on stream redirection.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._rich_progress: Optional["Progress"] = None
        self._rich_task = None
        self._tqdm_bar = None
        self._label = ""
        self._total = 0
        self._count = 0
        self._start = 0.0

    def start(self, label: str, total: int) -> None:
        self._label, self._total, self._count = label, max(total, 1), 0
        self._start = time.perf_counter()
        if not self.enabled:
            return

        if HAVE_RICH:
            self._rich_progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TextColumn("{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
            )
            self._rich_progress.start()
            self._rich_task = self._rich_progress.add_task(label, total=self._total)
        elif HAVE_TQDM:
            self._tqdm_bar = tqdm(total=self._total, desc=label, unit="item")
        else:
            print(f"[{label}] starting ({self._total} item(s))...")

    def advance(self, step: int = 1) -> None:
        self._count += step
        if not self.enabled:
            return
        if HAVE_RICH and self._rich_progress:
            self._rich_progress.update(self._rich_task, advance=step)
        elif HAVE_TQDM and self._tqdm_bar:
            self._tqdm_bar.update(step)
        else:
            elapsed = time.perf_counter() - self._start
            rate = self._count / elapsed if elapsed > 0 else 0
            pct = min(100, int(100 * self._count / self._total))
            print(f"\r[{self._label}] {pct:3d}%  {self._count}/{self._total}  "
                  f"{rate:.1f} items/s  elapsed {elapsed:.1f}s", end="", flush=True)

    def finish(self) -> None:
        if not self.enabled:
            return
        if HAVE_RICH and self._rich_progress:
            self._rich_progress.stop()
            self._rich_progress = None
        elif HAVE_TQDM and self._tqdm_bar:
            self._tqdm_bar.close()
            self._tqdm_bar = None
        else:
            print()


# =============================================================================
# SECTION: Platform Detection (single source of truth)
# =============================================================================

ANDROID_INDICATORS = (
    Path("/system/bin/app_process"),
    Path("/system/framework/framework.jar"),
    Path("/system/build.prop"),
)


def is_android() -> bool:
    """The one and only Android-detection routine used anywhere in the tool."""
    return any(p.exists() for p in ANDROID_INDICATORS)


def current_platform_key() -> str:
    """
    Resolve the current OS to the key used by the extractor registry.
    Android is treated as a distinct platform even though platform.system()
    reports 'Linux'.
    """
    system = platform.system()
    if system == "Linux" and is_android():
        return "Android"
    return system


def is_privileged() -> bool:
    """Cross-platform elevated-privilege check (root / Administrator)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


# =============================================================================
# SECTION: Base Extractor + Plugin Registry
# =============================================================================

EXTRACTOR_REGISTRY: dict[str, type["WifiExtractor"]] = {}


def register_extractor(platform_key: str) -> Callable[[type], type]:
    """
    Class decorator that registers an extractor under a platform key.
    Adding support for a new OS in the future means writing a new
    WifiExtractor subclass and decorating it — the dispatcher in
    get_extractor() never needs to change.
    """
    def decorator(cls: type["WifiExtractor"]) -> type["WifiExtractor"]:
        EXTRACTOR_REGISTRY[platform_key] = cls
        return cls
    return decorator


class WifiExtractor:
    """Base class for all platform-specific Wi-Fi credential extractors."""

    display_name: str = "Generic"

    def __init__(self, timeout: int = 30, progress: Optional[ProgressReporter] = None):
        self.timeout = timeout
        self.progress = progress
        self.credentials: list[WifiCredential] = []
        self.log = logging.getLogger(SCRIPT_NAME)
        self.parser_timings: dict[str, float] = {}

    def extract(self) -> list[WifiCredential]:
        """Subclasses must implement and return a list of WifiCredential."""
        raise NotImplementedError

    def _add_error(self, ssid: str, source: str, error: str) -> None:
        self.credentials.append(
            WifiCredential(
                ssid=ssid, security_type="Unknown", password="",
                source=source, success=False, error_message=error,
            )
        )

    def _timed(self, name: str, fn: Callable[[], Any]) -> Any:
        """Run a parser step and record its wall-clock time for benchmarking."""
        start = time.perf_counter()
        try:
            return fn()
        finally:
            self.parser_timings[name] = round(time.perf_counter() - start, 4)


def get_extractor(timeout: int, progress: Optional[ProgressReporter]) -> WifiExtractor:
    """Instantiate the extractor registered for the current platform."""
    key = current_platform_key()
    extractor_cls = EXTRACTOR_REGISTRY.get(key)
    if extractor_cls is None:
        raise UnsupportedPlatformError(
            f"No extractor registered for platform '{key}'. "
            f"Supported: {', '.join(EXTRACTOR_REGISTRY)}"
        )
    return extractor_cls(timeout=timeout, progress=progress)


# =============================================================================
# SECTION: Windows Extractor
# =============================================================================

@register_extractor("Windows")
class WindowsExtractor(WifiExtractor):
    """Extracts Wi-Fi credentials via `netsh wlan` on Windows."""

    display_name = "Windows netsh"

    def _get_profile_names(self) -> list[str]:
        result = run_command(["netsh", "wlan", "show", "profiles"], timeout=self.timeout)
        if result.returncode != 0:
            raise ExtractionError("Failed to retrieve Wi-Fi profile list from netsh")
        return [m.strip() for m in RE_WIN_PROFILE_NAME.findall(result.stdout)]

    def _extract_one_profile(self, profile: str) -> WifiCredential:
        try:
            result = run_command(
                ["netsh", "wlan", "show", "profile", f"name={profile}", "key=clear"],
                timeout=self.timeout,
            )
        except ExtractionError as exc:
            return WifiCredential(
                ssid=profile, security_type="Unknown", password="",
                source=self.display_name, success=False, error_message=str(exc),
            )

        if result.returncode != 0:
            return WifiCredential(
                ssid=profile, security_type="Unknown", password="",
                source=self.display_name, success=False,
                error_message="netsh returned a non-zero exit code",
            )

        output = result.stdout
        pwd_match = RE_WIN_KEY_CONTENT.search(output)
        auth_match = RE_WIN_AUTH.search(output)
        hidden_match = RE_WIN_HIDDEN.search(output)

        password = pwd_match.group(1).strip() if pwd_match else "[None / Open Network]"
        raw_auth = auth_match.group(1).strip() if auth_match else ""
        hidden = bool(hidden_match and hidden_match.group(1).strip().lower() == "yes")

        return WifiCredential(
            ssid=profile,
            security_type=classify_security(raw_auth),
            password=password,
            source=self.display_name,
            hidden=hidden,
        )

    def extract(self) -> list[WifiCredential]:
        profiles = self._timed("list_profiles", self._get_profile_names)
        self.log.info(f"Found {len(profiles)} Wi-Fi profile(s)")

        if self.progress:
            self.progress.start("Extracting Windows profiles", len(profiles))

        # Parallelized: each profile requires its own netsh subprocess call,
        # and these are independent I/O-bound operations — a real win here,
        # unlike the sequential, filesystem-bound Linux parsers below.
        def _worker(name: str) -> WifiCredential:
            cred = self._extract_one_profile(name)
            if self.progress:
                self.progress.advance()
            return cred

        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(profiles)))) as pool:
            self.credentials = list(pool.map(_worker, profiles))
        self.parser_timings["extract_profiles_parallel"] = round(time.perf_counter() - start, 4)

        if self.progress:
            self.progress.finish()

        return self.credentials


# =============================================================================
# SECTION: Linux Extractor
# =============================================================================

def parse_wpa_supplicant_text(content: str, source: str) -> list[WifiCredential]:
    """
    Shared wpa_supplicant.conf parser used by both LinuxExtractor and
    AndroidExtractor, eliminating the duplicated parsing logic that existed
    between the two platforms in earlier revisions.
    """
    results: list[WifiCredential] = []
    current_ssid: Optional[str] = None
    current_psk: Optional[str] = None
    current_key_mgmt = ""
    current_eap = ""

    def flush():
        if current_ssid is not None:
            security = classify_security(current_key_mgmt, current_eap)
            password = current_psk or ("[None / Open Network]" if security == "Open" else "[Enterprise/Unknown]")
            results.append(WifiCredential(
                ssid=current_ssid, security_type=security, password=password, source=source,
            ))

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("network={"):
            flush()
            current_ssid, current_psk, current_key_mgmt, current_eap = None, None, "", ""
            continue

        if (m := RE_WPA_SSID.match(line)):
            current_ssid = m.group(1)
        elif (m := RE_WPA_PSK.match(line)):
            current_psk = m.group(1)
        elif (m := RE_WPA_KEY_MGMT.match(line)):
            current_key_mgmt = m.group(1)
        elif (m := RE_WPA_EAP.match(line)):
            current_eap = m.group(1)

    flush()
    return results


@register_extractor("Linux")
class LinuxExtractor(WifiExtractor):
    """
    Extracts Wi-Fi credentials from NetworkManager (via configparser),
    wpa_supplicant, and iwd. Kept sequential: these are fast local file
    reads, and benchmarking (see --benchmark parser_timings output) showed
    no measurable benefit from threading here, unlike the Windows extractor.
    """

    display_name = "Linux"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.nm_connections_path = Path("/etc/NetworkManager/system-connections")
        self.wpa_supplicant_path = Path("/etc/wpa_supplicant")
        self.iwd_path = Path("/var/lib/iwd")

    def _parse_networkmanager_file(self, file_path: Path) -> Optional[WifiCredential]:
        parser = configparser.ConfigParser(strict=False, interpolation=None)
        parser.optionxform = str  # type: ignore[assignment]  # preserve key case

        try:
            raw = file_path.read_text(encoding="utf-8", errors="replace")
            parser.read_string(raw)
        except configparser.Error as exc:
            raise ConfigParseError(str(file_path), f"INI parse error: {exc}") from exc
        except OSError as exc:
            raise ConfigParseError(str(file_path), f"Could not read file: {exc}") from exc

        if "wifi" not in parser or "ssid" not in parser["wifi"]:
            return None  # not a Wi-Fi connection profile

        ssid = parser["wifi"]["ssid"].strip('"')
        hidden = parser["wifi"].getboolean("hidden", fallback=False)

        password = "[None / Open Network]"
        raw_key_mgmt = ""
        if parser.has_section("wifi-security"):
            sec = parser["wifi-security"]
            raw_key_mgmt = sec.get("key-mgmt", "")
            if sec.get("psk"):
                password = sec.get("psk").strip('"')
            elif raw_key_mgmt.upper() not in ("", "NONE"):
                password = "[Enterprise - credentials not stored in plaintext]"

        return WifiCredential(
            ssid=ssid, security_type=classify_security(raw_key_mgmt),
            password=password, source="NetworkManager", hidden=hidden,
        )

    def _parse_networkmanager(self) -> list[WifiCredential]:
        results: list[WifiCredential] = []
        if not self.nm_connections_path.exists():
            return results

        for conn_file in self.nm_connections_path.iterdir():
            if not conn_file.is_file() or conn_file.suffix not in (".nmconnection", "", ".conf"):
                continue
            try:
                cred = self._parse_networkmanager_file(conn_file)
                if cred:
                    results.append(cred)
            except ConfigParseError as exc:
                self.log.warning(f"Skipping malformed NM connection file: {exc}")
                self._add_error(conn_file.stem, "NetworkManager", str(exc))

        return results

    def _parse_wpa_supplicant(self) -> list[WifiCredential]:
        results: list[WifiCredential] = []
        if not self.wpa_supplicant_path.exists():
            return results

        for conf_file in self.wpa_supplicant_path.glob("*.conf"):
            try:
                results.extend(parse_wpa_supplicant_text(
                    conf_file.read_text(encoding="utf-8", errors="replace"),
                    source="wpa_supplicant",
                ))
            except OSError as exc:
                self.log.warning(f"Could not read {conf_file}: {exc}")
                self._add_error(conf_file.stem, "wpa_supplicant", str(exc))

        return results

    def _parse_iwd(self) -> list[WifiCredential]:
        results: list[WifiCredential] = []
        if not self.iwd_path.exists():
            return results

        valid_suffixes = {".psk", ".open", ".8021x"}
        for network_file in self.iwd_path.glob("*"):
            if network_file.is_dir() or network_file.suffix not in valid_suffixes:
                continue
            try:
                ssid = network_file.stem
                content = network_file.read_text(encoding="utf-8", errors="replace")
                password = "[None / Open Network]"
                security = "Open" if network_file.suffix == ".open" else "WPA/WPA2-PSK"

                if "[Security]" in content:
                    for line in content.splitlines():
                        match = RE_IWD_PSK.match(line.strip())
                        if match:
                            password = match.group(1).strip()
                            break

                results.append(WifiCredential(
                    ssid=ssid, security_type=security, password=password, source="iwd",
                ))
            except OSError as exc:
                self.log.warning(f"Could not read {network_file}: {exc}")
                self._add_error(network_file.stem, "iwd", str(exc))

        return results

    def extract(self) -> list[WifiCredential]:
        sources: list[tuple[str, Callable[[], list[WifiCredential]]]] = [
            ("NetworkManager", self._parse_networkmanager),
            ("wpa_supplicant", self._parse_wpa_supplicant),
            ("iwd", self._parse_iwd),
        ]

        if self.progress:
            self.progress.start("Parsing Linux Wi-Fi sources", len(sources))

        for name, fn in sources:
            found = self._timed(f"parse_{name.lower()}", fn)
            self.credentials.extend(found)
            if self.progress:
                self.progress.advance()

        if self.progress:
            self.progress.finish()

        self.log.info(f"Found {len(self.credentials)} credential(s) across {len(sources)} sources")
        return self.credentials


# =============================================================================
# SECTION: macOS Extractor
# =============================================================================

@register_extractor("Darwin")
class MacOSExtractor(WifiExtractor):
    """Extracts Wi-Fi credentials from the macOS Keychain."""

    display_name = "macOS Keychain"

    def _get_known_networks(self) -> list[str]:
        try:
            result = run_command(
                ["/usr/libexec/PlistBuddy", "-c", "Print :KnownNetworks",
                 "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"],
                timeout=self.timeout,
            )
            if result.returncode == 0:
                return [m.group(1) for line in result.stdout.splitlines()
                        if (m := RE_PLISTBUDDY_DICT.match(line))]
        except ExtractionError as exc:
            self.log.debug(f"PlistBuddy failed: {exc}")

        return self._get_networks_fallback()

    def _get_networks_fallback(self) -> list[str]:
        try:
            result = run_command(["networksetup", "-listallhardwareports"], timeout=self.timeout)
        except ExtractionError as exc:
            self.log.warning(f"networksetup unavailable: {exc}")
            return []

        wifi_device = None
        lines = result.stdout.splitlines()
        for idx, line in enumerate(lines):
            if "Wi-Fi" in line and idx + 1 < len(lines):
                if (m := RE_NETWORKSETUP_DEVICE.search(lines[idx + 1])):
                    wifi_device = m.group(1)
                    break

        if not wifi_device:
            self.log.warning("Could not identify Wi-Fi hardware device")
            return []

        try:
            result = run_command(
                ["networksetup", "-listpreferredwirelessnetworks", wifi_device],
                timeout=self.timeout,
            )
        except ExtractionError as exc:
            self.log.warning(f"Could not list preferred networks: {exc}")
            return []

        if result.returncode != 0:
            return []
        return [n.strip() for n in result.stdout.splitlines()[1:] if n.strip()]

    def _get_password(self, ssid: str) -> tuple[Optional[str], Optional[str]]:
        """Returns (password, error_message)."""
        try:
            result = run_command(
                ["security", "find-generic-password", "-wa", ssid], timeout=self.timeout,
            )
        except ExtractionError as exc:
            return None, str(exc)

        if result.returncode == 0:
            return result.stdout.strip(), None
        if result.returncode == 36:  # errSecItemNotFound
            return None, None
        if result.returncode == 25293:  # errSecAuthFailed
            return None, "Keychain authentication denied (user declined access prompt)"
        return None, f"security exited with code {result.returncode}"

    def extract(self) -> list[WifiCredential]:
        networks = self._timed("list_known_networks", self._get_known_networks)
        self.log.info(f"Found {len(networks)} known network(s)")

        if self.progress:
            self.progress.start("Querying macOS Keychain", len(networks))

        for ssid in networks:
            password, error = self._get_password(ssid)
            if password:
                self.credentials.append(WifiCredential(
                    ssid=ssid, security_type="Keychain (WPA/WPA2/WPA3)",
                    password=password, source=self.display_name,
                ))
            elif error:
                self.credentials.append(WifiCredential(
                    ssid=ssid, security_type="Unknown", password="",
                    source=self.display_name, success=False, error_message=error,
                ))
            else:
                self.credentials.append(WifiCredential(
                    ssid=ssid, security_type="Unknown/No Password",
                    password="[None / Open Network]", source=self.display_name,
                    error_message="No password found in keychain",
                ))
            if self.progress:
                self.progress.advance()

        if self.progress:
            self.progress.finish()

        return self.credentials


# =============================================================================
# SECTION: Android Extractor
# =============================================================================

@register_extractor("Android")
class AndroidExtractor(WifiExtractor):
    """Extracts Wi-Fi credentials from a rooted Android device."""

    display_name = "Android"

    CONFIG_PATHS = (
        Path("/data/misc/wifi/WifiConfigStore.xml"),
        Path("/data/misc/wifi/wpa_supplicant.conf"),
        Path("/data/wifi/WifiConfigStore.xml"),
    )

    def _run_as_root(self, command: list[str]) -> Optional[str]:
        for prefix in (["su", "-c"], ["sudo"]):
            try:
                result = run_command(prefix + command, timeout=self.timeout)
                if result.returncode == 0:
                    return result.stdout
            except ExtractionError as exc:
                self.log.debug(f"{prefix[0]} attempt failed: {exc}")
        return None

    def _validate_wifi_config_xml(self, xml_content: str, source_path: str) -> ElementTree.Element:
        """Validate structure before trusting the XML — never parse blindly."""
        if not xml_content.strip():
            raise XMLParseError(source_path, "Empty configuration file")
        try:
            root = ElementTree.fromstring(xml_content)
        except ElementTree.ParseError as exc:
            raise XMLParseError(source_path, f"Malformed XML: {exc}") from exc

        if root.tag not in ("WifiConfigStoreData", "map"):
            self.log.debug(f"Unexpected root element '{root.tag}' in {source_path} — continuing cautiously")

        if root.find(".//Network") is None:
            raise XMLParseError(source_path, "No <Network> nodes found — unexpected schema or empty store")

        return root

    def _parse_wifi_config_store(self, xml_content: str, source_path: str) -> list[WifiCredential]:
        root = self._validate_wifi_config_xml(xml_content, source_path)
        results: list[WifiCredential] = []

        for network in root.iter("Network"):
            ssid_elem = network.find("string[@name='SSID']")
            if ssid_elem is None or not ssid_elem.text:
                continue  # required field missing — skip rather than guess

            psk_elem = network.find("string[@name='PreSharedKey']")
            key_mgmt_elem = network.find("string[@name='KeyMgmt']")
            hidden_elem = network.find("boolean[@name='HiddenSSID']")

            ssid = ssid_elem.text.strip('"')
            password = psk_elem.text.strip('"') if psk_elem is not None and psk_elem.text else "[None / Open Network]"
            raw_key_mgmt = key_mgmt_elem.text if key_mgmt_elem is not None and key_mgmt_elem.text else ""
            hidden = bool(hidden_elem is not None and hidden_elem.get("value") == "true")

            results.append(WifiCredential(
                ssid=ssid,
                security_type=classify_security(raw_key_mgmt),
                password=password,
                source="Android WifiConfigStore",
                hidden=hidden,
            ))

        return results

    def extract(self) -> list[WifiCredential]:
        if self.progress:
            self.progress.start("Extracting Android configuration", len(self.CONFIG_PATHS))

        found_any_config = False
        for config_path in self.CONFIG_PATHS:
            content = self._timed(
                f"read_{config_path.name}",
                lambda p=config_path: self._run_as_root(["cat", str(p)]),
            )
            if self.progress:
                self.progress.advance()

            if content is None:
                continue
            found_any_config = True

            try:
                if config_path.suffix == ".xml":
                    self.credentials.extend(self._parse_wifi_config_store(content, str(config_path)))
                else:
                    self.credentials.extend(parse_wpa_supplicant_text(content, source="Android wpa_supplicant"))
            except XMLParseError as exc:
                self.log.error(f"XML validation failed for {config_path}: {exc.reason}")
                self._add_error("N/A", "Android", f"{config_path}: {exc.reason}")
                continue

            if self.credentials:
                break

        if self.progress:
            self.progress.finish()

        if not self.credentials:
            reason = ("Root access required and no readable config found"
                      if not found_any_config else
                      "Configuration files were found but contained no usable entries")
            self._add_error("N/A", "Android", reason)

        self.log.info(f"Found {len(self.credentials)} credential(s)")
        return self.credentials


# =============================================================================
# SECTION: Filtering
# =============================================================================

def apply_filters(
    credentials: list[WifiCredential],
    ssid_glob: Optional[str] = None,
    ssid_regex: Optional[str] = None,
    security_type: Optional[str] = None,
) -> list[WifiCredential]:
    """Filter credentials by SSID glob/regex and/or security classification."""
    import fnmatch

    result = credentials
    if ssid_glob:
        result = [c for c in result if fnmatch.fnmatch(c.ssid, ssid_glob)]
    if ssid_regex:
        pattern = re.compile(ssid_regex)
        result = [c for c in result if pattern.search(c.ssid)]
    if security_type:
        needle = security_type.lower()
        result = [c for c in result if needle in c.security_type.lower()]
    return result


# =============================================================================
# SECTION: Reporting
# =============================================================================

def _html_escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


class ReportGenerator:
    """
    Centralized, format-agnostic report generation. All formats render from
    the same internal model (credentials + metadata + stats), eliminating
    the duplicated standalone report functions from earlier revisions.
    """

    def __init__(
        self,
        credentials: list[WifiCredential],
        metadata: RunMetadata,
        stats: ExecutionStats,
        show_passwords: bool = True,
    ):
        self.credentials = credentials
        self.metadata = metadata
        self.stats = stats
        self.show_passwords = show_passwords

    def _rows(self) -> list[dict[str, Any]]:
        return [c.to_report_dict(show_passwords=self.show_passwords) for c in self.credentials]

    def _successful(self) -> list[WifiCredential]:
        return [c for c in self.credentials if c.success]

    def _failed(self) -> list[WifiCredential]:
        return [c for c in self.credentials if not c.success]

    def render_txt(self) -> str:
        successful, failed = self._successful(), self._failed()
        lines = [
            "=" * 70,
            "          WI-FI CREDENTIALS AUDIT REPORT",
            "=" * 70,
            f"Generated : {self.metadata.execution_timestamp}",
            f"Hostname  : {self.metadata.hostname}",
            f"OS        : {self.metadata.operating_system} {self.metadata.os_version} ({self.metadata.architecture})",
            f"User      : {self.metadata.username}",
            f"Python    : {self.metadata.python_version}",
            f"Tool ver. : {self.metadata.script_version}",
            "-" * 70,
            "",
        ]

        if successful:
            lines.append(f"RECOVERED CREDENTIALS ({len(successful)}):")
            lines.append("-" * 70)
            for i, cred in enumerate(successful, 1):
                pwd = cred.password if self.show_passwords else mask_password(cred.password)
                lines.extend([
                    f"\n[{i}] {cred.ssid}{'  (hidden)' if cred.hidden else ''}",
                    f"    Security : {cred.security_type}",
                    f"    Password : {pwd}",
                    f"    Sources  : {', '.join(sorted(cred.sources))}",
                ])

        if failed:
            lines += ["", f"ERRORS ({len(failed)}):", "-" * 70]
            lines += [f"  - {c.ssid}: {c.error_message}" for c in failed]

        reused = analyze_password_reuse(self.credentials)
        if reused:
            lines += ["", "PASSWORD REUSE DETECTED:", "-" * 70]
            for pwd, ssids in reused.items():
                shown = pwd if self.show_passwords else mask_password(pwd)
                lines.append(f"  - '{shown}' used by: {', '.join(ssids)}")

        lines += [
            "",
            "STATISTICS:",
            "-" * 70,
            f"  Profiles scanned        : {self.stats.profiles_scanned}",
            f"  Credentials recovered   : {self.stats.credentials_recovered}",
            f"  Credentials failed      : {self.stats.credentials_failed}",
            f"  Duplicates merged       : {self.stats.duplicates_removed}",
            f"  Extraction time         : {self.stats.extraction_seconds:.3f}s",
            f"  Report generation time  : {self.stats.report_seconds:.3f}s",
            f"  Total runtime           : {self.stats.total_seconds:.3f}s",
            "",
            "=" * 70,
            f"SUMMARY: {len(successful)} recovered, {len(failed)} failed",
            "=" * 70,
        ]
        return "\n".join(lines)

    def render_csv(self) -> str:
        buf = io.StringIO()
        fieldnames = ["ssid", "security_type", "password", "source", "sources",
                      "hidden", "success", "error_message"]
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for row in self._rows():
            row = dict(row)
            row["sources"] = ",".join(row["sources"])
            writer.writerow(row)
        return buf.getvalue()

    def render_json(self) -> str:
        payload = {
            "metadata": asdict(self.metadata),
            "statistics": asdict(self.stats),
            "credentials": self._rows(),
        }
        return json.dumps(payload, indent=2)

    def render_yaml(self) -> str:
        if not HAVE_YAML:
            raise ReportGenerationError("PyYAML is not installed — cannot generate YAML report")
        payload = {
            "metadata": asdict(self.metadata),
            "statistics": asdict(self.stats),
            "credentials": self._rows(),
        }
        return yaml.safe_dump(payload, sort_keys=False)

    def render_markdown(self) -> str:
        successful, failed = self._successful(), self._failed()
        lines = [
            "# Wi-Fi Credentials Audit Report",
            "",
            f"- **Generated:** {self.metadata.execution_timestamp}",
            f"- **Hostname:** `{self.metadata.hostname}`",
            f"- **OS:** {self.metadata.operating_system} {self.metadata.os_version} ({self.metadata.architecture})",
            f"- **Tool version:** {self.metadata.script_version}",
            "",
            f"## Recovered Credentials ({len(successful)})",
            "",
            "| SSID | Security | Password | Sources | Hidden |",
            "|---|---|---|---|---|",
        ]
        for cred in successful:
            pwd = cred.password if self.show_passwords else mask_password(cred.password)
            lines.append(
                f"| {cred.ssid} | {cred.security_type} | `{pwd}` | "
                f"{', '.join(sorted(cred.sources))} | {'Yes' if cred.hidden else 'No'} |"
            )

        if failed:
            lines += ["", f"## Errors ({len(failed)})", "", "| SSID | Error |", "|---|---|"]
            lines += [f"| {c.ssid} | {c.error_message} |" for c in failed]

        lines += [
            "",
            "## Statistics",
            "",
            f"- Profiles scanned: {self.stats.profiles_scanned}",
            f"- Recovered: {self.stats.credentials_recovered}",
            f"- Failed: {self.stats.credentials_failed}",
            f"- Duplicates merged: {self.stats.duplicates_removed}",
            f"- Total runtime: {self.stats.total_seconds:.3f}s",
        ]
        return "\n".join(lines)

    def render_html(self) -> str:
        successful, failed = self._successful(), self._failed()
        security_counts: dict[str, int] = {}
        for c in successful:
            security_counts[c.security_type] = security_counts.get(c.security_type, 0) + 1

        chart_svg = self._render_svg_bar_chart(security_counts)

        rows_html = "\n".join(
            f"<tr class='{'row-open' if c.security_type == 'Open' else 'row-secure'}'>"
            f"<td>{_html_escape(c.ssid)}</td><td>{_html_escape(c.security_type)}</td>"
            f"<td class='mono'>{_html_escape(c.password if self.show_passwords else mask_password(c.password))}</td>"
            f"<td>{_html_escape(', '.join(sorted(c.sources)))}</td>"
            f"<td>{'Yes' if c.hidden else 'No'}</td></tr>"
            for c in successful
        )

        errors_html = "\n".join(
            f"<tr><td>{_html_escape(c.ssid)}</td><td>{_html_escape(c.error_message or '')}</td></tr>"
            for c in failed
        )

        errors_block = ""
        if failed:
            errors_block = (
                f"<div class='panel'><h2>Errors ({len(failed)})</h2>"
                f"<table><thead><tr><th>SSID</th><th>Error</th></tr></thead>"
                f"<tbody>{errors_html}</tbody></table></div>"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Wi-Fi Credentials Audit Report — {_html_escape(self.metadata.hostname)}</title>
<style>
  :root {{
    --bg: #0f172a; --panel: #1e293b; --text: #e2e8f0; --muted: #94a3b8;
    --accent: #38bdf8; --danger: #f87171; --ok: #34d399;
  }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 2rem; }}
  h1 {{ color: var(--accent); margin-bottom: 0.25rem; }}
  .subtitle {{ color: var(--muted); margin-bottom: 1.5rem; }}
  .panel {{ background: var(--panel); border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.4); }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; }}
  .stat {{ text-align: center; }}
  .stat .value {{ font-size: 1.8rem; font-weight: 700; color: var(--accent); }}
  .stat .label {{ color: var(--muted); font-size: .85rem; text-transform: uppercase; letter-spacing: .03em; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: .5rem; }}
  th, td {{ text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #334155; font-size: .9rem; }}
  th {{ color: var(--muted); text-transform: uppercase; font-size: .75rem; letter-spacing: .05em; }}
  .mono {{ font-family: ui-monospace, Consolas, monospace; }}
  .row-open td:nth-child(2) {{ color: var(--danger); font-weight: 600; }}
  .row-secure td:nth-child(2) {{ color: var(--ok); }}
  footer {{ color: var(--muted); font-size: .8rem; margin-top: 2rem; }}
</style>
</head>
<body>
  <h1>Wi-Fi Credentials Audit Report</h1>
  <div class="subtitle">Generated {_html_escape(self.metadata.execution_timestamp)} on
    {_html_escape(self.metadata.hostname)} ({_html_escape(self.metadata.operating_system)}
    {_html_escape(self.metadata.os_version)}, {_html_escape(self.metadata.architecture)})</div>

  <div class="panel grid">
    <div class="stat"><div class="value">{self.stats.profiles_scanned}</div><div class="label">Scanned</div></div>
    <div class="stat"><div class="value">{self.stats.credentials_recovered}</div><div class="label">Recovered</div></div>
    <div class="stat"><div class="value">{self.stats.credentials_failed}</div><div class="label">Failed</div></div>
    <div class="stat"><div class="value">{self.stats.duplicates_removed}</div><div class="label">Duplicates merged</div></div>
    <div class="stat"><div class="value">{self.stats.total_seconds:.2f}s</div><div class="label">Total runtime</div></div>
  </div>

  <div class="panel">
    <h2>Security Type Distribution</h2>
    {chart_svg}
  </div>

  <div class="panel">
    <h2>Recovered Credentials ({len(successful)})</h2>
    <table>
      <thead><tr><th>SSID</th><th>Security</th><th>Password</th><th>Sources</th><th>Hidden</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>

  {errors_block}

  <footer>Generated by {SCRIPT_NAME} v{self.metadata.script_version} — Python {self.metadata.python_version}</footer>
</body>
</html>"""

    @staticmethod
    def _render_svg_bar_chart(counts: dict[str, int]) -> str:
        """Simple, dependency-free SVG bar chart — no JavaScript required."""
        if not counts:
            return "<p style='color:#94a3b8'>No data to chart.</p>"

        max_count = max(counts.values())
        bar_height = 28
        gap = 10
        chart_width = 480
        label_width = 160
        svg_height = len(counts) * (bar_height + gap) + gap

        bars = []
        for i, (label, count) in enumerate(sorted(counts.items(), key=lambda kv: -kv[1])):
            y = gap + i * (bar_height + gap)
            bar_w = int((chart_width - label_width) * (count / max_count)) if max_count else 0
            bars.append(
                f'<text x="0" y="{y + bar_height / 2 + 4}" fill="#e2e8f0" font-size="12">{_html_escape(label)}</text>'
                f'<rect x="{label_width}" y="{y}" width="{bar_w}" height="{bar_height}" rx="4" fill="#38bdf8"/>'
                f'<text x="{label_width + bar_w + 6}" y="{y + bar_height / 2 + 4}" fill="#94a3b8" font-size="12">{count}</text>'
            )

        return (
            f'<svg viewBox="0 0 {chart_width + 40} {svg_height}" xmlns="http://www.w3.org/2000/svg">'
            + "".join(bars) + "</svg>"
        )

    def write_sqlite(self, path: Path) -> None:
        conn = sqlite3.connect(str(path))
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    ssid TEXT, security_type TEXT, password TEXT,
                    sources TEXT, hidden INTEGER, success INTEGER, error_message TEXT
                )
            """)
            conn.executemany(
                "INSERT INTO credentials VALUES (?,?,?,?,?,?,?)",
                [
                    (r["ssid"], r["security_type"],
                     r["password"] if self.show_passwords else mask_password(r["password"]),
                     ",".join(r["sources"]), int(r["hidden"]), int(r["success"]), r["error_message"])
                    for r in self._rows()
                ],
            )
            conn.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT, value TEXT)")
            conn.executemany(
                "INSERT INTO metadata VALUES (?,?)",
                [(k, str(v)) for k, v in asdict(self.metadata).items()],
            )
            conn.commit()
        finally:
            conn.close()


ReportGenerator.RENDERERS = {
    "txt": ReportGenerator.render_txt,
    "csv": ReportGenerator.render_csv,
    "json": ReportGenerator.render_json,
    "yaml": ReportGenerator.render_yaml,
    "md": ReportGenerator.render_markdown,
    "html": ReportGenerator.render_html,
}


# =============================================================================
# SECTION: Output Writers
# =============================================================================

def write_reports(
    generator: ReportGenerator,
    formats: list[str],
    output_dir: Path,
    base_filename: str,
    timestamp: str,
    stats: ExecutionStats,
) -> list[Path]:
    """
    Write every requested format from ONE shared ReportGenerator instance,
    using ONE shared timestamp, to avoid the duplicated-logic and
    filename-drift problems of earlier per-format functions.
    """
    log = logging.getLogger(SCRIPT_NAME)
    written: list[Path] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    for fmt in formats:
        target = output_dir / f"{base_filename}_{timestamp}.{fmt}"

        if target.exists():
            backup = target.with_suffix(target.suffix + ".bak")
            try:
                shutil.copy2(target, backup)
                log.debug(f"Backed up existing report to {backup}")
            except OSError as exc:
                log.warning(f"Could not create backup for {target}: {exc}")

        try:
            if fmt == "sqlite":
                generator.write_sqlite(target)
            else:
                renderer = ReportGenerator.RENDERERS.get(fmt)
                if renderer is None:
                    raise ReportGenerationError(f"Unsupported format: {fmt}")
                target.write_text(renderer(generator), encoding="utf-8")
        except ReportGenerationError as exc:
            log.error(f"Skipping '{fmt}' report: {exc}")
            continue
        except OSError as exc:
            raise OutputWriteError(f"Failed writing {target}: {exc}") from exc

        set_restrictive_permissions(target)
        written.append(target)
        stats.files_written += 1

    return written


def write_manifest(written_files: list[Path], output_dir: Path, timestamp: str) -> Path:
    """Write a manifest summarizing all generated report files with SHA-256 hashes."""
    manifest_path = output_dir / f"manifest_{timestamp}.json"
    entries = [
        {"file": f.name, "sha256": compute_sha256(f), "size_bytes": f.stat().st_size}
        for f in written_files
    ]
    manifest_path.write_text(json.dumps({"generated": timestamp, "files": entries}, indent=2), encoding="utf-8")
    return manifest_path


def bundle_as_zip(files: list[Path], output_dir: Path, timestamp: str) -> Path:
    """Optionally compress all generated reports into a single ZIP archive."""
    zip_path = output_dir / f"wifi_audit_bundle_{timestamp}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            zf.write(f, arcname=f.name)
    set_restrictive_permissions(zip_path)
    return zip_path


# =============================================================================
# SECTION: Diagnostics / Benchmark / Self-test
# =============================================================================

def run_diagnostics() -> int:
    """Print an environment/capability report and return a process exit code."""
    print("=" * 60)
    print(" DIAGNOSTICS")
    print("=" * 60)

    checks: list[tuple[str, bool, str]] = [
        ("Elevated privileges", is_privileged(), "root/Administrator required for full extraction"),
        ("Python >= 3.10", sys.version_info >= (3, 10), sys.version.split()[0]),
        ("Output directory writable", os.access(Path.cwd(), os.W_OK), str(Path.cwd())),
        ("Registered extractor for this platform", current_platform_key() in EXTRACTOR_REGISTRY, current_platform_key()),
        ("Rich available", HAVE_RICH, "optional — progress bars"),
        ("tqdm available", HAVE_TQDM, "optional — progress bar fallback"),
        ("PyYAML available", HAVE_YAML, "optional — YAML config/report"),
        ("Terminal is a TTY", sys.stdout.isatty(), "informational only"),
    ]

    for name, ok, detail in checks:
        status = "OK " if ok else "!! "
        print(f"  [{status}] {name:<45} {detail}")

    config_found = any(Path(f).exists() for f in DEFAULT_CONFIG_FILENAMES)
    label = "present" if config_found else "not found (optional)"
    print(f"  [{'OK ' if config_found else '-- '}] Configuration file {label}")

    print("=" * 60)
    return 0


def run_self_test() -> int:
    """Validate core parsing logic against known-good synthetic inputs."""
    print("Running self-test...")
    failures = 0

    sample_wpa = """
network={
    ssid="TestNet"
    psk="hunter22blah"
    key_mgmt=WPA-PSK
}
network={
    ssid="OpenNet"
    key_mgmt=NONE
}
"""
    parsed = parse_wpa_supplicant_text(sample_wpa, source="self-test")
    if len(parsed) != 2 or parsed[0].ssid != "TestNet" or parsed[0].password != "hunter22blah":
        print("  [FAIL] wpa_supplicant parser")
        failures += 1
    else:
        print("  [PASS] wpa_supplicant parser")

    if classify_security("WPA2-Personal") != "WPA2":
        print("  [FAIL] classify_security (WPA2)")
        failures += 1
    else:
        print("  [PASS] classify_security (WPA2)")

    if "Enterprise" not in classify_security("WPA2-Enterprise", "PEAP"):
        print("  [FAIL] classify_security (Enterprise/PEAP)")
        failures += 1
    else:
        print("  [PASS] classify_security (Enterprise/PEAP)")

    a = WifiCredential(ssid="Dup", security_type="Open", password="", source="NetworkManager")
    b = WifiCredential(ssid="Dup", security_type="WPA2", password="secret", source="iwd")
    deduped, removed = deduplicate_credentials([a, b])
    if (len(deduped) != 1 or removed != 1 or deduped[0].password != "secret"
            or deduped[0].sources != {"NetworkManager", "iwd"}):
        print("  [FAIL] deduplication merge")
        failures += 1
    else:
        print("  [PASS] deduplication merge")

    if "/" in sanitize_filename("bad/name:here") or ":" in sanitize_filename("bad/name:here"):
        print("  [FAIL] filename sanitization")
        failures += 1
    else:
        print("  [PASS] filename sanitization")

    print(f"\nSelf-test complete: {failures} failure(s)")
    return 1 if failures else 0


def run_benchmark(extractor: WifiExtractor, stats: ExecutionStats) -> None:
    """Print per-parser timing collected during extraction."""
    print("=" * 60)
    print(" BENCHMARK")
    print("=" * 60)
    print(f"  Profiles scanned      : {stats.profiles_scanned}")
    print(f"  Profiles / second     : {stats.profiles_per_second()}")
    print(f"  Extraction time       : {stats.extraction_seconds:.4f}s")
    print(f"  Report generation time: {stats.report_seconds:.4f}s")
    print(f"  Total runtime         : {stats.total_seconds:.4f}s")
    if stats.peak_memory_kb:
        print(f"  Peak memory           : {stats.peak_memory_kb} KB")

    if extractor.parser_timings:
        print("\n  Per-parser timings:")
        timed = sorted(extractor.parser_timings.items(), key=lambda kv: kv[1])
        for name, secs in timed:
            print(f"    {name:<30} {secs:.4f}s")
        print(f"\n  Fastest parser: {timed[0][0]} ({timed[0][1]:.4f}s)")
        print(f"  Slowest parser: {timed[-1][0]} ({timed[-1][1]:.4f}s)")
    print("=" * 60)


def get_peak_memory_kb() -> Optional[int]:
    """Best-effort peak memory usage using only the standard library (POSIX)."""
    if not HAVE_RESOURCE:
        return None
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return usage if platform.system() == "Linux" else usage // 1024
    except Exception:
        return None


# =============================================================================
# SECTION: CLI
# =============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=SCRIPT_NAME,
        description=(
            "Wi-Fi Credential Audit Tool — extracts and reports saved Wi-Fi "
            "credentials on the local host. For authorized security "
            "assessments and system administration only."
        ),
        epilog="""Examples:
  sudo %(prog)s
  sudo %(prog)s --format txt csv json
  sudo %(prog)s --format html md --output /tmp/audit
  sudo %(prog)s --show-passwords --verbose
  sudo %(prog)s --diagnostics
  sudo %(prog)s --benchmark
  sudo %(prog)s --self-test
  sudo %(prog)s --ssid-filter "Corp-*"
  sudo %(prog)s --no-dedup --format json
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--format", nargs="+", choices=SUPPORTED_FORMATS, default=None,
                         help="One or more output formats (default: txt, or config file value)")
    parser.add_argument("--output", type=Path, default=None, help="Output directory")
    parser.add_argument("--config", type=Path, default=None, help="Explicit path to a config file")

    parser.add_argument("--show-passwords", action="store_true",
                         help="Show plaintext passwords in console output (written reports always contain them)")
    parser.add_argument("--no-dedup", action="store_true", help="Disable cross-source deduplication")
    parser.add_argument("--no-progress", action="store_true", help="Disable progress bars")
    parser.add_argument("--quiet", action="store_true", help="Suppress informational console output")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    parser.add_argument("--log-file", type=Path, default=None,
                         help=f"Write logs to a file (default: {DEFAULT_LOG_FILE} when --verbose, else none)")

    parser.add_argument("--zip", action="store_true", help="Bundle all generated reports into a ZIP archive")
    parser.add_argument("--manifest", action="store_true", help="Write a manifest with SHA-256 hashes of generated reports")

    parser.add_argument("--ssid-filter", type=str, default=None, help="Glob pattern to filter SSIDs, e.g. 'Corp-*'")
    parser.add_argument("--ssid-regex", type=str, default=None, help="Regex pattern to filter SSIDs")
    parser.add_argument("--security-filter", type=str, default=None, help="Substring filter on security type, e.g. 'WPA2'")

    parser.add_argument("--diagnostics", action="store_true", help="Run environment diagnostics and exit")
    parser.add_argument("--benchmark", action="store_true", help="Print per-parser timing after extraction")
    parser.add_argument("--self-test", action="store_true", help="Run internal parser self-tests and exit")
    parser.add_argument("--version", action="store_true", help="Show version information and exit")

    return parser


def print_version() -> None:
    print(f"{SCRIPT_NAME} version {SCRIPT_VERSION}")
    print(f"Python: {platform.python_version()}")
    print(f"OS: {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Registered extractors: {', '.join(EXTRACTOR_REGISTRY)}")


# =============================================================================
# SECTION: Main Entry Point
# =============================================================================

def main() -> None:
    args = build_arg_parser().parse_args()

    if args.version:
        print_version()
        sys.exit(0)

    log_file = args.log_file or (Path(DEFAULT_LOG_FILE) if args.verbose else None)
    log = configure_logging(verbose=args.verbose, quiet=args.quiet, log_file=log_file)

    if args.self_test:
        sys.exit(run_self_test())

    if args.diagnostics:
        sys.exit(run_diagnostics())

    try:
        config = load_config(args.config)
    except ConfigParseError as exc:
        log.error(f"Configuration error: {exc}")
        sys.exit(1)

    formats = args.format or config.get("formats", ["txt"])
    output_dir = args.output or Path(config.get("output_dir", "."))
    timeout = int(config.get("timeout", 30))
    show_progress = (not args.no_progress) and (not args.quiet) and config.get("show_progress", True)

    if not is_privileged():
        print("[ERROR] This tool requires elevated privileges.")
        print("        Windows: run as Administrator")
        print("        Linux/macOS: use sudo")
        print("        Android: requires root")
        sys.exit(1)

    total_start = time.perf_counter()
    stats = ExecutionStats()
    progress = ProgressReporter(enabled=show_progress)

    try:
        extractor = get_extractor(timeout=timeout, progress=progress)
    except UnsupportedPlatformError as exc:
        log.error(str(exc))
        sys.exit(1)

    log.info(f"Starting extraction on {current_platform_key()} using {extractor.display_name}")

    extraction_start = time.perf_counter()
    try:
        credentials = extractor.extract()
    except ExtractionError as exc:
        log.error(f"Extraction failed: {exc}")
        sys.exit(1)
    stats.extraction_seconds = time.perf_counter() - extraction_start
    stats.parser_timings = extractor.parser_timings

    stats.profiles_scanned = len(credentials)
    stats.credentials_failed = sum(1 for c in credentials if not c.success)

    if not args.no_dedup:
        credentials, duplicates = deduplicate_credentials(credentials)
        stats.duplicates_removed = duplicates
    stats.sources_parsed = len({s for c in credentials for s in c.sources})

    credentials = apply_filters(
        credentials,
        ssid_glob=args.ssid_filter,
        ssid_regex=args.ssid_regex,
        security_type=args.security_filter,
    )
    stats.credentials_recovered = sum(1 for c in credentials if c.success)

    if not credentials:
        log.warning("No credentials found")
        sys.exit(0)

    metadata = RunMetadata()
    generator = ReportGenerator(credentials, metadata, stats, show_passwords=True)  # written reports keep real passwords

    hostname = sanitize_filename(metadata.hostname) or "unknown"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_start = time.perf_counter()
    try:
        written = write_reports(
            generator, formats, output_dir,
            base_filename=f"{hostname}_wifi_creds", timestamp=timestamp, stats=stats,
        )
    except OutputWriteError as exc:
        log.error(str(exc))
        sys.exit(1)
    stats.report_seconds = time.perf_counter() - report_start

    manifest_path = None
    if args.manifest and written:
        manifest_path = write_manifest(written, output_dir, timestamp)

    zip_path = None
    if args.zip and written:
        bundle_inputs = written + ([manifest_path] if manifest_path else [])
        zip_path = bundle_as_zip(bundle_inputs, output_dir, timestamp)

    stats.peak_memory_kb = get_peak_memory_kb()
    stats.total_seconds = time.perf_counter() - total_start

    # Console summary — passwords masked here unless --show-passwords was given.
    console_report = ReportGenerator(credentials, metadata, stats, show_passwords=args.show_passwords)
    if not args.quiet:
        print("\n" + console_report.render_txt())

        print("\nFiles written:")
        for f in written:
            print(f"  - {f}")
        if manifest_path:
            print(f"  - {manifest_path}  (manifest)")
        if zip_path:
            print(f"  - {zip_path}  (bundle)")

    if args.benchmark:
        run_benchmark(extractor, stats)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except WifiExtractorError as exc:
        logging.getLogger(SCRIPT_NAME).error(str(exc))
        sys.exit(1)
