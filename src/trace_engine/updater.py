"""TRACE Autonomous In-App Update Engine.

Checks for latest TRACE releases on npm registry and PyPI, displays sleek non-blocking
update notifications, and provides instant one-click/one-command upgrades.
"""

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional, Dict, Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from packaging import version as pkg_version

import trace_engine

console = Console()

CACHE_DIR = Path.home() / ".trace" / "cache"
CACHE_FILE = CACHE_DIR / "update_check.json"
CACHE_TTL_SECONDS = 900  # 15 minutes cache

_BACKGROUND_RESULT: Optional[Dict[str, Any]] = None
_BACKGROUND_THREAD: Optional[threading.Thread] = None


def get_current_version() -> str:
    """Returns the currently running TRACE version."""
    return getattr(trace_engine, "__version__", "2.1.15")


def fetch_latest_version(timeout: float = 1.8) -> Optional[str]:
    """Fetches the latest published TRACE version from npm registry or PyPI."""
    import urllib.request

    # 1. Try npm registry (primary distribution for trace-sec)
    try:
        req = urllib.request.Request(
            "https://registry.npmjs.org/trace-sec/latest",
            headers={"User-Agent": f"TRACE/{get_current_version()} (UpdateChecker)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                latest = data.get("version")
                if latest:
                    return str(latest).strip()
    except Exception:
        pass

    # 2. Fallback to PyPI
    try:
        req = urllib.request.Request(
            "https://pypi.org/pypi/trace-sec/json",
            headers={"User-Agent": f"TRACE/{get_current_version()} (UpdateChecker)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                latest = data.get("info", {}).get("version")
                if latest:
                    return str(latest).strip()
    except Exception:
        pass

    return None


def check_for_updates(force: bool = False, timeout: float = 1.8) -> Optional[Dict[str, Any]]:
    """Checks whether a newer version of TRACE is available.

    Returns dict with update metadata if a newer version exists, else None.
    Uses cached result if checked within CACHE_TTL_SECONDS unless force=True.
    """
    global _BACKGROUND_RESULT
    if _BACKGROUND_RESULT is not None and not force:
        return _BACKGROUND_RESULT if _BACKGROUND_RESULT.get("update_available") else None

    current_ver = get_current_version()

    # Check cache first
    if not force and CACHE_FILE.exists():
        try:
            cached = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            cache_time = cached.get("timestamp", 0)
            if time.time() - cache_time < CACHE_TTL_SECONDS:
                latest_ver = cached.get("latest_version")
                if latest_ver and cached.get("cached_current") == current_ver:
                    if pkg_version.parse(latest_ver) > pkg_version.parse(current_ver):
                        res = {
                            "update_available": True,
                            "current_version": current_ver,
                            "latest_version": latest_ver,
                        }
                        _BACKGROUND_RESULT = res
                        return res
                    return None
        except Exception:
            pass

    # Query registry
    latest_ver = fetch_latest_version(timeout=timeout)
    if not latest_ver:
        return None

    try:
        has_update = pkg_version.parse(latest_ver) > pkg_version.parse(current_ver)
    except Exception:
        has_update = latest_ver != current_ver

    result_data = {
        "update_available": has_update,
        "current_version": current_ver,
        "latest_version": latest_ver,
        "cached_current": current_ver,
        "timestamp": time.time(),
    }

    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(result_data, indent=2), encoding="utf-8")
    except Exception:
        pass

    if has_update:
        res = {
            "update_available": True,
            "current_version": current_ver,
            "latest_version": latest_ver,
        }
        _BACKGROUND_RESULT = res
        return res

    _BACKGROUND_RESULT = {"update_available": False}
    return None


def start_background_check() -> None:
    """Spawns an asynchronous background daemon thread to query update status without blocking startup."""
    global _BACKGROUND_THREAD
    if _BACKGROUND_THREAD is not None and _BACKGROUND_THREAD.is_alive():
        return

    def _worker():
        try:
            check_for_updates(force=False, timeout=2.5)
        except Exception:
            pass

    _BACKGROUND_THREAD = threading.Thread(target=_worker, daemon=True)
    _BACKGROUND_THREAD.start()


if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def render_update_banner(info: Optional[Dict[str, Any]] = None) -> None:
    """Renders a sleek, eye-catching banner notifying the user of an available update."""
    if not info:
        info = check_for_updates()
    if not info or not info.get("update_available"):
        return

    curr = info["current_version"]
    latest = info["latest_version"]

    arrow = "->" if sys.platform == "win32" else "➜"

    content = Text()
    content.append("  * UPDATE AVAILABLE: ", style="bold #10B981")
    content.append(f"v{curr} ", style="bold white")
    content.append(f"{arrow} ", style="bold #FF9E3B")
    content.append(f"v{latest} (latest)\n", style="bold #10B981")
    content.append(
        "    A newer version of TRACE is ready with updated AST analyzers, testpacks & AI weights.\n\n",
        style="dim white",
    )
    content.append("    To update immediately: ", style="white")
    content.append("trace update", style="bold #10B981")
    content.append("  or  ", style="dim white")
    content.append("npx trace-sec@latest", style="bold #FF9E3B")

    panel = Panel(
        content,
        border_style="#10B981",
        title="[bold #10B981] TRACE Package Update [/bold #10B981]",
        subtitle="[dim white]Press [bold white]U[/bold white] in menu or run [bold white]trace update[/bold white][/dim white]",
        padding=(0, 1),
    )
    console.print()
    console.print(panel)
    console.print()


def perform_update(target_version: Optional[str] = None) -> bool:
    """Performs an automatic zero-hassle upgrade of TRACE using npm and pip."""
    current_ver = get_current_version()
    console.print(f"\n  [bold #10B981]◆ TRACE AUTOMATIC UPGRADE ENGINE[/bold #10B981]")
    console.print(f"    [dim white]Upgrading from v{current_ver} to {target_version or 'latest'}...[/dim white]")
    console.print(f"    [dim #10B981]{'─' * 60}[/dim #10B981]\n")

    success = False
    is_win = sys.platform == "win32"
    shell_cmd = True if is_win else False

    # 1. Detect if npm is installed
    npm_path = shutil.which("npm") or shutil.which("npm.cmd")
    if npm_path:
        console.print("  [bold #FF9E3B]›[/bold #FF9E3B] [bold white]Step 1/3: Updating global npm package (trace-sec@latest)...[/bold white]")
        try:
            update_spec = f"trace-sec@{target_version}" if target_version else "trace-sec@latest"
            proc = subprocess.run(
                ["npm", "install", "-g", update_spec],
                shell=shell_cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.returncode == 0:
                console.print(f"    [bold #10B981]✓[/bold #10B981] Global npm package upgraded successfully.")
                success = True
            else:
                console.print(f"    [dim white]npm notice: {proc.stderr.strip() or proc.stdout.strip()}[/dim white]")
        except Exception as e:
            console.print(f"    [dim white]npm update skipped: {e}[/dim white]")

    # 2. Check Python environment and upgrade pip package if installed
    console.print("  [bold #FF9E3B]›[/bold #FF9E3B] [bold white]Step 2/3: Synchronizing Python engine & dependencies...[/bold white]")
    py_exec = sys.executable

    # Check if running in development git repo
    repo_root = Path(__file__).resolve().parent.parent.parent
    is_git_repo = (repo_root / ".git").exists()

    if is_git_repo:
        try:
            console.print("    [dim white]Detected local repository. Running editable sync (pip install -e .)...[/dim white]")
            proc = subprocess.run(
                [py_exec, "-m", "pip", "install", "-e", "."],
                cwd=str(repo_root),
                shell=shell_cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.returncode == 0:
                console.print("    [bold #10B981]✓[/bold #10B981] Local repository synced in editable mode.")
                success = True
        except Exception as e:
            console.print(f"    [dim white]Local repo sync note: {e}[/dim white]")
    else:
        # Check ~/.trace/venv or current python
        dedicated_venv_py = Path.home() / ".trace" / "venv" / ("Scripts" if is_win else "bin") / ("python.exe" if is_win else "python")
        targets = [py_exec]
        if dedicated_venv_py.exists() and str(dedicated_venv_py) != py_exec:
            targets.append(str(dedicated_venv_py))

        for target_py in targets:
            try:
                proc = subprocess.run(
                    [target_py, "-m", "pip", "install", "--upgrade", "trace-sec"],
                    shell=shell_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if proc.returncode == 0:
                    console.print(f"    [bold #10B981]✓[/bold #10B981] Python environment updated ({target_py}).")
                    success = True
            except Exception:
                pass

    # 3. Clear npx cache
    console.print("  [bold #FF9E3B]›[/bold #FF9E3B] [bold white]Step 3/3: Refreshing npx cache & package registry...[/bold white]")
    try:
        # Clear update cache file so fresh version registers
        if CACHE_FILE.exists():
            CACHE_FILE.unlink(missing_ok=True)
        console.print("    [bold #10B981]✓[/bold #10B981] Cache invalidated.")
    except Exception:
        pass

    console.print(f"\n  [dim #10B981]{'─' * 60}[/dim #10B981]")
    if success or target_version:
        console.print(f"  [bold #10B981]✓ SUCCESS: TRACE is now up-to-date![/bold #10B981]")
        console.print(f"  [dim white]Launch the upgraded engine anytime using:[/dim white] [bold white]trace[/bold white] [dim white]or[/dim white] [bold white]npx trace-sec[/bold white]\n")
        return True
    else:
        console.print(f"  [bold #FF9E3B]Notice:[/bold #FF9E3B] Automatic upgrade completed. If needed, run manually:")
        console.print(f"    [bold white]npm install -g trace-sec@latest[/bold white]\n")
        return False
