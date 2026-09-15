"""Wordlist generator — ESSID-based custom wordlists for targeted cracking."""

from __future__ import annotations

import itertools
import os
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress

from ..core.logger import get_logger

console = Console()
log = get_logger("wordlist")

COMMON_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345", "123456",
    "01", "00", "99", "69", "007",
    "!", "!!", "!!!", "@", "#", "$",
    "wifi", "WiFi", "WIFI",
    "pass", "Pass", "PASS",
    "net", "Net", "NET",
]

YEAR_RANGE = range(2018, 2028)

LEET_MAP = {
    "a": ["a", "A", "@", "4"],
    "e": ["e", "E", "3"],
    "i": ["i", "I", "1", "!"],
    "o": ["o", "O", "0"],
    "s": ["s", "S", "$", "5"],
    "t": ["t", "T", "7"],
    "l": ["l", "L", "1"],
}

COMMON_PATTERNS = [
    "{name}",
    "{name}{year}",
    "{name}{suffix}",
    "{name}_{suffix}",
    "{name}{year}{suffix}",
    "{NAME}",
    "{NAME}{year}",
    "{NAME}{suffix}",
    "{Name}",
    "{Name}{year}",
    "{Name}{suffix}",
    "{name}{name}",
    "wifi{name}",
    "WiFi{name}",
    "{name}wifi",
    "{name}WiFi",
    "{name}_wifi",
    "password{name}",
    "{name}password",
    "{name}pass",
    "pass{name}",
]

KEYBOARD_WALKS = [
    "qwerty", "qwerty123", "qwertyuiop",
    "asdfgh", "asdfghjkl",
    "zxcvbn", "zxcvbnm",
    "1q2w3e", "1q2w3e4r",
    "1qaz2wsx", "qazwsx",
]

COMMON_WIFI_PASSWORDS = [
    "password", "password1", "password123",
    "12345678", "123456789", "1234567890",
    "admin123", "admin1234", "administrator",
    "letmein", "welcome", "welcome1",
    "internet", "wifi1234", "wifi12345",
    "changeme", "default", "guest",
    "master", "access", "connect",
    "wireless", "network", "security",
]


@dataclass
class WordlistConfig:
    essid: str
    include_leet: bool = True
    include_years: bool = True
    include_common: bool = True
    include_keyboard: bool = True
    min_length: int = 8
    max_length: int = 63
    custom_words: list[str] | None = None


class WordlistGenerator:
    def __init__(self, config: WordlistConfig) -> None:
        self.config = config
        self.words: set[str] = set()

    def generate(self) -> set[str]:
        console.print(f"[cyan]Generating wordlist for ESSID: \"{self.config.essid}\"[/cyan]")

        name = self.config.essid.strip()
        name_lower = name.lower()
        name_upper = name.upper()
        name_title = name.title()
        name_parts = self._split_essid(name)

        with Progress(console=console) as progress:
            task = progress.add_task("Building wordlist...", total=6)

            self._add_pattern_variants(name, name_lower, name_upper, name_title)
            progress.advance(task)

            if self.config.include_years:
                self._add_year_variants(name, name_lower, name_title)
            progress.advance(task)

            for part in name_parts:
                if len(part) >= 3:
                    self._add_pattern_variants(part, part.lower(), part.upper(), part.title())
            progress.advance(task)

            if self.config.include_leet:
                self._add_leet_variants(name_lower)
            progress.advance(task)

            if self.config.include_common:
                self.words.update(COMMON_WIFI_PASSWORDS)
            progress.advance(task)

            if self.config.include_keyboard:
                self.words.update(KEYBOARD_WALKS)
            progress.advance(task)

        if self.config.custom_words:
            for word in self.config.custom_words:
                self._add_pattern_variants(word, word.lower(), word.upper(), word.title())

        self.words = {
            w for w in self.words
            if self.config.min_length <= len(w) <= self.config.max_length
        }

        console.print(f"[green]{len(self.words)} candidates generated[/green]")
        return self.words

    def save(self, output_path: str | None = None) -> str:
        if not self.words:
            self.generate()

        if not output_path:
            safe_name = "".join(c if c.isalnum() else "_" for c in self.config.essid)
            output_path = f"wordlist_{safe_name}.txt"

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(output_path, "w") as f:
            for word in sorted(self.words):
                f.write(word + "\n")

        console.print(f"[green]Wordlist saved: {output_path} ({len(self.words)} words)[/green]")
        return output_path

    def _split_essid(self, essid: str) -> list[str]:
        import re
        parts = re.split(r"[-_\s.]+", essid)
        camel_parts = []
        for part in parts:
            camel_parts.extend(re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+", part))
        return [p for p in set(parts + camel_parts) if p]

    def _add_pattern_variants(
        self, name: str, name_lower: str, name_upper: str, name_title: str,
    ) -> None:
        for pattern in COMMON_PATTERNS:
            for suffix in COMMON_SUFFIXES:
                try:
                    word = pattern.format(
                        name=name_lower, NAME=name_upper, Name=name_title,
                        suffix=suffix, year="",
                    )
                    if word:
                        self.words.add(word)
                except (KeyError, IndexError):
                    pass

    def _add_year_variants(
        self, name: str, name_lower: str, name_title: str,
    ) -> None:
        for year in YEAR_RANGE:
            for suffix in ["", "!", "#", "@"]:
                self.words.add(f"{name_lower}{year}{suffix}")
                self.words.add(f"{name_title}{year}{suffix}")
                self.words.add(f"{name}{year}{suffix}")
                self.words.add(f"{name_lower}_{year}{suffix}")

    def _add_leet_variants(self, word: str) -> None:
        if len(word) > 10:
            return

        positions = []
        for i, char in enumerate(word):
            if char.lower() in LEET_MAP:
                positions.append((i, LEET_MAP[char.lower()]))

        if len(positions) > 4:
            positions = positions[:4]

        for combo in itertools.product(*[opts for _, opts in positions]):
            chars = list(word)
            for (pos, _), replacement in zip(positions, combo, strict=False):
                chars[pos] = replacement
            result = "".join(chars)
            self.words.add(result)
            for suffix in ["", "!", "123", "1"]:
                self.words.add(f"{result}{suffix}")
