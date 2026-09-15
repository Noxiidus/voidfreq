"""Tests for wordlist generator."""

import os
import tempfile

import pytest

from voidfreq.modules.wordlist import WordlistGenerator, WordlistConfig


def test_basic_generation():
    config = WordlistConfig(essid="TestNetwork")
    gen = WordlistGenerator(config)
    words = gen.generate()

    assert len(words) > 50
    assert all(8 <= len(w) <= 63 for w in words)


def test_essid_in_wordlist():
    config = WordlistConfig(essid="CoffeeShop")
    gen = WordlistGenerator(config)
    words = gen.generate()

    lower_words = {w.lower() for w in words}
    assert any("coffeeshop" in w for w in lower_words)


def test_year_variants():
    config = WordlistConfig(essid="MyWifi", include_years=True)
    gen = WordlistGenerator(config)
    words = gen.generate()

    assert any("2024" in w for w in words)
    assert any("2025" in w for w in words)


def test_no_years():
    config = WordlistConfig(essid="MyWifi", include_years=False)
    gen = WordlistGenerator(config)
    words = gen.generate()

    year_words = {w for w in words if any(str(y) in w for y in range(2018, 2028))}
    assert len(year_words) == 0


def test_no_leet():
    config = WordlistConfig(
        essid="Test", include_leet=False, include_years=False,
        include_common=False, include_keyboard=False,
    )
    gen = WordlistGenerator(config)
    words_no_leet = gen.generate()

    config2 = WordlistConfig(
        essid="Test", include_leet=True, include_years=False,
        include_common=False, include_keyboard=False,
    )
    gen2 = WordlistGenerator(config2)
    words_with_leet = gen2.generate()

    assert len(words_with_leet) >= len(words_no_leet)


def test_min_length_filter():
    config = WordlistConfig(essid="AB", min_length=10)
    gen = WordlistGenerator(config)
    words = gen.generate()

    assert all(len(w) >= 10 for w in words)


def test_max_length_filter():
    config = WordlistConfig(essid="Test", max_length=12)
    gen = WordlistGenerator(config)
    words = gen.generate()

    assert all(len(w) <= 12 for w in words)


def test_custom_words():
    config = WordlistConfig(essid="Net", custom_words=["admin", "root"])
    gen = WordlistGenerator(config)
    words = gen.generate()

    lower_words = {w.lower() for w in words}
    assert any("admin" in w for w in lower_words)


def test_save_wordlist():
    config = WordlistConfig(essid="SaveTest")
    gen = WordlistGenerator(config)
    gen.generate()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        path = f.name

    try:
        saved = gen.save(path)
        assert os.path.exists(saved)

        with open(saved) as f:
            lines = f.readlines()
        assert len(lines) == len(gen.words)
    finally:
        os.unlink(path)


def test_save_auto_generates():
    config = WordlistConfig(essid="AutoGen")
    gen = WordlistGenerator(config)

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.txt")
        gen.save(path)
        assert os.path.exists(path)


def test_common_wifi_passwords_included():
    config = WordlistConfig(essid="Test", include_common=True)
    gen = WordlistGenerator(config)
    words = gen.generate()

    assert "password123" in words
    assert "12345678" in words


def test_keyboard_walks_included():
    config = WordlistConfig(essid="Test", include_keyboard=True)
    gen = WordlistGenerator(config)
    words = gen.generate()

    assert "qwerty123" in words


def test_essid_split():
    config = WordlistConfig(essid="MyHome_WiFi-5GHz")
    gen = WordlistGenerator(config)
    parts = gen._split_essid("MyHome_WiFi-5GHz")

    assert "MyHome" in parts or "My" in parts
    assert "WiFi" in parts or "Wi" in parts
