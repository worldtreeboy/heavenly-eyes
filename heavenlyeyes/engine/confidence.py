"""Confidence scoring system for OSINT findings."""

from dataclasses import dataclass, field
from enum import Enum


class ConfidenceLevel(Enum):
    CONFIRMED = 95
    HIGH = 80
    MEDIUM = 60
    LOW = 40
    SPECULATIVE = 20


@dataclass
class Finding:
    """A single OSINT finding with confidence metadata."""
    category: str           # e.g., "social_profile", "email", "domain", "breach"
    source: str             # e.g., "GitHub API", "DNS MX", "Shodan SSL"
    label: str              # e.g., "GitHub Profile"
    value: str              # e.g., "https://github.com/johndoe"
    confidence: int         # 0-100
    pivot_type: str = ""    # What new input type this finding can pivot to
    pivot_value: str = ""   # The value to pivot on
    raw_data: dict = field(default_factory=dict)
    verified: bool = False

    @property
    def confidence_label(self) -> str:
        if self.confidence >= 90:
            return "CONFIRMED"
        elif self.confidence >= 75:
            return "HIGH"
        elif self.confidence >= 55:
            return "MEDIUM"
        elif self.confidence >= 35:
            return "LOW"
        return "SPECULATIVE"

    @property
    def confidence_color(self) -> str:
        if self.confidence >= 90:
            return "bold green"
        elif self.confidence >= 75:
            return "green"
        elif self.confidence >= 55:
            return "yellow"
        elif self.confidence >= 35:
            return "red"
        return "dim red"


class ConfidenceScorer:
    """Calculates confidence scores based on multiple signals."""

    # Base scores by source reliability
    SOURCE_WEIGHTS = {
        "api_verified": 95,      # Direct API confirmation
        "dns_record": 90,        # DNS records are authoritative
        "ssl_certificate": 85,   # SSL certs are registered data
        "whois_record": 85,      # WHOIS is authoritative
        "shodan_verified": 85,   # Shodan indexed data
        "http_status_200": 70,   # Page exists (could be false positive)
        "html_scrape": 60,       # Scraped from page content
        "pattern_match": 50,     # Regex or pattern-based
        "google_dork": 55,       # Found via dorking
        "historical_data": 45,   # Old data, may be outdated
        "breach_data": 75,       # From breach databases
        "ct_log": 65,            # Certificate transparency
        "inference": 30,         # Inferred / guessed
    }

    @classmethod
    def score(
        cls,
        source_type: str,
        modifiers: dict | None = None,
    ) -> int:
        """Calculate confidence score with optional modifiers.

        Modifiers can include:
            cross_validated: bool  — found by multiple sources (+15)
            recent: bool           — data is fresh / recent (+10)
            exact_match: bool      — exact string match vs fuzzy (+10)
            authenticated: bool    — from authenticated API (+10)
            stale: bool            — data may be outdated (-15)
            fuzzy_match: bool      — not exact match (-10)
            rate_limited: bool     — partial data due to limits (-5)
        """
        base = cls.SOURCE_WEIGHTS.get(source_type, 50)
        mods = modifiers or {}

        if mods.get("cross_validated"):
            base += 15
        if mods.get("recent"):
            base += 10
        if mods.get("exact_match"):
            base += 10
        if mods.get("authenticated"):
            base += 10
        if mods.get("stale"):
            base -= 15
        if mods.get("fuzzy_match"):
            base -= 10
        if mods.get("rate_limited"):
            base -= 5

        return max(5, min(100, base))


def make_finding(
    category: str,
    source: str,
    label: str,
    value: str,
    source_type: str,
    pivot_type: str = "",
    pivot_value: str = "",
    modifiers: dict | None = None,
    raw_data: dict | None = None,
) -> Finding:
    """Helper to create a Finding with auto-calculated confidence."""
    score = ConfidenceScorer.score(source_type, modifiers)
    return Finding(
        category=category,
        source=source,
        label=label,
        value=value,
        confidence=score,
        pivot_type=pivot_type,
        pivot_value=pivot_value,
        raw_data=raw_data or {},
    )
