"""Smart Stealth Layer — rotating headers, randomized delays, session management."""

import random
import time
from dataclasses import dataclass, field

import requests
from rich.console import Console

console = Console()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Vivaldi/7.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Brave/131",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
    "en,*;q=0.5",
    "en-US,en;q=0.9,ja;q=0.8",
    "en-US,en;q=0.8",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
]

SEC_CH_UA = [
    '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
    '"Firefox";v="133", "Not A;Brand";v="99"',
    '"Microsoft Edge";v="131", "Not_A Brand";v="24", "Chromium";v="131"',
    '"Brave";v="131", "Not_A Brand";v="24", "Chromium";v="131"',
]


@dataclass
class StealthConfig:
    """Configuration for stealth behavior."""
    min_delay: float = 0.5
    max_delay: float = 3.0
    timeout: int = 15
    max_retries: int = 3
    retry_backoff: float = 2.0
    proxies: list[str] = field(default_factory=list)
    respect_robots: bool = False
    verbose: bool = False


class StealthSession:
    """HTTP session with stealth capabilities — rotating fingerprints and delays."""

    def __init__(self, config: StealthConfig | None = None):
        self.config = config or StealthConfig()
        self.session = requests.Session()
        self._request_count = 0
        self._proxy_index = 0
        self._last_request_time = 0.0

    @property
    def request_count(self) -> int:
        return self._request_count

    def _random_headers(self) -> dict:
        """Generate a randomized browser fingerprint."""
        ua = random.choice(USER_AGENTS)
        is_chrome = "Chrome" in ua and "Firefox" not in ua

        headers = {
            "User-Agent": ua,
            "Accept": random.choice(ACCEPT_HEADERS),
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

        if is_chrome:
            headers["Sec-CH-UA"] = random.choice(SEC_CH_UA)
            headers["Sec-CH-UA-Mobile"] = "?0"
            headers["Sec-CH-UA-Platform"] = random.choice(['"Windows"', '"macOS"', '"Linux"'])
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-User"] = "?1"

        # Randomize header order by rebuilding dict
        items = list(headers.items())
        random.shuffle(items)
        return dict(items)

    def _get_proxy(self) -> dict | None:
        """Get next proxy from rotation pool."""
        if not self.config.proxies:
            return None
        proxy = self.config.proxies[self._proxy_index % len(self.config.proxies)]
        self._proxy_index += 1
        return {"http": proxy, "https": proxy}

    def _stealth_delay(self):
        """Apply randomized delay between requests."""
        elapsed = time.time() - self._last_request_time
        min_wait = self.config.min_delay
        if elapsed < min_wait:
            jitter = random.uniform(min_wait - elapsed, self.config.max_delay)
            time.sleep(jitter)
        else:
            # Small random jitter even if enough time passed
            time.sleep(random.uniform(0.1, 0.5))

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        skip_delay: bool = False,
        **kwargs,
    ) -> requests.Response | None:
        """Make a stealthy HTTP request with retry logic."""
        if not skip_delay and self._request_count > 0:
            self._stealth_delay()

        merged_headers = self._random_headers()
        if headers:
            merged_headers.update(headers)

        proxies = self._get_proxy()
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("allow_redirects", True)

        last_error = None
        for attempt in range(self.config.max_retries):
            try:
                resp = self.session.request(
                    method,
                    url,
                    headers=merged_headers,
                    proxies=proxies,
                    **kwargs,
                )
                self._request_count += 1
                self._last_request_time = time.time()

                # Handle rate limiting
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 5))
                    wait = min(retry_after, 30)
                    if self.config.verbose:
                        console.print(f"  [yellow]Rate limited, waiting {wait}s...[/yellow]")
                    time.sleep(wait)
                    # Rotate fingerprint on rate limit
                    merged_headers = self._random_headers()
                    if headers:
                        merged_headers.update(headers)
                    continue

                # Handle captcha / block pages
                if resp.status_code == 403:
                    if any(kw in resp.text.lower() for kw in ("captcha", "challenge", "blocked", "access denied")):
                        if self.config.verbose:
                            console.print(f"  [yellow]Bot detection triggered, rotating...[/yellow]")
                        merged_headers = self._random_headers()
                        if headers:
                            merged_headers.update(headers)
                        time.sleep(random.uniform(2, 5))
                        continue

                return resp

            except requests.exceptions.Timeout:
                last_error = "timeout"
            except requests.exceptions.ConnectionError:
                last_error = "connection_error"
            except requests.exceptions.RequestException as e:
                last_error = str(e)

            # Exponential backoff
            if attempt < self.config.max_retries - 1:
                wait = self.config.retry_backoff ** (attempt + 1) + random.uniform(0, 1)
                time.sleep(wait)

        if self.config.verbose and last_error:
            console.print(f"  [red]Request failed after {self.config.max_retries} attempts: {last_error}[/red]")
        return None

    def get(self, url: str, **kwargs) -> requests.Response | None:
        return self.request(url, method="GET", **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response | None:
        return self.request(url, method="HEAD", **kwargs)

    def reset(self):
        """Reset session — new cookies, new identity."""
        self.session.close()
        self.session = requests.Session()
        self._request_count = 0
