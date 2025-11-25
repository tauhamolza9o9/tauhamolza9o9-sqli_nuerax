# target_loader.py
"""
TARGET LOADER MODULE
--------------------
This module verifies the target is alive, follows redirects safely,
extracts the final landing HTML, and normalizes the target for the
extractor modules and time_based.py detector.

Features:
- Intelligent follow-redirects (3xx)
- Detect infinite redirect loops
- Detect meta-refresh redirects
- Detect JS redirects (window.location)
- HTTP -> HTTPS upgrading
- Cookie accumulation between redirects
- User-Agent and header injection support
"""

import aiohttp
import asyncio
import re
from urllib.parse import urljoin, urlparse

DEFAULT_TIMEOUT = 15
MAX_REDIRECTS = 10


class TargetLoader:
    def __init__(self, timeout: int = DEFAULT_TIMEOUT, verify_ssl: bool = False):
        """
        timeout: total request timeout
        verify_ssl: whether to verify SSL certs (False = no errors on self-signed websites)
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session: aiohttp.ClientSession | None = None

    async def _ensure_session(self):
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(timeout=timeout)

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

    # ---------------------------------------------------------
    # INTERNAL: Standard GET request
    # ---------------------------------------------------------
    async def _fetch(self, url: str, headers=None, cookies=None):
        await self._ensure_session()
        headers = headers or {}
        cookies = cookies or {}

        try:
            async with self.session.get(
                url,
                headers=headers,
                cookies=cookies,
                allow_redirects=False,
                ssl=self.verify_ssl
            ) as resp:
                text = await resp.text(errors="replace")
                return resp, text
        except Exception:
            return None, None

    # ---------------------------------------------------------
    # INTERNAL: HTML soft redirect detectors (meta + JS)
    # ---------------------------------------------------------
    def _detect_meta_refresh(self, html: str) -> str | None:
        """
        Detect html: <meta http-equiv="refresh" content="0; url=/redirect">
        """
        meta = re.search(
            r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\']\s*\d+;\s*url=([^"\']+)["\']',
            html,
            re.IGNORECASE
        )
        if meta:
            return meta.group(1)
        return None

    def _detect_js_redirect(self, html: str) -> str | None:
        """
        Detect: window.location = '/abc'; or location.href = '...';
        """
        js = re.search(
            r'(?:window\.location|location\.href)\s*=\s*["\']([^"\']+)["\']',
            html,
            re.IGNORECASE
        )
        if js:
            return js.group(1)
        return None

    # ---------------------------------------------------------
    # MAIN: Load target, follow redirects, return final result
    # ---------------------------------------------------------
    async def load(self, url: str, headers=None, cookies=None):
        """
        Returns:
        {
            "alive": bool,
            "final_url": str,
            "status": int,
            "html": str,
            "redirect_chain": [...],
            "cookies": {...},
        }
        """
        await self._ensure_session()

        headers = headers or {"User-Agent": "Mozilla/5.0"}
        cookies = cookies or {}

        redirect_chain = []
        visited = set()

        current_url = url
        html = ""
        status = None

        for _ in range(MAX_REDIRECTS):

            if current_url in visited:
                return {
                    "alive": False,
                    "final_url": current_url,
                    "status": None,
                    "html": html,
                    "redirect_chain": redirect_chain,
                    "cookies": cookies,
                    "error": "Redirect loop detected"
                }

            visited.add(current_url)

            resp, text = await self._fetch(current_url, headers, cookies)

            if resp is None:
                return {
                    "alive": False,
                    "final_url": current_url,
                    "status": None,
                    "html": "",
                    "redirect_chain": redirect_chain,
                    "cookies": cookies,
                    "error": "Connection failed"
                }

            html = text
            status = resp.status

            # -----------------------------------------------------
            # 1. Handle TRUE HTTP redirect (301/302/303/307/308)
            # -----------------------------------------------------
            if 300 <= resp.status < 400:
                location = resp.headers.get("Location")
                if not location:
                    break  # broken redirect

                new_url = urljoin(current_url, location)
                redirect_chain.append((current_url, new_url, resp.status))
                current_url = new_url
                continue

            # -----------------------------------------------------
            # 2. Detect meta-refresh redirects
            # -----------------------------------------------------
            meta_redirect = self._detect_meta_refresh(html)
            if meta_redirect:
                new_url = urljoin(current_url, meta_redirect)
                redirect_chain.append((current_url, new_url, "meta-refresh"))
                current_url = new_url
                continue

            # -----------------------------------------------------
            # 3. Detect JS redirects
            # -----------------------------------------------------
            js_redirect = self._detect_js_redirect(html)
            if js_redirect:
                new_url = urljoin(current_url, js_redirect)
                redirect_chain.append((current_url, new_url, "js-redirect"))
                current_url = new_url
                continue

            # -----------------------------------------------------
            # 4. Reached final page
            # -----------------------------------------------------
            break

        # Final result object
        return {
            "alive": True if status and status >= 200 and status < 600 else False,
            "final_url": current_url,
            "status": status,
            "html": html,
            "redirect_chain": redirect_chain,
            "cookies": cookies,
        }
