"""
Features:
- Reads API key from env var SECURITYTRAILS_APIKEY (or you can pass it explicitly)
- Rate-limit safe (simple sleep/backoff)
- Retries on transient errors
- Returns deduplicated subdomain list and raw JSON if needed
- Example usage at the bottom with CLI arguments

References:
- SecurityTrails docs: https://docs.securitytrails.com (list-subdomains and domains/list endpoints)
"""

from typing import List, Tuple, Dict, Any, Optional
import os
import time
import requests
import logging

# --------------------------------------------------------
# Setup logging for consistent info/error messages
# --------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("securitytrails")

DEFAULT_BASE = "https://api.securitytrails.com/v1"

# ========================================================
# SecurityTrails API Client
# ========================================================
class SecurityTrailsClient:
    def __init__(self, api_key: Optional[str] = None, base_url: str = DEFAULT_BASE, timeout: int = 15):
        """
        Initialize the SecurityTrails client.
        - api_key: your SecurityTrails API key
        - base_url: default API base
        - timeout: request timeout
        """
        self.api_key = api_key or os.getenv("SECURITYTRAILS_APIKEY")
        if not self.api_key:
            raise ValueError("SecurityTrails API key not provided. Set SECURITYTRAILS_APIKEY or pass api_key param.")
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "APIKEY": self.api_key,
            "User-Agent": "BlackByt3-Subenum/1.0 (by Jahangir)"  # Custom user-agent for your internship tool
        })
        self.timeout = timeout

    # ----------------------
    # Internal GET request
    # ----------------------
    def _get(self, path: str, params: dict = None, retries: int = 3, backoff: float = 1.0) -> Dict[str, Any]:
        url = f"{self.base}{path}"
        for attempt in range(1, retries + 1):
            try:
                r = self.session.get(url, params=params, timeout=self.timeout)
                if r.status_code == 200:
                    return r.json()
                elif r.status_code == 429:
                    # Too many requests – wait and retry
                    wait = backoff * attempt
                    logger.warning(f"Rate limited (429). Sleeping {wait}s and retrying...")
                    time.sleep(wait)
                else:
                    r.raise_for_status()
            except requests.RequestException as e:
                logger.warning(f"GET request error: {e} (attempt {attempt}/{retries})")
                time.sleep(backoff * attempt)
        raise RuntimeError(f"GET request to {url} failed after {retries} attempts")

    # ----------------------
    # Internal POST request
    # ----------------------
    def _post(self, path: str, json_body: dict, retries: int = 3, backoff: float = 1.0) -> Dict[str, Any]:
        url = f"{self.base}{path}"
        for attempt in range(1, retries + 1):
            try:
                r = self.session.post(url, json=json_body, timeout=self.timeout)
                if r.status_code == 200:
                    return r.json()
                elif r.status_code == 429:
                    wait = backoff * attempt
                    logger.warning(f"Rate limited (429). Sleeping {wait}s and retrying...")
                    time.sleep(wait)
                else:
                    r.raise_for_status()
            except requests.RequestException as e:
                logger.warning(f"POST request error: {e} (attempt {attempt}/{retries})")
                time.sleep(backoff * attempt)
        raise RuntimeError(f"POST request to {url} failed after {retries} attempts")

    # ----------------------
    # GET subdomains (simple list)
    # ----------------------
    def list_subdomains(self, domain: str) -> Tuple[List[str], Dict[str, Any]]:
        """
        Simple GET endpoint: /v1/domain/{domain}/subdomains
        Returns deduplicated list of subdomains and raw JSON.
        """
        path = f"/domain/{domain}/subdomains"
        logger.info(f"Requesting subdomains for {domain} (simple list)...")
        data = self._get(path)

        subdomains = []
        if isinstance(data, dict) and 'subdomains' in data:
            for s in data.get('subdomains', []):
                # SecurityTrails returns fragments like 'www', 'api'
                full = s if s.endswith(domain) else f"{s}.{domain}" if s else None
                if full:
                    subdomains.append(full)
        else:
            logger.debug("Unexpected response shape from list_subdomains; attempting fallback parsing")

        # Deduplicate and sort
        unique = sorted(set(subdomains))
        logger.info(f"Found {len(unique)} subdomains via list_subdomains")
        return unique, data

    # ----------------------
    # POST search subdomains (advanced, paginated)
    # ----------------------
    def search_subdomains(self, domain: str, page_size: int = 100, max_pages: int = 10) -> Tuple[List[str], Dict[str, Any]]:
        """
        POST /v1/domains/list - searches for domains by apex domain.
        Returns (subdomains_list, aggregated_raw_response)
        """
        path = "/domains/list"
        body = {
            "filter": {
                "apex_domain": domain
            },
            "limit": page_size,
            "page": 1
        }

        all_subdomains = set()
        raw_pages = []

        for page in range(1, max_pages + 1):
            body["page"] = page
            logger.info(f"Fetching page {page}...")
            resp = self._post(path, body)
            raw_pages.append(resp)

            records = resp.get("records", [])
            for r in records:
                hostname = r.get("hostname") or r.get("domain")
                if hostname and hostname.endswith(domain):
                    all_subdomains.add(hostname)

            # Stop if no more records
            if not records:
                logger.info("No more records; stopping search")
                break

            time.sleep(0.3)

        logger.info(f"search_subdomains aggregated {len(all_subdomains)} unique hostnames")
        return sorted(all_subdomains), {"pages": raw_pages}



# ========================================================
# Utility Functions
# ========================================================

def merge_sources(*lists: List[str]) -> List[str]:
    """Merge multiple lists of hostnames, deduplicate, and sort."""
    merged = set()
    for l in lists:
        merged.update(l or [])
    return sorted(merged)

def save_to_file(hosts: List[str], path: str):
    """Save discovered subdomains to a text file (one per line)."""
    with open(path, "w") as f:
        for h in hosts:
            f.write(h + "\n")

# ========================================================
# CLI Example Usage
# ========================================================
if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="SecurityTrails subdomain fetcher (module for internship tool)")
    p.add_argument("domain", help="Target domain, e.g. example.com")
    p.add_argument("--method", choices=["list","search"], default="list",
                   help="Which SecurityTrails endpoint to use")
    p.add_argument("--out", help="Output file to save hostnames (one per line)", default=None)
    p.add_argument("--api-key", help="SecurityTrails API key (optional, falls back to SECURITYTRAILS_APIKEY env var)")
    args = p.parse_args()

    # Initialize client
    client = SecurityTrailsClient(api_key=args.api_key)

    # Run selected method
    if args.method == "list":
        subs, raw = client.list_subdomains(args.domain)
    else:
        subs, raw = client.search_subdomains(args.domain)

    # Print results
    print(f"Found {len(subs)} subdomains for {args.domain} via SecurityTrails ({args.method})")
    for s in subs:
        print(s)

    # Save results if --out is given
    if args.out:
        save_to_file(subs, args.out)
        print(f"[INFO] Saved results to {args.out}")
