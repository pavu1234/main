import asyncio, time
from urllib.parse import urljoin
import httpx
from .scope import validate_public_target, same_host, ScopeError
from ..config import settings

class SafeHttpClient:
    def __init__(self, root_url: str, concurrency: int = 5, follow_redirects: bool = True, allow_demo_private: bool = False):
        self.root_url = root_url
        self.follow_redirects = follow_redirects
        self.allow_demo_private = allow_demo_private
        self.sem = asyncio.Semaphore(min(concurrency, settings.max_concurrent_requests))
        self.client = httpx.AsyncClient(timeout=settings.request_timeout, follow_redirects=False, headers={"User-Agent":"WebGuardPro/1.0 Authorized-Security-Scanner"})
        self.requests_sent = 0

    async def close(self): await self.client.aclose()

    async def get(self, url: str, method: str = "GET"):
        current = await validate_public_target(url, self.allow_demo_private)
        if not same_host(self.root_url, current): raise ScopeError("Target left authorized host scope")
        for _ in range(settings.max_redirects + 1):
            async with self.sem:
                await asyncio.sleep(settings.request_delay_ms / 1000)
                started = time.perf_counter(); self.requests_sent += 1
                resp = await self.client.request(method, current)
                elapsed = time.perf_counter() - started
            body = resp.content[: settings.max_response_bytes]
            if resp.is_redirect and self.follow_redirects and resp.headers.get("location"):
                nxt = urljoin(current, resp.headers["location"])
                await validate_public_target(nxt, self.allow_demo_private)
                if not same_host(self.root_url, nxt): raise ScopeError("Redirect left authorized host scope")
                current = nxt; continue
            return resp, body, elapsed, current
        raise ScopeError("Maximum redirect limit exceeded")
