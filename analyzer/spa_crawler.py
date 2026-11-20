import asyncio
from concurrent.futures import ThreadPoolExecutor
import re
import time
from urllib.parse import urljoin, urlsplit

from browser_tools.session import BrowserSession


def _normalize_cookies_for_playwright(cookies, default_host):
    pw_cookies = []
    for c in (cookies or []):
        if not isinstance(c, dict) or not c.get("name"):
            continue
        item = {
            "name": str(c["name"]),
            "value": str(c.get("value", "")),
            "path": str(c.get("path") or "/"),
        }
        domain = c.get("domain") or default_host
        if domain and ":" in str(domain):
            domain = str(domain).split(":", 1)[0]
        if domain:
            item["domain"] = str(domain)
        pw_cookies.append(item)
    return pw_cookies


async def _crawl_spa_async(start_url, cookies=None, run_id=None, timeout_ms=12000, max_items=15):
    parsed = urlsplit(start_url)
    host = parsed.hostname
    if not host:
        return {"dynamic_urls": [], "xhr_endpoints": [], "dom_routes": []}

    safe_run_id = run_id or ("spacrawl-" + re.sub(r"[^0-9]", "", f"{time.time():.3f}")[-14:])
    safe_run_id = re.sub(r"[^A-Za-z0-9_-]", "-", safe_run_id)[:100] or "spacrawl"

    xhr_endpoints = []
    seen_xhr = set()

    def _on_request(req):
        try:
            if req.resource_type in ("xhr", "fetch"):
                u = req.url
                if u and u not in seen_xhr and len(seen_xhr) < max_items:
                    seen_xhr.add(u)
                    xhr_endpoints.append(u)
        except Exception:
            pass

    async with BrowserSession(run_id=safe_run_id, allowed_hosts=[host], timeout_ms=timeout_ms) as session:
        pw_cookies = _normalize_cookies_for_playwright(cookies, host)
        if pw_cookies and session._context is not None:
            try:
                await session._context.add_cookies(pw_cookies)
            except Exception:
                pass

        session._page.on("request", _on_request)
        await session.navigate(start_url)

        try:
            await session._page.wait_for_load_state("networkidle", timeout=3500)
        except Exception:
            await session._page.wait_for_timeout(1200)

        raw_items = await session._page.evaluate(r"""() => {
            const out = new Set();
            for (const a of document.querySelectorAll('a[href]')) {
                const h = a.getAttribute('href');
                if (h && !h.startsWith('javascript:') && !h.startsWith('mailto:')) {
                    out.add(h);
                }
            }
            if (location.hash && location.hash.length > 1) {
                out.add(location.href);
            }
            for (const form of document.querySelectorAll('form')) {
                const method = (form.getAttribute('method') || 'GET').toUpperCase();
                if (method !== 'GET') continue;
                const act = form.getAttribute('action') || '';
                const pairs = [];
                for (const el of form.querySelectorAll('input[name], select[name], textarea[name]')) {
                    const name = el.getAttribute('name');
                    if (!name) continue;
                    const val = el.getAttribute('value') || '1';
                    pairs.push(`${encodeURIComponent(name)}=${encodeURIComponent(val)}`);
                }
                if (pairs.length) {
                    const sep = act.includes('?') ? '&' : '?';
                    out.add(`${act}${sep}${pairs.join('&')}`);
                }
            }
            return Array.from(out);
        }""")

    dom_routes = []
    combined = []
    seen = {start_url}

    for item in (raw_items or []):
        full = urljoin(start_url, item)
        if session.in_scope(full):
            if full not in dom_routes and len(dom_routes) < max_items:
                dom_routes.append(full)
            if full not in seen and len(combined) < max_items:
                seen.add(full)
                combined.append(full)

    for u in xhr_endpoints:
        if session.in_scope(u) and u not in seen and len(combined) < max_items:
            seen.add(u)
            combined.append(u)

    return {
        "dynamic_urls": combined,
        "xhr_endpoints": xhr_endpoints,
        "dom_routes": dom_routes,
    }


def crawl_spa_endpoints(start_url, cookies=None, run_id=None, timeout_ms=12000, max_items=15):
    try:
        asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(
                lambda: asyncio.run(_crawl_spa_async(start_url, cookies, run_id, timeout_ms, max_items))
            ).result(timeout=25)
    except RuntimeError:
        return asyncio.run(_crawl_spa_async(start_url, cookies, run_id, timeout_ms, max_items))
    except Exception:
        return {"dynamic_urls": [], "xhr_endpoints": [], "dom_routes": []}
