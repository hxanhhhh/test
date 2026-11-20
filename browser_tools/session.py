"""One persistent Chromium context per run; no user-supplied JS or selectors."""

import asyncio
from functools import wraps
import ipaddress
from pathlib import Path
import re
from urllib.parse import urlsplit
from urllib.parse import urljoin

from playwright.async_api import Error, TimeoutError as PlaywrightTimeout, async_playwright


ROOT = Path(__file__).resolve().parent.parent
SELECTOR = ('a[href], button, input, select, textarea, h1, h2, h3, h4, h5, h6, '
            '[role="link"], [role="button"], [role="textbox"], [role="checkbox"], '
            '[role="radio"], [role="combobox"], [role="heading"]')


class ToolError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message


def guarded(method):
    """Serialize calls and return the same JSON envelope for every tool."""
    @wraps(method)
    async def call(self, *args, **kwargs):
        async with self._lock:
            try:
                self._blocked = False
                self._route_error = None
                await self.open()
                data = await method(self, *args, **kwargs)
                if self._blocked:
                    raise ToolError("OUT_OF_SCOPE", "Navigation outside allowed_hosts was blocked.")
                if self._route_error:
                    raise ToolError(*self._route_error)
                return {"ok": True, "data": data, "error": None}
            except ToolError as exc:
                code, message = exc.code, exc.message
            except PlaywrightTimeout:
                code, message = "TIMEOUT", "Browser operation exceeded the configured timeout."
            except Error:
                if self._route_error:
                    code, message = self._route_error
                else:
                    code = "OUT_OF_SCOPE" if self._blocked else "BROWSER_ERROR"
                    message = "Navigation outside allowed_hosts was blocked." if self._blocked else "Browser operation failed."
            except OSError:
                code, message = "IO_ERROR", "Unable to write the screenshot."
            return {"ok": False, "data": None, "error": {"code": code, "message": message}}
    return call


class BrowserSession:
    def __init__(self, run_id: str, allowed_hosts: list[str], *, timeout_ms: int = 15000):
        if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", run_id):
            raise ValueError("run_id must contain only letters, digits, underscores or hyphens.")
        if isinstance(allowed_hosts, str) or not allowed_hosts:
            raise ValueError("allowed_hosts must be a nonempty list of hosts/IPs/CIDRs.")
        if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or timeout_ms <= 0:
            raise ValueError("timeout_ms must be a positive integer.")
        self.run_id, self.timeout_ms = run_id, timeout_ms
        self.allowed_hosts = []
        for entry in allowed_hosts:
            entry = entry.strip().lower().rstrip(".")
            try:
                entry = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", entry):
                    raise ValueError("Scope entries must be hosts, literal IPs or CIDRs.")
                entry = entry.encode("idna").decode("ascii")
            self.allowed_hosts.append(entry)
        self._lock = asyncio.Lock()
        self._playwright = self._browser = self._context = self._page = None
        self._refs = {}
        self._next_ref = 1
        self._blocked = False
        self._redirect_target = None
        self._route_error = None
        self._closed = False

    def in_scope(self, url: str) -> bool:
        try:
            parsed = urlsplit(url)
            _ = parsed.port  # Reject malformed ports.
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
                return False
            host = parsed.hostname.lower().rstrip(".").encode("idna").decode("ascii")
            for entry in self.allowed_hosts:
                if isinstance(entry, str):
                    if host == entry:
                        return True
                else:
                    try:
                        if ipaddress.ip_address(host) in entry:
                            return True
                    except ValueError:
                        pass
        except (ValueError, UnicodeError, AttributeError):
            pass
        return False

    async def _route(self, route):
        if self.in_scope(route.request.url):
            if route.request.is_navigation_request():
                # Playwright routing does not re-intercept an automatic redirect
                # chain. Fetch one response, abort redirects, and follow validated
                # main-frame targets explicitly in _goto instead.
                try:
                    response = await route.fetch(max_redirects=0, timeout=self.timeout_ms)
                except PlaywrightTimeout:
                    self._route_error = ("TIMEOUT", "Browser operation exceeded the configured timeout.")
                    await route.abort()
                    return
                except Error:
                    self._route_error = ("BROWSER_ERROR", "Browser operation failed.")
                    await route.abort()
                    return
                location = response.headers.get("location")
                if response.status in (301, 302, 303, 307, 308) and location:
                    target = urljoin(route.request.url, location)
                    if not self.in_scope(target):
                        self._blocked = True
                    elif route.request.frame != self._page.main_frame:
                        self._route_error = ("BROWSER_ERROR", "Redirects in subframes are not supported.")
                    elif response.status in (307, 308) and route.request.method not in ("GET", "HEAD"):
                        self._route_error = ("BROWSER_ERROR", "Redirects preserving a submitted request body are not supported.")
                    else:
                        self._redirect_target = target
                    # A 204 leaves the current document intact, without racing
                    # Chromium's chrome-error page against the explicit follow-up.
                    await route.fulfill(status=204, body="")
                else:
                    await route.fulfill(response=response)
            else:
                await route.continue_()
        else:
            if route.request.is_navigation_request():
                self._blocked = True
            await route.abort("blockedbyclient")

    async def open(self):
        if self._closed:
            raise ToolError("SESSION_CLOSED", "This browser session is closed.")
        if self._page is not None:
            return self
        try:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch()
            self._context = await self._browser.new_context(service_workers="block", accept_downloads=False)
            self._context.set_default_timeout(self.timeout_ms)
            self._context.set_default_navigation_timeout(self.timeout_ms)
            await self._context.route("**/*", self._route)
            self._page = await self._context.new_page()
            self._page.on("popup", lambda page: asyncio.create_task(page.close()))
            return self
        except BaseException:
            await self.close()
            raise

    async def close(self):
        try:
            if self._browser:
                await self._browser.close()
        finally:
            if self._playwright:
                await self._playwright.stop()
            self._refs.clear()
            self._page = self._context = self._browser = self._playwright = None
            self._closed = True

    async def __aenter__(self):
        return await self.open()

    async def __aexit__(self, *args):
        await self.close()

    async def _element(self, ref):
        handle = self._refs.get(ref) if isinstance(ref, str) else None
        if handle is None:
            raise ToolError("ELEMENT_NOT_FOUND", "Unknown or stale element ref; inspect the page again.")
        try:
            connected = await handle.evaluate("el => el.isConnected")
        except Error:
            connected = False
        if not connected:
            raise ToolError("ELEMENT_NOT_FOUND", "Unknown or stale element ref; inspect the page again.")
        return handle

    async def _goto(self, url):
        for _ in range(20):
            self._redirect_target = None
            try:
                response = await self._page.goto(url, wait_until="domcontentloaded")
            except Error:
                if not self._redirect_target:
                    raise
            if not self._redirect_target:
                return response
            url = self._redirect_target
        raise ToolError("BROWSER_ERROR", "Too many HTTP redirects.")

    @guarded
    async def navigate(self, url: str):
        if not self.in_scope(url):
            raise ToolError("OUT_OF_SCOPE", "URL must be HTTP(S) and its host must be in allowed_hosts.")
        response = await self._goto(url)
        return {"url": self._page.url, "title": await self._page.title(),
                "status": response.status if response else None}

    @guarded
    async def inspect_page(self, max_elements: int = 50):
        if not isinstance(max_elements, int) or isinstance(max_elements, bool) or not 1 <= max_elements <= 500:
            raise ToolError("INVALID_ARGUMENT", "max_elements must be between 1 and 500.")
        elements = []
        candidates = self._page.locator(SELECTOR)
        for index in range(await candidates.count()):
            locator = candidates.nth(index)
            if not await locator.is_visible():
                continue
            handle = await locator.element_handle()
            # Fixed internal DOM extraction; callers cannot supply scripts or selectors.
            if handle is None:
                continue
            info = await handle.evaluate(r"""el => {
                const tag = el.tagName.toLowerCase();
                const type = (el.getAttribute('type') || '').toLowerCase();
                const label = el.labels ? [...el.labels].map(x => x.innerText).join(' ') : '';
                const ids = (el.getAttribute('aria-labelledby') || '').split(/\s+/);
                const labelled = ids.map(id => document.getElementById(id)?.innerText || '').join(' ');
                return {tag, type, explicitRole: el.getAttribute('role'),
                    name: labelled.trim() || el.getAttribute('aria-label') || label ||
                        el.getAttribute('placeholder') || (tag === 'input' && ['submit','button'].includes(type) ? el.value : '') ||
                        el.innerText || el.getAttribute('title') || el.getAttribute('name') || '',
                    value: type === 'password' ? '********' : (el.value || '')};
            }""")
            roles = {"a": "link", "button": "button", "input": "textbox", "select": "combobox", "textarea": "textbox"}
            role = info["explicitRole"] or roles.get(info["tag"], "heading")
            if info["tag"] == "input":
                role = info["explicitRole"] or {"submit": "button", "button": "button", "checkbox": "checkbox", "radio": "radio"}.get(info["type"], "textbox")
            name = info["name"]
            # Accessibility snapshot is preferred for the computed role and name.
            # Never expose its full contents (it can contain input values).
            if info["type"] != "password":
                snapshot = await locator.aria_snapshot(timeout=self.timeout_ms)
                match = re.match(r'- ([a-z]+)(?: "((?:[^"\\]|\\.)*)")?', snapshot)
                if match:
                    role = match[1]
                    name = match[2] or name
            ref = await handle.evaluate("""(el, candidate) => {
                const key = '__webSecElementRefs';
                if (!window[key]) window[key] = new WeakMap();
                if (!window[key].has(el)) window[key].set(el, candidate);
                return window[key].get(el);
            }""", f"e{self._next_ref}")
            if ref not in self._refs:
                self._next_ref += 1
                self._refs[ref] = handle
            else:
                await handle.dispose()
            elements.append({"ref": ref, "role": role,
                             "name": " ".join(name.split())[:160],
                             "type": info["type"], "value": str(info["value"])[:200], "visible": True})
            if len(elements) == max_elements:
                break
        return {"url": self._page.url, "title": await self._page.title(), "elements": elements}

    @guarded
    async def click(self, ref: str):
        handle = await self._element(ref)
        self._redirect_target = None
        try:
            await handle.click()
        except Error:
            if not self._redirect_target:
                raise
        if self._redirect_target:
            await self._goto(self._redirect_target)
        await self._page.wait_for_load_state("domcontentloaded")
        return {"url_after": self._page.url, "title_after": await self._page.title()}

    @guarded
    async def fill(self, ref: str, value: str):
        if not isinstance(value, str):
            raise ToolError("INVALID_ARGUMENT", "value must be a string.")
        handle = await self._element(ref)
        await handle.fill(value)
        return {"filled": True}

    @guarded
    async def get_text(self, ref: str = ""):
        if ref:
            handle = await self._element(ref)
            if (await handle.get_attribute("type") or "").lower() == "password":
                text = "********"
            else:
                text = await handle.inner_text()
        else:
            text = await self._page.locator("body").inner_text()
        return {"text": text[:2000]}

    @guarded
    async def get_current_url(self):
        return {"url": self._page.url, "title": await self._page.title()}
    @guarded
    async def get_cookies(self, url: str = "", default_security: str = "low"):
        if self._context is None:
            raise ToolError("SESSION_CLOSED", "Browser context is not initialized.")
        raw_cookies = await self._context.cookies([url]) if url else await self._context.cookies()
        cookie_map = {}
        for c in raw_cookies:
            name = c.get("name")
            value = c.get("value")
            if name and value is not None:
                cookie_map[name] = value
        if "PHPSESSID" not in cookie_map:
            raise ToolError("COOKIE_NOT_FOUND", "PHPSESSID not found in browser context.")
        security = cookie_map.get("security") or default_security
        header = f"PHPSESSID={cookie_map['PHPSESSID']}; security={security}"
        return {"cookies": cookie_map, "cookie_header": header}
    @guarded
    async def screenshot(self, name: str):
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", name):
            raise ToolError("INVALID_ARGUMENT", "name must contain only letters, digits, underscores or hyphens (without .png).")
        relative = Path("media") / "runs" / self.run_id / f"{name}.png"
        destination = ROOT / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.resolve().is_relative_to((ROOT / "media" / "runs").resolve()):
            raise ToolError("INVALID_ARGUMENT", "Screenshot path escapes the runs directory.")
        await self._page.screenshot(path=str(destination), full_page=True)
        return {"path": relative.as_posix()}
