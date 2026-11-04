"""Real Chromium tests served exclusively from a local static HTML fixture."""

import asyncio
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import unittest
from uuid import uuid4

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from browser_tools import BrowserSession, tools
from browser_tools.session import ROOT


class QuietHandler(SimpleHTTPRequestHandler):
    outside_hits = 0

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/redirect-out":
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.server.server_port}/outside")
            self.end_headers()
        elif self.path == "/redirect-chain":
            self.send_response(302)
            self.send_header("Location", "/redirect-out")
            self.end_headers()
        elif self.path == "/redirect-inside":
            self.send_response(302)
            self.send_header("Location", "/browser.html?redirected=1")
            self.end_headers()
        elif self.path == "/outside":
            type(self).outside_hits += 1
            self.send_response(200)
            self.end_headers()
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == "/login-redirect":
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(302)
            self.send_header("Set-Cookie", "fixture_login=yes; Path=/; SameSite=Lax")
            self.send_header("Location", "/browser.html?logged_in=1")
            self.end_headers()
        else:
            self.send_error(404)


class LocalSite:
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        handler = partial(QuietHandler, directory=str(Path(__file__).parent / "fixtures"))
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.httpd.server_port}/browser.html"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()
        super().tearDownClass()


class BrowserToolTests(LocalSite, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.session = BrowserSession(f"test-{uuid4().hex}", ["127.0.0.1"], timeout_ms=600)
        self.addAsyncCleanup(self.session.close)
        self.data(await tools.navigate(self.session, self.url))

    def data(self, result):
        self.assertEqual(set(result), {"ok", "data", "error"})
        self.assertTrue(result["ok"], result)
        self.assertIsNone(result["error"])
        return result["data"]

    def error(self, result, code):
        self.assertEqual(set(result), {"ok", "data", "error"})
        self.assertFalse(result["ok"])
        self.assertIsNone(result["data"])
        self.assertEqual(set(result["error"]), {"code", "message"})
        self.assertEqual(result["error"]["code"], code)
        self.assertIsInstance(result["error"]["message"], str)

    async def elements(self):
        return self.data(await tools.inspect_page(self.session))["elements"]

    async def ref(self, name):
        return next(e["ref"] for e in await self.elements() if e["name"] == name)

    async def test_all_seven_tools_and_cookie_persistence(self):
        self.assertEqual(set(tools.__all__), {"navigate", "inspect_page", "click", "fill", "get_text", "get_current_url", "screenshot"})
        current = self.data(await tools.get_current_url(self.session))
        self.assertEqual(current, {"url": self.url, "title": "Local browser fixture"})
        user = await self.ref("Username")
        self.assertEqual(self.data(await tools.fill(self.session, user, "admin")), {"filled": True})
        self.assertEqual(next(e["value"] for e in await self.elements() if e["ref"] == user), "admin")
        clicked = self.data(await tools.click(self.session, await self.ref("Login")))
        self.assertEqual(set(clicked), {"url_after", "title_after"})
        self.assertEqual(self.data(await tools.get_text(self.session, await self.ref("Logged in"))), {"text": "Logged in"})
        nav = self.data(await tools.navigate(self.session, self.url + "?next=1"))
        self.assertEqual(set(nav), {"url", "title", "status"})
        self.assertEqual(nav["status"], 200)
        self.assertIn("Logged in", self.data(await tools.get_text(self.session))["text"])
        shot = self.data(await tools.screenshot(self.session, "page"))
        self.assertEqual(shot["path"], f"media/runs/{self.session.run_id}/page.png")
        path = ROOT / shot["path"]
        self.addCleanup(path.unlink, missing_ok=True)
        self.assertEqual(path.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")

    async def test_inspect_compact_accessible_and_password_redacted(self):
        elements = await self.elements()
        self.assertTrue(elements)
        for element in elements:
            self.assertEqual(set(element), {"ref", "role", "name", "type", "value", "visible"})
            self.assertRegex(element["ref"], r"^e\d+$")
            self.assertTrue(element["visible"])
            self.assertLessEqual(len(element["name"]), 160)
        self.assertIn("Accessible action", [e["name"] for e in elements])
        self.assertNotIn("Hidden button", [e["name"] for e in elements])
        password = next(e for e in elements if e["type"] == "password")
        self.assertEqual(password["value"], "********")
        self.assertNotIn("fixture-secret", json.dumps(elements))
        self.data(await tools.fill(self.session, password["ref"], "new-private-secret"))
        self.assertNotIn("new-private-secret", json.dumps(await self.elements()))
        self.assertEqual(self.data(await tools.get_text(self.session, password["ref"])), {"text": "********"})
        compact = self.data(await tools.inspect_page(self.session, 3))
        self.assertEqual(len(compact["elements"]), 3)
        self.assertNotIn("<html", json.dumps(compact).lower())
        self.assertNotIn("<script", json.dumps(compact).lower())
        self.assertEqual(len(self.data(await tools.get_text(self.session))["text"]), 2000)
        for limit in (0, -1, 501, True, "3"):
            self.error(await tools.inspect_page(self.session, limit), "INVALID_ARGUMENT")

    async def test_refs_stable_after_inspection_and_stale_after_removal_or_navigation(self):
        user = await self.ref("Username")
        self.assertEqual(await self.ref("Username"), user)
        self.data(await tools.click(self.session, await self.ref("Remove username")))
        self.error(await tools.fill(self.session, user, "x"), "ELEMENT_NOT_FOUND")
        login = await self.ref("Login")
        self.data(await tools.navigate(self.session, self.url))
        self.error(await tools.click(self.session, login), "ELEMENT_NOT_FOUND")
        self.assertNotEqual(await self.ref("Login"), login)

    async def test_unknown_refs_errors_and_timeout(self):
        self.error(await tools.click(self.session, "e999999"), "ELEMENT_NOT_FOUND")
        self.error(await tools.fill(self.session, "e999999", "secret"), "ELEMENT_NOT_FOUND")
        self.error(await tools.get_text(self.session, "e999999"), "ELEMENT_NOT_FOUND")
        self.error(await tools.click(self.session, await self.ref("Disabled button")), "TIMEOUT")
        self.assertEqual(self.data(await tools.get_current_url(self.session))["url"], self.url)

    async def test_scope_rejects_urls_and_link_navigation(self):
        for url in ("http://localhost:9/", "http://127.0.0.1.evil.invalid/", "file:///etc/passwd",
                    "javascript:alert(1)", "data:text/html,test", "http://127.0.0.1:bad/", "http://user:pass@127.0.0.1/"):
            with self.subTest(url=url):
                self.error(await tools.navigate(self.session, url), "OUT_OF_SCOPE")
        self.assertEqual(self.data(await tools.get_current_url(self.session))["url"], self.url)
        self.error(await tools.click(self.session, await self.ref("Outside scope")), "OUT_OF_SCOPE")

    async def test_safe_names_closed_session_and_session_isolation(self):
        for name in ("../escape", "/tmp/escape", "a.png", "", "$(id)"):
            self.error(await tools.screenshot(self.session, name), "INVALID_ARGUMENT")
        self.data(await tools.click(self.session, await self.ref("Login")))
        async with BrowserSession(f"isolated-{uuid4().hex}", ["127.0.0.1"]) as other:
            self.data(await tools.navigate(other, self.url))
            self.assertIn("Logged out", self.data(await tools.get_text(other))["text"])
        await self.session.close()
        self.error(await tools.get_current_url(self.session), "SESSION_CLOSED")

    async def test_http_redirect_chain_cannot_leave_scope(self):
        hits = QuietHandler.outside_hits
        base = self.url.rsplit("/", 1)[0]
        self.error(await tools.navigate(self.session, base + "/redirect-out"), "OUT_OF_SCOPE")
        self.error(await tools.navigate(self.session, base + "/redirect-chain"), "OUT_OF_SCOPE")
        self.assertEqual(QuietHandler.outside_hits, hits)

    async def test_allowed_redirect_and_cookie_from_form_submission(self):
        base = self.url.rsplit("/", 1)[0]
        data = self.data(await tools.navigate(self.session, base + "/redirect-inside"))
        self.assertEqual(data["url"], self.url + "?redirected=1")
        self.assertEqual(data["status"], 200)
        clicked = self.data(await tools.click(self.session, await self.ref("Submit login")))
        self.assertEqual(clicked["url_after"], self.url + "?logged_in=1")
        self.assertIn("Logged in", self.data(await tools.get_text(self.session))["text"])
        self.data(await tools.navigate(self.session, self.url))
        self.assertIn("Logged in", self.data(await tools.get_text(self.session))["text"])


class ScopeTests(unittest.TestCase):
    def test_exact_host_ip_and_cidr(self):
        session = BrowserSession("scope", ["example.com", "192.0.2.0/24", "::1/128"])
        for url in ("https://EXAMPLE.com./", "http://192.0.2.7:8080/", "http://[::1]/"):
            self.assertTrue(session.in_scope(url), url)
        for url in ("http://sub.example.com/", "http://193.0.2.7/", "https://example.com.evil/", "https://example.com@evil/"):
            self.assertFalse(session.in_scope(url), url)

    def test_constructor_validation_and_default_timeout(self):
        self.assertEqual(BrowserSession("valid", ["127.0.0.1"]).timeout_ms, 15000)
        for run_id, hosts in [("../bad", ["localhost"]), ("ok", []), ("ok", "localhost"), ("ok", ["http://localhost/"])]:
            with self.assertRaises(ValueError):
                BrowserSession(run_id, hosts)


class MCPTests(LocalSite, unittest.IsolatedAsyncioTestCase):
    async def test_stdio_schema_and_real_browser_calls(self):
        params = StdioServerParameters(command=sys.executable,
            args=["-m", "browser_tools.server", "--run-id", f"mcp-{uuid4().hex}", "--allowed-hosts", "127.0.0.1"], cwd=str(ROOT))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                listed = (await client.list_tools()).tools
                self.assertEqual({t.name for t in listed}, set(tools.__all__))
                schemas = {t.name: t.inputSchema for t in listed}
                self.assertEqual(schemas["navigate"]["required"], ["url"])
                self.assertEqual(schemas["fill"]["required"], ["ref", "value"])
                self.assertEqual(schemas["inspect_page"]["properties"]["max_elements"]["default"], 50)
                self.assertEqual(schemas["get_current_url"]["properties"], {})
                self.assertEqual((await client.list_resources()).resources, [])
                self.assertEqual((await client.list_prompts()).prompts, [])

                async def call(name, arguments):
                    result = await client.call_tool(name, arguments)
                    self.assertFalse(result.isError, result)
                    data = json.loads(result.content[0].text)
                    self.assertTrue(data["ok"], data)
                    return data["data"]

                self.assertEqual((await call("navigate", {"url": self.url}))["status"], 200)
                elements = (await call("inspect_page", {}))["elements"]
                login = next(e["ref"] for e in elements if e["name"] == "Login")
                self.assertEqual((await call("click", {"ref": login}))["title_after"], "Local browser fixture")
                self.assertIn("Logged in", (await call("get_text", {}))["text"])
                invalid = await client.call_tool("navigate", {"url": "file:///etc/passwd"})
                self.assertEqual(json.loads(invalid.content[0].text)["error"]["code"], "OUT_OF_SCOPE")
                unknown = await client.call_tool("evaluate", {"script": "1+1"})
                self.assertTrue(unknown.isError)


if __name__ == "__main__":
    unittest.main()
