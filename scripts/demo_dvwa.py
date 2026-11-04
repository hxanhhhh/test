"""Login to an initialized DVWA lab using only the seven browser tools."""

import asyncio
from pathlib import Path
import sys
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from browser_tools import BrowserSession
from scripts.demo_common import find, step


async def main():
    async with BrowserSession(f"dvwa-{uuid4().hex}", ["127.0.0.1"]) as session:
        await step(session, "navigate", url="http://127.0.0.1:4280/login.php")
        username = await find(session, lambda e: e["role"] == "textbox" and e["type"] != "password")
        password = await find(session, lambda e: e["type"] == "password")
        await step(session, "fill", ref=username, value="admin")
        await step(session, "fill", ref=password, value="password")
        login = await find(session, lambda e: e["role"] == "button" and "login" in e["name"].lower())
        await step(session, "click", ref=login)
        # A logout link confirms authentication, rather than just a successful HTTP response.
        await find(session, lambda e: e["role"] == "link" and "logout" in e["name"].lower())
        await step(session, "navigate", url="http://127.0.0.1:4280/instructions.php")
        await find(session, lambda e: e["role"] == "link" and "logout" in e["name"].lower())
        await step(session, "get_current_url")
        await step(session, "get_text")
        await step(session, "screenshot", name="instructions")


if __name__ == "__main__":
    asyncio.run(main())
