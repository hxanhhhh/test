"""Search Juice Shop via its public search route using only the seven tools."""

import argparse
import asyncio
from pathlib import Path
import sys
from urllib.parse import quote
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from browser_tools import BrowserSession
from scripts.demo_common import find, read_until, step


async def main(keyword="apple"):
    async with BrowserSession(f"juice-{uuid4().hex}", ["127.0.0.1"]) as session:
        await step(session, "navigate", url="http://127.0.0.1:3000/")
        dismiss = await find(session, lambda e: e["role"] == "button" and "dismiss" in e["name"].lower())
        await step(session, "click", ref=dismiss)
        # Search uses the application route. The tool set deliberately has no press/JS tool.
        await step(session, "navigate", url=f"http://127.0.0.1:3000/#/search?q={quote(keyword, safe='')}")
        await read_until(session, lambda text: keyword.lower() in text.lower())
        await step(session, "inspect_page")
        await step(session, "get_current_url")
        await step(session, "screenshot", name="search-results")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keyword", default="apple")
    args = parser.parse_args()
    asyncio.run(main(args.keyword))
