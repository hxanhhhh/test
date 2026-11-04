"""Demo helpers: browser interaction is exclusively through the seven tools."""

import asyncio
import json
import time

from browser_tools import tools


async def step(session, tool, **params):
    result = await getattr(tools, tool)(session, **params)
    # Do not log tool inputs: fill may contain a password.
    print(json.dumps({"tool": tool, **result}, ensure_ascii=False), flush=True)
    if not result["ok"]:
        raise RuntimeError(f'{tool}: {result["error"]["code"]}')
    return result["data"]


async def find(session, predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = await step(session, "inspect_page", max_elements=100)
        for element in data["elements"]:
            if predicate(element):
                return element["ref"]
        await asyncio.sleep(0.2)
    raise RuntimeError("Expected page element was not found within 15 seconds.")


async def read_until(session, predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = await step(session, "get_text")
        if predicate(data["text"]):
            return data["text"]
        await asyncio.sleep(0.2)
    raise RuntimeError("Expected page text was not found within 15 seconds.")
