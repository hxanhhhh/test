"""Plain async Python functions shared by demo scripts and the MCP server."""

from .session import BrowserSession

__all__ = ["navigate", "inspect_page", "click", "fill", "get_text", "get_current_url", "screenshot"]


async def navigate(session: BrowserSession, url: str) -> dict:
    return await session.navigate(url)


async def inspect_page(session: BrowserSession, max_elements: int = 50) -> dict:
    return await session.inspect_page(max_elements)


async def click(session: BrowserSession, ref: str) -> dict:
    return await session.click(ref)


async def fill(session: BrowserSession, ref: str, value: str) -> dict:
    return await session.fill(ref, value)


async def get_text(session: BrowserSession, ref: str = "") -> dict:
    return await session.get_text(ref)


async def get_current_url(session: BrowserSession) -> dict:
    return await session.get_current_url()


async def screenshot(session: BrowserSession, name: str) -> dict:
    return await session.screenshot(name)
