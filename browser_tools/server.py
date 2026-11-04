"""Run with: python -m browser_tools.server --run-id demo --allowed-hosts 127.0.0.1"""

import argparse
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP

from .session import BrowserSession
from . import tools


def create_server(run_id: str, allowed_hosts: list[str]) -> FastMCP:
    session = BrowserSession(run_id, allowed_hosts)

    @asynccontextmanager
    async def lifespan(server):
        try:
            yield session
        finally:
            await session.close()

    server = FastMCP("Web Sec Browser", lifespan=lifespan)

    @server.tool()
    async def navigate(url: str) -> dict:
        """Open an HTTP(S) URL inside allowed_hosts in this run's browser."""
        return await tools.navigate(session, url)

    @server.tool()
    async def inspect_page(max_elements: int = 50) -> dict:
        """List visible meaningful elements with stable refs; limit 1..500, no raw HTML."""
        return await tools.inspect_page(session, max_elements)

    @server.tool()
    async def click(ref: str) -> dict:
        """Click an element ref previously returned by inspect_page."""
        return await tools.click(session, ref)

    @server.tool()
    async def fill(ref: str, value: str) -> dict:
        """Fill an input using its inspected ref; password values are hidden in results."""
        return await tools.fill(session, ref, value)

    @server.tool()
    async def get_text(ref: str = "") -> dict:
        """Read at most 2000 characters from a ref, or from the body if ref is empty."""
        return await tools.get_text(session, ref)

    @server.tool()
    async def get_current_url() -> dict:
        """Return the current page URL and title."""
        return await tools.get_current_url(session)

    @server.tool()
    async def screenshot(name: str) -> dict:
        """Save media/runs/<run_id>/<name>.png; name is a simple filename stem."""
        return await tools.screenshot(session, name)

    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--allowed-hosts", required=True, nargs="+", help="Hosts/IPs/CIDRs; space or comma separated")
    args = parser.parse_args()
    hosts = [host for entry in args.allowed_hosts for host in entry.split(",") if host]
    create_server(args.run_id, hosts).run(transport="stdio")


if __name__ == "__main__":
    main()
