"""Open both lab sites with Playwright; exit nonzero if either fails."""
import asyncio
import json

from playwright.async_api import async_playwright


async def main():
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch()
        try:
            page = await browser.new_page()
            for url in ("http://127.0.0.1:4280/", "http://127.0.0.1:3000/"):
                response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                if response is None or response.status >= 400:
                    raise RuntimeError("Lab site did not return a successful response")
                print(json.dumps({"url": page.url, "title": await page.title(),
                                  "status": response.status}))
        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
