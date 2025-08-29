import asyncio
from playwright.async_api import async_playwright

async def take_screenshot():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        page = await browser.new_page()
        
        print("🔍 Taking screenshot of current application state...")
        await page.goto("http://localhost:3004")
        await page.wait_for_load_state('networkidle')
        
        # Take screenshot
        await page.screenshot(path='current_app_state.png', full_page=True)
        
        # Get page title and content
        title = await page.title()
        content = await page.content()
        
        print(f"Page Title: {title}")
        print(f"Page contains login: {'login' in content.lower()}")
        print(f"Page contains form: {'<form' in content}")
        print(f"Page contains input: {'<input' in content}")
        
        # Check for common authentication elements
        auth_elements = []
        try:
            if await page.locator('input[type="email"]').count() > 0:
                auth_elements.append("Email input found")
        except: pass
        
        try:
            if await page.locator('input[type="password"]').count() > 0:
                auth_elements.append("Password input found")
        except: pass
        
        try:
            if await page.locator('button:has-text("Login")').count() > 0:
                auth_elements.append("Login button found")
        except: pass
        
        try:
            if await page.locator('[data-testid="user-menu"]').count() > 0:
                auth_elements.append("User menu found (already logged in)")
        except: pass
        
        print(f"Auth elements: {auth_elements}")
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(take_screenshot())