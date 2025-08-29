#!/usr/bin/env python3
"""
Comprehensive Host Groups Validation
Automated test with proper error handling and detailed reporting
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from playwright.async_api import async_playwright

BASE_URL = "http://localhost:3005"
SCREENSHOTS_DIR = Path(__file__).parent / "screenshots"
REPORTS_DIR = Path(__file__).parent / "reports"

SCREENSHOTS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

class HostGroupsValidator:
    def __init__(self):
        self.results = {
            "test_start": datetime.now().isoformat(),
            "environment": {"frontend_url": BASE_URL},
            "steps": {},
            "critical_fixes": {},
            "screenshots": [],
            "errors": [],
            "summary": {}
        }
    
    async def save_screenshot(self, page, name, description=""):
        """Save screenshot and log it"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{name}.png"
        filepath = SCREENSHOTS_DIR / filename
        await page.screenshot(path=str(filepath), full_page=True)
        
        self.results["screenshots"].append({
            "filename": filename,
            "description": description,
            "timestamp": timestamp
        })
        print(f"  📸 {filename}: {description}")
    
    def log_step(self, step_name, success, details=None, error=None):
        """Log test step result"""
        self.results["steps"][step_name] = {
            "success": success,
            "details": details or {},
            "error": str(error) if error else None,
            "timestamp": datetime.now().isoformat()
        }
        
        status = "✅" if success else "❌"
        print(f"{status} {step_name}")
        if error:
            print(f"   Error: {error}")
            self.results["errors"].append(f"{step_name}: {error}")
    
    def log_critical_fix(self, fix_name, working, details=None):
        """Log critical fix validation result"""
        self.results["critical_fixes"][fix_name] = {
            "working": working,
            "details": details or {},
            "timestamp": datetime.now().isoformat()
        }
        
        status = "✅ WORKING" if working else "❌ BROKEN"
        print(f"🔧 {fix_name}: {status}")
    
    async def run_validation(self):
        """Run the complete validation suite"""
        print("\n" + "="*60)
        print("🧪 COMPREHENSIVE HOST GROUPS VALIDATION")
        print("="*60)
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(viewport={"width": 1920, "height": 1080})
            page = await context.new_page()
            
            try:
                await self.test_login(page)
                await self.test_navigation(page)
                await self.test_host_groups_page(page)
                await self.test_edit_functionality(page)
                
            except Exception as e:
                print(f"💥 Validation suite failed: {e}")
                await self.save_screenshot(page, "suite_failure", f"Suite failed: {e}")
            finally:
                await browser.close()
                self.generate_final_report()
    
    async def test_login(self, page):
        """Test login functionality"""
        try:
            await page.goto(BASE_URL)
            await page.wait_for_load_state("networkidle")
            await self.save_screenshot(page, "01_initial_load", "Initial page load")
            
            # Fill credentials
            await page.fill('input[name="username"]', "admin")
            await page.fill('input[name="password"]', "admin123")
            await self.save_screenshot(page, "02_login_form", "Login form filled")
            
            # Submit
            await page.click('button[type="submit"]')
            await page.wait_for_timeout(3000)
            
            # Verify login success
            if await page.is_visible('text=Security Compliance Dashboard'):
                await self.save_screenshot(page, "03_login_success", "Dashboard loaded")
                self.log_step("Login", True, {"redirect": "dashboard"})
            else:
                await self.save_screenshot(page, "03_login_failed", "Login failed")
                self.log_step("Login", False, error="Dashboard not visible after login")
                
        except Exception as e:
            self.log_step("Login", False, error=e)
            await self.save_screenshot(page, "login_error", f"Login error: {e}")
    
    async def test_navigation(self, page):
        """Test navigation to Host Groups"""
        try:
            # Navigate to Hosts menu
            await page.click('text=Hosts')
            await page.wait_for_timeout(500)
            
            # Click Host Groups
            await page.click('text=Host Groups')
            await page.wait_for_timeout(1000)
            
            # Verify we're on the right page
            page_visible = (await page.is_visible('text=Compliance Groups') or 
                           await page.is_visible('text=Host Groups'))
            
            if page_visible:
                await self.save_screenshot(page, "04_host_groups_page", "Host Groups page loaded")
                self.log_step("Navigation", True, {"page": "Host Groups"})
            else:
                await self.save_screenshot(page, "04_navigation_failed", "Navigation failed")
                self.log_step("Navigation", False, error="Host Groups page not visible")
                
        except Exception as e:
            self.log_step("Navigation", False, error=e)
            await self.save_screenshot(page, "navigation_error", f"Navigation error: {e}")
    
    async def test_host_groups_page(self, page):
        """Test Host Groups page elements"""
        try:
            # Check for key elements
            elements_found = {}
            
            # Look for Create Group button
            create_btn = await page.is_visible('button:has-text("Create Group")')
            elements_found["create_button"] = create_btn
            
            # Look for existing groups
            groups = await page.query_selector_all('.MuiCard-root, [data-testid*="group"]')
            elements_found["existing_groups"] = len(groups)
            
            # Look for RHEL group specifically
            rhel_group = await page.is_visible('text=RHEL 8 STIG')
            elements_found["rhel_group"] = rhel_group
            
            # Look for menu buttons
            menu_buttons = await page.query_selector_all('button[aria-label="more"], button:has(svg)')
            elements_found["menu_buttons"] = len(menu_buttons)
            
            await self.save_screenshot(page, "05_page_elements", "Page elements scan")
            self.log_step("Page Elements Check", True, elements_found)
            
        except Exception as e:
            self.log_step("Page Elements Check", False, error=e)
            await self.save_screenshot(page, "page_elements_error", f"Page elements error: {e}")
    
    async def test_edit_functionality(self, page):
        """Test the edit functionality and critical fixes"""
        try:
            print("\n🔧 Testing Critical Fixes...")
            
            # Try multiple strategies to open edit dialog
            edit_dialog_opened = await self.try_open_edit_dialog(page)
            
            if edit_dialog_opened:
                await self.test_scap_content_dropdown(page)
                await self.test_profile_dropdown(page)
            else:
                self.log_critical_fix("SCAP Content Dropdown", False, 
                                    {"reason": "Could not open edit dialog"})
                self.log_critical_fix("Profile Object Handling", False, 
                                    {"reason": "Could not open edit dialog"})
        
        except Exception as e:
            self.log_step("Edit Functionality", False, error=e)
            await self.save_screenshot(page, "edit_error", f"Edit error: {e}")
    
    async def try_open_edit_dialog(self, page):
        """Try multiple strategies to open the edit dialog"""
        strategies = [
            ("aria_label", 'button[aria-label="more"]'),
            ("three_dots", 'button:has-text("⋯")'),
            ("menu_icon", 'button:has([data-testid="MoreVertIcon"])'),
            ("icon_button", '.MuiIconButton-root'),
            ("svg_button", 'button:has(svg)')
        ]
        
        for strategy_name, selector in strategies:
            try:
                print(f"   Trying {strategy_name} strategy...")
                elements = await page.query_selector_all(selector)
                
                for i, element in enumerate(elements):
                    try:
                        # Click the element
                        await element.click(timeout=2000)
                        await page.wait_for_timeout(1000)
                        
                        # Look for menu
                        if await page.is_visible('[role="menu"], .MuiMenu-root'):
                            print(f"   ✓ Menu opened with {strategy_name}[{i}]")
                            await self.save_screenshot(page, f"06_menu_{strategy_name}", f"Menu opened via {strategy_name}")
                            
                            # Try to click Edit
                            edit_selectors = ['text=Edit', '[role="menuitem"]', 'li:has-text("Edit")']
                            for edit_selector in edit_selectors:
                                try:
                                    await page.click(edit_selector, timeout=2000)
                                    await page.wait_for_timeout(2000)
                                    
                                    # Check if dialog opened
                                    dialog_open = (await page.is_visible('dialog') or 
                                                 await page.is_visible('.MuiDialog-root') or
                                                 await page.is_visible('form') or
                                                 await page.is_visible('input[name="name"]'))
                                    
                                    if dialog_open:
                                        print(f"   ✅ Edit dialog opened!")
                                        await self.save_screenshot(page, "07_edit_dialog", "Edit dialog opened")
                                        self.log_step("Open Edit Dialog", True, 
                                                    {"strategy": strategy_name, "element": i})
                                        return True
                                        
                                except:
                                    continue
                    except:
                        continue
            except:
                continue
        
        # If all strategies failed
        await self.save_screenshot(page, "edit_dialog_failed", "All strategies to open edit dialog failed")
        self.log_step("Open Edit Dialog", False, error="All strategies failed")
        return False
    
    async def test_scap_content_dropdown(self, page):
        """Test SCAP content dropdown fix"""
        try:
            print("   🔍 Testing SCAP content dropdown...")
            
            # Look for dropdowns in the dialog
            dropdowns = await page.query_selector_all(
                'select, .MuiSelect-root, [role="button"][aria-haspopup="listbox"]'
            )
            
            scap_dropdown_found = False
            for i, dropdown in enumerate(dropdowns):
                # Check context around dropdown
                context = await self.get_dropdown_context(page, dropdown)
                
                if ('scap' in context.lower() or 'content' in context.lower()):
                    print(f"   ✓ Found SCAP content dropdown")
                    scap_dropdown_found = True
                    
                    # Test the dropdown
                    await dropdown.click()
                    await page.wait_for_timeout(1000)
                    await self.save_screenshot(page, "08_scap_dropdown", "SCAP content dropdown opened")
                    
                    # Check for options
                    options = await page.query_selector_all(
                        'li[role="option"], .MuiMenuItem-root, option'
                    )
                    
                    if options:
                        self.log_critical_fix("SCAP Content Dropdown", True, 
                                            {"options_count": len(options)})
                        print(f"   ✅ SCAP dropdown has {len(options)} options - FIX WORKING!")
                        
                        # Test selection if multiple options
                        if len(options) > 1:
                            await options[1].click()
                            await page.wait_for_timeout(1000)
                            await self.save_screenshot(page, "09_scap_selected", "SCAP content selected")
                        
                        return True
                    else:
                        self.log_critical_fix("SCAP Content Dropdown", False, 
                                            {"reason": "Dropdown empty"})
                        print("   ❌ SCAP dropdown is EMPTY - BUG CONFIRMED!")
                        return False
                    break
            
            if not scap_dropdown_found:
                self.log_critical_fix("SCAP Content Dropdown", False, 
                                    {"reason": "Dropdown not found"})
                print("   ❌ SCAP content dropdown not found")
                return False
                
        except Exception as e:
            self.log_critical_fix("SCAP Content Dropdown", False, {"error": str(e)})
            print(f"   ❌ SCAP dropdown test failed: {e}")
            return False
    
    async def test_profile_dropdown(self, page):
        """Test profile dropdown object handling"""
        try:
            print("   🔍 Testing profile dropdown...")
            await page.wait_for_timeout(2000)  # Wait for profiles to load
            
            dropdowns = await page.query_selector_all(
                'select, .MuiSelect-root, [role="button"][aria-haspopup="listbox"]'
            )
            
            for i, dropdown in enumerate(dropdowns):
                context = await self.get_dropdown_context(page, dropdown)
                
                if ('profile' in context.lower()):
                    print(f"   ✓ Found profile dropdown")
                    
                    try:
                        # Test clicking without crashing
                        await dropdown.click()
                        await page.wait_for_timeout(1000)
                        await self.save_screenshot(page, "10_profile_dropdown", "Profile dropdown opened")
                        
                        # Check for options
                        options = await page.query_selector_all(
                            'li[role="option"], .MuiMenuItem-root, option'
                        )
                        
                        if options:
                            # Test selection
                            await options[0].click()
                            await page.wait_for_timeout(1000)
                            
                            self.log_critical_fix("Profile Object Handling", True, 
                                                {"options_count": len(options)})
                            print("   ✅ Profile dropdown works without crashes - FIX WORKING!")
                            await self.save_screenshot(page, "11_profile_selected", "Profile selected successfully")
                            return True
                        else:
                            self.log_critical_fix("Profile Object Handling", False, 
                                                {"reason": "No options available"})
                            print("   ⚠️  Profile dropdown empty")
                            return False
                            
                    except Exception as e:
                        self.log_critical_fix("Profile Object Handling", False, 
                                            {"error": f"Dropdown crashed: {e}"})
                        print(f"   ❌ Profile dropdown crashed: {e}")
                        await self.save_screenshot(page, "profile_crash", f"Profile crash: {e}")
                        return False
                    break
            else:
                self.log_critical_fix("Profile Object Handling", False, 
                                    {"reason": "Profile dropdown not found"})
                print("   ⚠️  Profile dropdown not found")
                return False
                
        except Exception as e:
            self.log_critical_fix("Profile Object Handling", False, {"error": str(e)})
            print(f"   ❌ Profile dropdown test failed: {e}")
            return False
    
    async def get_dropdown_context(self, page, dropdown):
        """Get text context around a dropdown element"""
        try:
            # Get text content of nearby elements
            parent = await dropdown.query_selector('xpath=..')
            if parent:
                return await parent.text_content()
            return await dropdown.text_content()
        except:
            return ""
    
    def generate_final_report(self):
        """Generate comprehensive final report"""
        self.results["test_end"] = datetime.now().isoformat()
        
        # Calculate summary
        total_steps = len(self.results["steps"])
        passed_steps = sum(1 for step in self.results["steps"].values() if step["success"])
        
        critical_fixes_working = sum(1 for fix in self.results["critical_fixes"].values() if fix["working"])
        total_critical_fixes = len(self.results["critical_fixes"])
        
        self.results["summary"] = {
            "total_steps": total_steps,
            "passed_steps": passed_steps,
            "failed_steps": total_steps - passed_steps,
            "critical_fixes_working": critical_fixes_working,
            "total_critical_fixes": total_critical_fixes,
            "overall_success": critical_fixes_working == total_critical_fixes and passed_steps >= total_steps - 1
        }
        
        # Print summary
        print("\n" + "="*60)
        print("🎯 VALIDATION SUMMARY")
        print("="*60)
        
        print(f"\n📊 STEP RESULTS:")
        for step_name, result in self.results["steps"].items():
            status = "✅" if result["success"] else "❌"
            print(f"  {status} {step_name}")
            if result["error"]:
                print(f"      Error: {result['error']}")
        
        print(f"\n🔧 CRITICAL FIXES:")
        for fix_name, result in self.results["critical_fixes"].items():
            status = "✅ WORKING" if result["working"] else "❌ BROKEN"
            print(f"  {status} {fix_name}")
            if result["details"]:
                print(f"      Details: {result['details']}")
        
        success_rate = (critical_fixes_working / max(total_critical_fixes, 1)) * 100
        print(f"\n🎯 OVERALL: {success_rate:.1f}% of critical fixes working")
        
        if success_rate == 100:
            print("✅ ALL CRITICAL FIXES ARE WORKING!")
        elif success_rate >= 50:
            print("⚠️  PARTIAL SUCCESS - Some fixes need attention")
        else:
            print("❌ CRITICAL ISSUES FOUND - Immediate attention needed")
        
        # Save detailed report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = REPORTS_DIR / f"comprehensive_validation_{timestamp}.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Generate markdown report
        self.generate_markdown_report(timestamp)
        
        print(f"\n📋 Reports saved:")
        print(f"  JSON: {report_file}")
        print(f"  Screenshots: {SCREENSHOTS_DIR}")
    
    def generate_markdown_report(self, timestamp):
        """Generate markdown report"""
        md_content = f"""# Host Groups E2E Validation Report

**Date**: {self.results['test_start']}  
**Environment**: {self.results['environment']['frontend_url']}

## Executive Summary

- **Steps Executed**: {self.results['summary']['total_steps']}
- **Steps Passed**: {self.results['summary']['passed_steps']}
- **Critical Fixes Tested**: {self.results['summary']['total_critical_fixes']}
- **Critical Fixes Working**: {self.results['summary']['critical_fixes_working']}

## Critical Fixes Status

"""
        
        for fix_name, result in self.results['critical_fixes'].items():
            status = "✅ WORKING" if result['working'] else "❌ BROKEN"
            md_content += f"### {fix_name}\n\n"
            md_content += f"**Status**: {status}\n\n"
            if result['details']:
                md_content += f"**Details**: {result['details']}\n\n"
        
        md_content += "\n## Test Steps\n\n"
        
        for step_name, result in self.results['steps'].items():
            status = "✅ PASS" if result['success'] else "❌ FAIL"
            md_content += f"- **{step_name}**: {status}\n"
            if result['error']:
                md_content += f"  - Error: {result['error']}\n"
        
        md_content += "\n## Screenshots\n\n"
        for screenshot in self.results['screenshots']:
            md_content += f"- `{screenshot['filename']}`: {screenshot['description']}\n"
        
        if self.results['errors']:
            md_content += "\n## Errors Encountered\n\n"
            for error in self.results['errors']:
                md_content += f"- {error}\n"
        
        # Save markdown
        md_file = REPORTS_DIR / f"validation_report_{timestamp}.md"
        with open(md_file, 'w') as f:
            f.write(md_content)
        
        print(f"  Markdown: {md_file}")

async def main():
    validator = HostGroupsValidator()
    await validator.run_validation()

if __name__ == "__main__":
    asyncio.run(main())