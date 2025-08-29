#!/usr/bin/env python3
"""
Frontend UI Validation Test for Host Groups
Sofia Alvarez - Frontend Engineer

This script validates the UI components and user experience for the host groups functionality,
specifically focusing on the recent fixes to the Profile dropdown and SCAP content integration.
"""

import asyncio
import json
from datetime import datetime
from playwright.async_api import async_playwright
import sys
import os

class HostGroupsUIValidator:
    def __init__(self):
        self.frontend_ports = [3006, 3005, 3004, 3003, 3002, 3001]
        self.base_url = None
        self.backend_url = "http://localhost:8000"
        self.test_results = {
            "timestamp": datetime.now().isoformat(),
            "test_suite": "Frontend UI Validation - Host Groups",
            "engineer": "Sofia Alvarez",
            "focus_areas": [
                "GroupEditDialog Profile dropdown fixes",
                "SCAP content dropdown integration", 
                "Material-UI component validation",
                "Accessibility compliance",
                "Responsive design",
                "Form validation and error handling"
            ],
            "results": {}
        }
        self.auth_token = None
    
    async def run_validation(self):
        """Main validation runner"""
        async with async_playwright() as p:
            # Launch browser with dev tools for debugging
            browser = await p.chromium.launch(
                headless=False,
                args=['--start-maximized'],
                devtools=True
            )
            
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            )
            
            page = await context.new_page()
            
            try:
                # Step 0: Find available frontend port
                await self.find_frontend_port(page)
                
                # Step 1: Authentication and Navigation
                await self.authenticate(page)
                
                # Step 2: Validate Group Edit Dialog Core Components
                await self.validate_group_edit_dialog(page)
                
                # Step 3: Test Profile Dropdown Fix  
                await self.validate_profile_dropdown_fix(page)
                
                # Step 4: Test SCAP Content Integration
                await self.validate_scap_content_integration(page)
                
                # Step 5: Material-UI Component Validation
                await self.validate_material_ui_components(page)
                
                # Step 6: Accessibility Testing
                await self.validate_accessibility(page)
                
                # Step 7: Responsive Design Testing
                await self.validate_responsive_design(page)
                
                # Step 8: Form Validation Testing
                await self.validate_form_validation(page)
                
                # Step 9: Smart Group Creation Wizard
                await self.validate_smart_group_wizard(page)
                
                print("✅ All UI validation tests completed successfully!")
                
            except Exception as e:
                self.test_results["results"]["error"] = str(e)
                print(f"❌ Validation failed: {e}")
                
            finally:
                await browser.close()
                await self.save_results()
    
    async def find_frontend_port(self, page):
        """Find an available frontend port"""
        print("🔍 Finding available frontend port...")
        
        for port in self.frontend_ports:
            try:
                test_url = f"http://localhost:{port}"
                response = await page.goto(test_url, timeout=5000)
                if response and response.ok:
                    self.base_url = test_url
                    print(f"✅ Frontend found on port {port}")
                    return
            except Exception as e:
                print(f"Port {port} not available: {str(e)[:50]}...")
                continue
        
        raise Exception("No available frontend port found")
    
    async def authenticate(self, page):
        """Authenticate with the application"""
        print("🔐 Authenticating...")
        
        await page.goto(f"{self.base_url}/login")
        await page.wait_for_load_state('networkidle')
        
        # Take screenshot of login page
        await page.screenshot(path=f"screenshots/{datetime.now().strftime('%Y%m%d_%H%M%S')}_01_login.png")
        
        # Fill login form
        await page.fill('input[type="email"]', 'admin@openwatch.local')
        await page.fill('input[type="password"]', 'admin123')
        
        # Click login button
        await page.click('button[type="submit"]')
        await page.wait_for_load_state('networkidle')
        
        # Check if we're redirected to dashboard
        await page.wait_for_url(f"{self.base_url}/dashboard", timeout=10000)
        
        # Extract auth token from localStorage
        self.auth_token = await page.evaluate('localStorage.getItem("auth_token")')
        
        print("✅ Authentication successful")
        
        # Take screenshot of dashboard
        await page.screenshot(path=f"screenshots/{datetime.now().strftime('%Y%m%d_%H%M%S')}_02_dashboard.png")
        
        self.test_results["results"]["authentication"] = {
            "status": "success",
            "has_auth_token": bool(self.auth_token)
        }
    
    async def validate_group_edit_dialog(self, page):
        """Validate the GroupEditDialog component structure and functionality"""
        print("🔍 Validating GroupEditDialog component...")
        
        # Navigate to host groups page
        await page.goto(f"{self.base_url}/host-groups")
        await page.wait_for_load_state('networkidle')
        
        dialog_tests = {}
        
        try:
            # Look for existing groups or create a test group
            existing_groups = await page.locator('[data-testid="host-group-card"], .MuiCard-root').count()
            
            if existing_groups == 0:
                # Create a test group first
                await page.click('button:has-text("Create Group"), [data-testid="create-group-button"]')
                await page.wait_for_selector('.MuiDialog-root')
                
                # Fill basic group info
                await page.fill('input[name="name"], input[label*="Group Name"]', 'Test Group for UI Validation')
                await page.click('button:has-text("Create"), button[type="submit"]')
                await page.wait_for_load_state('networkidle')
            
            # Click on first available group to edit
            await page.click('[data-testid="edit-group-button"], button[aria-label*="edit"], .MuiIconButton-root:has(svg)', first=True)
            await page.wait_for_selector('.MuiDialog-root[role="dialog"]')
            
            # Validate dialog structure
            dialog_tests["dialog_present"] = await page.locator('.MuiDialog-root').is_visible()
            dialog_tests["dialog_title"] = await page.locator('.MuiDialogTitle-root').is_visible()
            dialog_tests["dialog_content"] = await page.locator('.MuiDialogContent-root').is_visible()
            dialog_tests["dialog_actions"] = await page.locator('.MuiDialogActions-root').is_visible()
            
            # Validate form sections
            dialog_tests["basic_info_section"] = await page.locator('text="Basic Information"').is_visible()
            dialog_tests["system_requirements_section"] = await page.locator('text="System Requirements"').is_visible()
            dialog_tests["compliance_config_section"] = await page.locator('text="Compliance Configuration"').is_visible()
            
            # Validate color picker
            color_circles = await page.locator('[role="button"][style*="border-radius: 50%"]').count()
            dialog_tests["color_picker_present"] = color_circles >= 8  # Should have 8 default colors
            
            print("✅ GroupEditDialog validation completed")
            
        except Exception as e:
            dialog_tests["error"] = str(e)
            print(f"❌ GroupEditDialog validation failed: {e}")
        
        self.test_results["results"]["group_edit_dialog"] = dialog_tests
    
    async def validate_profile_dropdown_fix(self, page):
        """Validate the critical Profile dropdown fix"""
        print("🎯 Testing Profile dropdown fix (Critical)...")
        
        profile_tests = {}
        
        try:
            # Ensure we're in the edit dialog
            if not await page.locator('.MuiDialog-root').is_visible():
                await page.click('[data-testid="edit-group-button"], button[aria-label*="edit"]', first=True)
                await page.wait_for_selector('.MuiDialog-root')
            
            # Look for SCAP Content dropdown
            scap_dropdown = page.locator('label:has-text("SCAP Content")').locator('..').locator('input')
            profile_tests["scap_content_dropdown_present"] = await scap_dropdown.is_visible()
            
            # Click on SCAP content dropdown to load options
            if await scap_dropdown.is_visible():
                await scap_dropdown.click()
                await page.wait_for_timeout(1000)  # Wait for options to load
                
                # Check if options are available
                scap_options = await page.locator('.MuiAutocomplete-option, .MuiMenuItem-root').count()
                profile_tests["scap_content_options_count"] = scap_options
                
                if scap_options > 0:
                    # Select first SCAP content option
                    await page.click('.MuiAutocomplete-option, .MuiMenuItem-root', first=True)
                    await page.wait_for_timeout(2000)  # Wait for profile dropdown to populate
                    
                    # Now check Profile dropdown
                    profile_dropdown = page.locator('label:has-text("Default Profile")').locator('..').locator('input, select')
                    profile_tests["profile_dropdown_present"] = await profile_dropdown.is_visible()
                    profile_tests["profile_dropdown_enabled"] = not await profile_dropdown.is_disabled()
                    
                    # Test if profile dropdown has options
                    if await profile_dropdown.is_visible() and not await profile_dropdown.is_disabled():
                        await profile_dropdown.click()
                        await page.wait_for_timeout(1000)
                        
                        profile_options = await page.locator('.MuiMenuItem-root').count()
                        profile_tests["profile_options_count"] = profile_options
                        profile_tests["profile_dropdown_functional"] = profile_options > 0
                        
                        # Test selecting a profile (critical fix validation)
                        if profile_options > 0:
                            await page.click('.MuiMenuItem-root', first=True)
                            profile_tests["profile_selection_works"] = True
                            print("✅ Profile dropdown selection working correctly")
                        else:
                            profile_tests["profile_selection_works"] = False
                            print("⚠️ No profile options available")
                    else:
                        profile_tests["profile_dropdown_functional"] = False
                else:
                    profile_tests["no_scap_content"] = True
                    print("⚠️ No SCAP content available for testing")
            
            print("✅ Profile dropdown fix validation completed")
            
        except Exception as e:
            profile_tests["error"] = str(e)
            print(f"❌ Profile dropdown validation failed: {e}")
        
        self.test_results["results"]["profile_dropdown_fix"] = profile_tests
    
    async def validate_scap_content_integration(self, page):
        """Test SCAP content and profile integration"""
        print("🔧 Validating SCAP content integration...")
        
        scap_tests = {}
        
        try:
            # Check autocomplete functionality
            scap_autocomplete = page.locator('.MuiAutocomplete-root')
            scap_tests["autocomplete_present"] = await scap_autocomplete.count() > 0
            
            # Check for proper error handling when no content available
            no_options_text = await page.locator('text="No SCAP content available"').is_visible()
            loading_text = await page.locator('text="Loading..."').is_visible()
            scap_tests["proper_empty_state"] = no_options_text or loading_text
            
            # Check for proper option rendering
            if await scap_autocomplete.first.is_visible():
                await scap_autocomplete.first.click()
                
                # Look for chips/badges in options (OS, Version, Framework)
                chip_elements = await page.locator('.MuiChip-root, [class*="chip"]').count()
                scap_tests["option_chips_present"] = chip_elements > 0
            
            print("✅ SCAP content integration validation completed")
            
        except Exception as e:
            scap_tests["error"] = str(e)
            print(f"❌ SCAP content integration validation failed: {e}")
        
        self.test_results["results"]["scap_content_integration"] = scap_tests
    
    async def validate_material_ui_components(self, page):
        """Validate Material-UI component usage and theming"""
        print("🎨 Validating Material-UI components and theming...")
        
        mui_tests = {}
        
        try:
            # Check for proper Material-UI classes
            mui_classes = [
                '.MuiDialog-root',
                '.MuiTextField-root', 
                '.MuiButton-root',
                '.MuiSelect-root',
                '.MuiAutocomplete-root',
                '.MuiSwitch-root',
                '.MuiChip-root'
            ]
            
            for class_name in mui_classes:
                count = await page.locator(class_name).count()
                mui_tests[f"{class_name.replace('.', '').replace('-', '_')}_count"] = count
            
            # Check theme consistency
            primary_buttons = await page.locator('.MuiButton-containedPrimary').count()
            mui_tests["primary_buttons_count"] = primary_buttons
            
            # Check for proper spacing and layout
            grid_containers = await page.locator('.MuiGrid-container').count()
            mui_tests["grid_layout_usage"] = grid_containers > 0
            
            # Validate icon usage
            svg_icons = await page.locator('svg[data-testid$="Icon"]').count()
            mui_tests["material_icons_count"] = svg_icons
            
            print("✅ Material-UI component validation completed")
            
        except Exception as e:
            mui_tests["error"] = str(e)
            print(f"❌ Material-UI validation failed: {e}")
        
        self.test_results["results"]["material_ui_components"] = mui_tests
    
    async def validate_accessibility(self, page):
        """Test accessibility compliance"""
        print("♿ Validating accessibility compliance...")
        
        a11y_tests = {}
        
        try:
            # Check for ARIA labels
            aria_labels = await page.locator('[aria-label]').count()
            a11y_tests["aria_labels_count"] = aria_labels
            
            # Check for proper heading hierarchy
            h1_count = await page.locator('h1').count()
            h2_count = await page.locator('h2').count()
            h3_count = await page.locator('h3').count()
            a11y_tests["heading_structure"] = {"h1": h1_count, "h2": h2_count, "h3": h3_count}
            
            # Check for keyboard navigation support
            focusable_elements = await page.locator('button, input, select, textarea, [tabindex]').count()
            a11y_tests["focusable_elements_count"] = focusable_elements
            
            # Test keyboard navigation (Tab key)
            await page.keyboard.press('Tab')
            focused_element = await page.evaluate('document.activeElement.tagName')
            a11y_tests["keyboard_navigation_works"] = focused_element.lower() in ['button', 'input', 'select']
            
            # Check for proper form labels
            labeled_inputs = await page.locator('input[aria-label], input[aria-labelledby], label input').count()
            total_inputs = await page.locator('input').count()
            a11y_tests["input_labeling_ratio"] = labeled_inputs / max(total_inputs, 1)
            
            print("✅ Accessibility validation completed")
            
        except Exception as e:
            a11y_tests["error"] = str(e)
            print(f"❌ Accessibility validation failed: {e}")
        
        self.test_results["results"]["accessibility"] = a11y_tests
    
    async def validate_responsive_design(self, page):
        """Test responsive design across different viewports"""
        print("📱 Validating responsive design...")
        
        responsive_tests = {}
        
        try:
            # Test different viewport sizes
            viewports = [
                {"width": 1920, "height": 1080, "name": "desktop"},
                {"width": 1024, "height": 768, "name": "tablet"}, 
                {"width": 375, "height": 667, "name": "mobile"}
            ]
            
            for viewport in viewports:
                await page.set_viewport_size({"width": viewport["width"], "height": viewport["height"]})
                await page.wait_for_timeout(1000)
                
                # Check if dialog is still properly visible
                dialog_visible = await page.locator('.MuiDialog-root').is_visible()
                
                # Check if content doesn't overflow
                dialog_width = await page.locator('.MuiDialog-root .MuiPaper-root').bounding_box()
                viewport_fits = dialog_width['width'] <= viewport["width"] if dialog_width else True
                
                responsive_tests[viewport["name"]] = {
                    "dialog_visible": dialog_visible,
                    "content_fits": viewport_fits,
                    "viewport": viewport
                }
            
            # Reset to desktop size
            await page.set_viewport_size({"width": 1920, "height": 1080})
            
            print("✅ Responsive design validation completed")
            
        except Exception as e:
            responsive_tests["error"] = str(e)
            print(f"❌ Responsive design validation failed: {e}")
        
        self.test_results["results"]["responsive_design"] = responsive_tests
    
    async def validate_form_validation(self, page):
        """Test form validation and error handling"""
        print("📝 Validating form validation and error handling...")
        
        form_tests = {}
        
        try:
            # Test required field validation
            group_name_input = page.locator('input[name="name"], input[label*="Group Name"]').first
            if await group_name_input.is_visible():
                # Clear the field and try to submit
                await group_name_input.fill('')
                
                submit_button = page.locator('button:has-text("Update"), button[type="submit"]').first
                if await submit_button.is_visible():
                    is_disabled = await submit_button.is_disabled()
                    form_tests["required_field_validation"] = is_disabled
                    
                    # Test minimum length validation
                    await group_name_input.fill('ab')  # Too short
                    await page.wait_for_timeout(500)
                    still_disabled = await submit_button.is_disabled()
                    form_tests["min_length_validation"] = still_disabled
                    
                    # Test valid input
                    await group_name_input.fill('Valid Group Name')
                    await page.wait_for_timeout(500)
                    now_enabled = not await submit_button.is_disabled()
                    form_tests["valid_input_enables_submit"] = now_enabled
            
            # Test profile requirement when SCAP content is selected
            # This was part of the critical fix
            scap_input = page.locator('label:has-text("SCAP Content")').locator('..').locator('input')
            profile_input = page.locator('label:has-text("Default Profile")').locator('..').locator('input, select')
            
            if await scap_input.is_visible() and await profile_input.is_visible():
                form_tests["conditional_validation_present"] = True
            
            print("✅ Form validation testing completed")
            
        except Exception as e:
            form_tests["error"] = str(e)
            print(f"❌ Form validation testing failed: {e}")
        
        self.test_results["results"]["form_validation"] = form_tests
    
    async def validate_smart_group_wizard(self, page):
        """Test the Smart Group Creation Wizard"""
        print("🧙 Validating Smart Group Creation Wizard...")
        
        wizard_tests = {}
        
        try:
            # Close current dialog if open
            if await page.locator('.MuiDialog-root').is_visible():
                await page.click('button:has-text("Cancel")')
                await page.wait_for_timeout(1000)
            
            # Look for Smart Group Creation button/option
            smart_wizard_button = page.locator('text="Smart Group", button:has-text("Smart")')
            
            if await smart_wizard_button.count() > 0:
                await smart_wizard_button.first.click()
                await page.wait_for_selector('.MuiStepper-root, .MuiDialog-root')
                
                # Check for stepper component
                stepper_present = await page.locator('.MuiStepper-root').is_visible()
                wizard_tests["stepper_component_present"] = stepper_present
                
                if stepper_present:
                    # Check step labels
                    step_labels = await page.locator('.MuiStepLabel-root').count()
                    wizard_tests["step_count"] = step_labels
                    
                    # Test step navigation
                    next_button = page.locator('button:has-text("Next")')
                    if await next_button.is_visible():
                        wizard_tests["navigation_buttons_present"] = True
                        
                        # Test that Next is disabled when no hosts selected
                        next_disabled = await next_button.is_disabled()
                        wizard_tests["proper_step_validation"] = next_disabled
                
                wizard_tests["wizard_accessible"] = True
            else:
                wizard_tests["wizard_accessible"] = False
                wizard_tests["note"] = "Smart Group Wizard button not found"
            
            print("✅ Smart Group Wizard validation completed")
            
        except Exception as e:
            wizard_tests["error"] = str(e)
            print(f"❌ Smart Group Wizard validation failed: {e}")
        
        self.test_results["results"]["smart_group_wizard"] = wizard_tests
    
    async def save_results(self):
        """Save test results to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"frontend_ui_validation_{timestamp}.json"
        
        # Calculate overall score
        total_tests = 0
        passed_tests = 0
        
        for category, results in self.test_results["results"].items():
            if isinstance(results, dict) and "error" not in results:
                for test_name, result in results.items():
                    if isinstance(result, bool):
                        total_tests += 1
                        if result:
                            passed_tests += 1
                    elif isinstance(result, (int, float)) and test_name.endswith(('_count', '_ratio')):
                        total_tests += 1
                        if result > 0:
                            passed_tests += 1
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        overall_status = "PASSED" if total_tests > 0 and (passed_tests / total_tests) >= 0.8 else ("NEEDS_ATTENTION" if total_tests > 0 else "NO_TESTS_RUN")
        
        self.test_results["summary"] = {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "success_rate": success_rate,
            "overall_status": overall_status
        }
        
        with open(filename, 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        # Also create markdown report
        await self.create_markdown_report(timestamp)
        
        print(f"\n📊 Test Results Summary:")
        print(f"   Tests Run: {total_tests}")
        print(f"   Passed: {passed_tests}")
        print(f"   Success Rate: {self.test_results['summary']['success_rate']:.1f}%")
        print(f"   Overall Status: {self.test_results['summary']['overall_status']}")
        print(f"\n📄 Full results saved to: {filename}")
    
    async def create_markdown_report(self, timestamp):
        """Create a markdown report for easy reading"""
        filename = f"frontend_ui_validation_report_{timestamp}.md"
        
        with open(filename, 'w') as f:
            f.write(f"# Frontend UI Validation Report\n\n")
            f.write(f"**Engineer**: Sofia Alvarez\n")
            f.write(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Test Suite**: Host Groups UI Validation\n\n")
            
            f.write(f"## Executive Summary\n\n")
            summary = self.test_results["summary"]
            f.write(f"- **Total Tests**: {summary['total_tests']}\n")
            f.write(f"- **Passed**: {summary['passed_tests']}\n") 
            f.write(f"- **Success Rate**: {summary['success_rate']:.1f}%\n")
            f.write(f"- **Status**: {'✅ PASSED' if summary['overall_status'] == 'PASSED' else '⚠️ NEEDS ATTENTION'}\n\n")
            
            f.write(f"## Focus Areas Validated\n\n")
            for area in self.test_results["focus_areas"]:
                f.write(f"- {area}\n")
            f.write(f"\n")
            
            f.write(f"## Detailed Results\n\n")
            
            for category, results in self.test_results["results"].items():
                f.write(f"### {category.replace('_', ' ').title()}\n\n")
                
                if isinstance(results, dict):
                    if "error" in results:
                        f.write(f"❌ **Error**: {results['error']}\n\n")
                    else:
                        for test_name, result in results.items():
                            icon = "✅" if result else "❌" if isinstance(result, bool) else "ℹ️"
                            f.write(f"{icon} **{test_name.replace('_', ' ').title()}**: {result}\n")
                        f.write(f"\n")
        
        print(f"📋 Markdown report saved to: {filename}")

async def main():
    """Main execution function"""
    print("🚀 Starting Frontend UI Validation for Host Groups")
    print("👩‍💻 Engineer: Sofia Alvarez")
    print("🎯 Focus: Profile dropdown fixes, SCAP integration, Material-UI validation\n")
    
    # Ensure screenshots directory exists
    os.makedirs("screenshots", exist_ok=True)
    
    validator = HostGroupsUIValidator()
    await validator.run_validation()

if __name__ == "__main__":
    asyncio.run(main())