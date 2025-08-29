#!/usr/bin/env python3
"""
Backend API Validation Script for OpenWatch Host Groups
Tests all API endpoints supporting host groups functionality
"""
import requests
import json
import sys
import time
from typing import Dict, Any, List, Optional
from datetime import datetime


class APIValidator:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.auth_token = None
        self.test_results = []
        
    def log_result(self, endpoint: str, method: str, status: str, details: str, 
                   response_time: float = 0, status_code: int = 0):
        """Log test result"""
        result = {
            "endpoint": endpoint,
            "method": method,
            "status": status,
            "details": details,
            "response_time_ms": round(response_time * 1000, 2),
            "status_code": status_code,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        
        # Color coding for console output
        color = "\033[92m" if status == "PASS" else "\033[91m" if status == "FAIL" else "\033[93m"
        reset = "\033[0m"
        print(f"{color}[{status}]{reset} {method} {endpoint} - {details}")
        if response_time > 0:
            print(f"        Response time: {round(response_time * 1000, 2)}ms")
    
    def authenticate(self) -> bool:
        """Authenticate and get JWT token"""
        try:
            # Try to authenticate with default credentials
            auth_data = {
                "username": "admin",
                "password": "admin123"
            }
            
            start_time = time.time()
            response = self.session.post(
                f"{self.base_url}/api/auth/login",
                json=auth_data,
                timeout=10
            )
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                if "access_token" in data:
                    self.auth_token = data["access_token"]
                    self.session.headers.update({
                        "Authorization": f"Bearer {self.auth_token}"
                    })
                    self.log_result("/api/auth/login", "POST", "PASS", 
                                  "Authentication successful", response_time, response.status_code)
                    return True
                else:
                    self.log_result("/api/auth/login", "POST", "FAIL", 
                                  f"No access_token in response: {data}", response_time, response.status_code)
            else:
                self.log_result("/api/auth/login", "POST", "FAIL", 
                              f"Authentication failed: {response.text}", response_time, response.status_code)
        except Exception as e:
            self.log_result("/api/auth/login", "POST", "FAIL", 
                          f"Authentication error: {str(e)}", 0, 0)
        
        return False
    
    def test_health_endpoint(self) -> bool:
        """Test health check endpoint"""
        try:
            start_time = time.time()
            response = self.session.get(f"{self.base_url}/health", timeout=10)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                if "status" in data:
                    self.log_result("/health", "GET", "PASS", 
                                  f"Health check OK - Status: {data.get('status')}", 
                                  response_time, response.status_code)
                    return True
                else:
                    self.log_result("/health", "GET", "FAIL", 
                                  f"Invalid health response format: {data}", 
                                  response_time, response.status_code)
            else:
                self.log_result("/health", "GET", "FAIL", 
                              f"Health check failed: {response.text}", 
                              response_time, response.status_code)
        except Exception as e:
            self.log_result("/health", "GET", "FAIL", f"Health check error: {str(e)}", 0, 0)
        
        return False
    
    def test_scap_content_endpoint(self) -> bool:
        """Test the SCAP content endpoint that was causing frontend issues"""
        try:
            start_time = time.time()
            response = self.session.get(f"{self.base_url}/api/scap-content/", timeout=30)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    # Check if response has the expected scap_content key
                    if "scap_content" in data:
                        scap_content = data["scap_content"]
                        
                        # Validate data structure
                        if isinstance(scap_content, list):
                            self.log_result("/api/scap-content/", "GET", "PASS", 
                                          f"SCAP content retrieved successfully - {len(scap_content)} items", 
                                          response_time, response.status_code)
                            
                            # Test profile data structure for any existing content
                            if scap_content:
                                self.validate_scap_profiles_structure(scap_content[0])
                            
                            return True
                        else:
                            self.log_result("/api/scap-content/", "GET", "FAIL", 
                                          f"scap_content is not a list: {type(scap_content)}", 
                                          response_time, response.status_code)
                    else:
                        self.log_result("/api/scap-content/", "GET", "FAIL", 
                                      f"Response missing 'scap_content' key. Keys: {list(data.keys())}", 
                                      response_time, response.status_code)
                except json.JSONDecodeError as e:
                    self.log_result("/api/scap-content/", "GET", "FAIL", 
                                  f"Invalid JSON response: {str(e)}", response_time, response.status_code)
            elif response.status_code == 401:
                self.log_result("/api/scap-content/", "GET", "FAIL", 
                              "Authentication required", response_time, response.status_code)
            else:
                self.log_result("/api/scap-content/", "GET", "FAIL", 
                              f"Unexpected status code: {response.status_code} - {response.text}", 
                              response_time, response.status_code)
        except Exception as e:
            self.log_result("/api/scap-content/", "GET", "FAIL", 
                          f"SCAP content endpoint error: {str(e)}", 0, 0)
        
        return False
    
    def validate_scap_profiles_structure(self, content_item: Dict[str, Any]):
        """Validate SCAP profiles structure matches frontend expectations"""
        if "profiles" in content_item:
            profiles = content_item["profiles"]
            
            # Check if profiles can be both strings and objects
            if isinstance(profiles, list) and profiles:
                profile = profiles[0]
                
                # Validate profile structure
                expected_fields = ["id", "title", "description"]
                missing_fields = []
                
                if isinstance(profile, dict):
                    for field in expected_fields:
                        if field not in profile:
                            missing_fields.append(field)
                    
                    if not missing_fields:
                        self.log_result("/api/scap-content/", "GET", "PASS", 
                                      "Profile structure validation passed", 0, 200)
                    else:
                        self.log_result("/api/scap-content/", "GET", "WARN", 
                                      f"Profile missing fields: {missing_fields}", 0, 200)
                elif isinstance(profile, str):
                    self.log_result("/api/scap-content/", "GET", "INFO", 
                                  "Profile is string format (legacy)", 0, 200)
                else:
                    self.log_result("/api/scap-content/", "GET", "WARN", 
                                  f"Unexpected profile type: {type(profile)}", 0, 200)
    
    def test_host_groups_endpoints(self) -> bool:
        """Test host groups management endpoints"""
        success_count = 0
        total_tests = 0
        
        # Test list host groups
        total_tests += 1
        if self.test_list_host_groups():
            success_count += 1
        
        # Test create host group
        total_tests += 1
        group_id = self.test_create_host_group()
        if group_id:
            success_count += 1
            
            # Test update host group
            total_tests += 1
            if self.test_update_host_group(group_id):
                success_count += 1
            
            # Test group validation endpoints
            total_tests += 1
            if self.test_group_validation_endpoints(group_id):
                success_count += 1
            
            # Test delete host group
            total_tests += 1
            if self.test_delete_host_group(group_id):
                success_count += 1
        
        return success_count >= total_tests * 0.8  # 80% success rate
    
    def test_list_host_groups(self) -> bool:
        """Test listing host groups"""
        try:
            start_time = time.time()
            response = self.session.get(f"{self.base_url}/api/host-groups/", timeout=30)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_result("/api/host-groups/", "GET", "PASS", 
                                  f"Listed {len(data)} host groups", response_time, response.status_code)
                    return True
                else:
                    self.log_result("/api/host-groups/", "GET", "FAIL", 
                                  f"Response is not a list: {type(data)}", response_time, response.status_code)
            else:
                self.log_result("/api/host-groups/", "GET", "FAIL", 
                              f"Failed to list groups: {response.text}", response_time, response.status_code)
        except Exception as e:
            self.log_result("/api/host-groups/", "GET", "FAIL", 
                          f"List groups error: {str(e)}", 0, 0)
        
        return False
    
    def test_create_host_group(self) -> Optional[int]:
        """Test creating a host group"""
        try:
            group_data = {
                "name": f"test-group-{int(time.time())}",
                "description": "Test group for API validation",
                "color": "#4CAF50",
                "os_family": "ubuntu",
                "os_version_pattern": "22.04",
                "architecture": "x86_64"
            }
            
            start_time = time.time()
            response = self.session.post(
                f"{self.base_url}/api/host-groups/", 
                json=group_data, 
                timeout=30
            )
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                if "id" in data:
                    group_id = data["id"]
                    self.log_result("/api/host-groups/", "POST", "PASS", 
                                  f"Created group with ID {group_id}", response_time, response.status_code)
                    return group_id
                else:
                    self.log_result("/api/host-groups/", "POST", "FAIL", 
                                  f"No ID in response: {data}", response_time, response.status_code)
            else:
                self.log_result("/api/host-groups/", "POST", "FAIL", 
                              f"Failed to create group: {response.text}", response_time, response.status_code)
        except Exception as e:
            self.log_result("/api/host-groups/", "POST", "FAIL", 
                          f"Create group error: {str(e)}", 0, 0)
        
        return None
    
    def test_update_host_group(self, group_id: int) -> bool:
        """Test updating a host group"""
        try:
            update_data = {
                "description": "Updated test group description",
                "color": "#2196F3"
            }
            
            start_time = time.time()
            response = self.session.put(
                f"{self.base_url}/api/host-groups/{group_id}", 
                json=update_data, 
                timeout=30
            )
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                if data.get("description") == update_data["description"]:
                    self.log_result(f"/api/host-groups/{group_id}", "PUT", "PASS", 
                                  "Group updated successfully", response_time, response.status_code)
                    return True
                else:
                    self.log_result(f"/api/host-groups/{group_id}", "PUT", "FAIL", 
                                  f"Update not reflected in response: {data}", response_time, response.status_code)
            else:
                self.log_result(f"/api/host-groups/{group_id}", "PUT", "FAIL", 
                              f"Failed to update group: {response.text}", response_time, response.status_code)
        except Exception as e:
            self.log_result(f"/api/host-groups/{group_id}", "PUT", "FAIL", 
                          f"Update group error: {str(e)}", 0, 0)
        
        return False
    
    def test_group_validation_endpoints(self, group_id: int) -> bool:
        """Test group validation endpoints"""
        try:
            # Test host compatibility validation
            validation_data = {
                "host_ids": ["test-host-1", "test-host-2"]
            }
            
            start_time = time.time()
            response = self.session.post(
                f"{self.base_url}/api/host-groups/{group_id}/validate-hosts", 
                json=validation_data, 
                timeout=30
            )
            response_time = time.time() - start_time
            
            # We expect this to return either success or a validation error
            # since test hosts don't exist
            if response.status_code in [200, 400, 404]:
                self.log_result(f"/api/host-groups/{group_id}/validate-hosts", "POST", "PASS", 
                              f"Validation endpoint responded appropriately", response_time, response.status_code)
                return True
            else:
                self.log_result(f"/api/host-groups/{group_id}/validate-hosts", "POST", "FAIL", 
                              f"Unexpected response: {response.text}", response_time, response.status_code)
        except Exception as e:
            self.log_result(f"/api/host-groups/{group_id}/validate-hosts", "POST", "FAIL", 
                          f"Validation endpoint error: {str(e)}", 0, 0)
        
        return False
    
    def test_delete_host_group(self, group_id: int) -> bool:
        """Test deleting a host group"""
        try:
            start_time = time.time()
            response = self.session.delete(f"{self.base_url}/api/host-groups/{group_id}", timeout=30)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data:
                    self.log_result(f"/api/host-groups/{group_id}", "DELETE", "PASS", 
                                  "Group deleted successfully", response_time, response.status_code)
                    return True
                else:
                    self.log_result(f"/api/host-groups/{group_id}", "DELETE", "FAIL", 
                                  f"No message in response: {data}", response_time, response.status_code)
            else:
                self.log_result(f"/api/host-groups/{group_id}", "DELETE", "FAIL", 
                              f"Failed to delete group: {response.text}", response_time, response.status_code)
        except Exception as e:
            self.log_result(f"/api/host-groups/{group_id}", "DELETE", "FAIL", 
                          f"Delete group error: {str(e)}", 0, 0)
        
        return False
    
    def test_hosts_endpoint(self) -> bool:
        """Test hosts endpoint that includes group information"""
        try:
            start_time = time.time()
            response = self.session.get(f"{self.base_url}/api/hosts/", timeout=30)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_result("/api/hosts/", "GET", "PASS", 
                                  f"Listed {len(data)} hosts", response_time, response.status_code)
                    
                    # Check if group information is included in host data
                    if data:
                        host = data[0]
                        group_fields = ['group_id', 'group_name', 'group_description', 'group_color']
                        present_fields = [field for field in group_fields if field in host]
                        
                        if present_fields:
                            self.log_result("/api/hosts/", "GET", "INFO", 
                                          f"Group fields present: {present_fields}", 0, 200)
                        else:
                            self.log_result("/api/hosts/", "GET", "INFO", 
                                          "No group fields in host data (expected if no groups assigned)", 0, 200)
                    
                    return True
                else:
                    self.log_result("/api/hosts/", "GET", "FAIL", 
                                  f"Response is not a list: {type(data)}", response_time, response.status_code)
            else:
                self.log_result("/api/hosts/", "GET", "FAIL", 
                              f"Failed to list hosts: {response.text}", response_time, response.status_code)
        except Exception as e:
            self.log_result("/api/hosts/", "GET", "FAIL", 
                          f"List hosts error: {str(e)}", 0, 0)
        
        return False
    
    def test_error_handling(self) -> bool:
        """Test API error handling scenarios"""
        success_count = 0
        total_tests = 0
        
        # Test 404 endpoints
        total_tests += 1
        if self.test_404_error():
            success_count += 1
        
        # Test invalid group ID
        total_tests += 1  
        if self.test_invalid_group_id():
            success_count += 1
        
        # Test malformed data
        total_tests += 1
        if self.test_malformed_data():
            success_count += 1
        
        return success_count >= total_tests * 0.8
    
    def test_404_error(self) -> bool:
        """Test 404 error handling"""
        try:
            start_time = time.time()
            response = self.session.get(f"{self.base_url}/api/host-groups/99999", timeout=10)
            response_time = time.time() - start_time
            
            if response.status_code == 404:
                self.log_result("/api/host-groups/99999", "GET", "PASS", 
                              "404 error handled correctly", response_time, response.status_code)
                return True
            else:
                self.log_result("/api/host-groups/99999", "GET", "FAIL", 
                              f"Expected 404, got {response.status_code}", response_time, response.status_code)
        except Exception as e:
            self.log_result("/api/host-groups/99999", "GET", "FAIL", 
                          f"404 test error: {str(e)}", 0, 0)
        
        return False
    
    def test_invalid_group_id(self) -> bool:
        """Test invalid group ID handling"""
        try:
            start_time = time.time()
            response = self.session.get(f"{self.base_url}/api/host-groups/invalid", timeout=10)
            response_time = time.time() - start_time
            
            if response.status_code in [400, 422]:
                self.log_result("/api/host-groups/invalid", "GET", "PASS", 
                              f"Invalid ID handled correctly ({response.status_code})", response_time, response.status_code)
                return True
            else:
                self.log_result("/api/host-groups/invalid", "GET", "FAIL", 
                              f"Expected 400/422, got {response.status_code}", response_time, response.status_code)
        except Exception as e:
            self.log_result("/api/host-groups/invalid", "GET", "FAIL", 
                          f"Invalid ID test error: {str(e)}", 0, 0)
        
        return False
    
    def test_malformed_data(self) -> bool:
        """Test malformed data handling"""
        try:
            malformed_data = {
                "name": "",  # Empty name should be invalid
                "color": "invalid-color",
                "invalid_field": "should be ignored"
            }
            
            start_time = time.time()
            response = self.session.post(
                f"{self.base_url}/api/host-groups/", 
                json=malformed_data, 
                timeout=10
            )
            response_time = time.time() - start_time
            
            if response.status_code in [400, 422]:
                self.log_result("/api/host-groups/", "POST", "PASS", 
                              f"Malformed data rejected correctly ({response.status_code})", 
                              response_time, response.status_code)
                return True
            else:
                self.log_result("/api/host-groups/", "POST", "FAIL", 
                              f"Expected 400/422, got {response.status_code}", response_time, response.status_code)
        except Exception as e:
            self.log_result("/api/host-groups/", "POST", "FAIL", 
                          f"Malformed data test error: {str(e)}", 0, 0)
        
        return False
    
    def test_performance(self) -> bool:
        """Test API performance benchmarks"""
        success_count = 0
        total_tests = 0
        
        # Test multiple concurrent requests to SCAP content
        total_tests += 1
        if self.test_concurrent_requests():
            success_count += 1
        
        # Test large data handling
        total_tests += 1
        if self.test_response_time_limits():
            success_count += 1
        
        return success_count >= total_tests * 0.5  # More lenient for performance tests
    
    def test_concurrent_requests(self) -> bool:
        """Test concurrent API requests"""
        import concurrent.futures
        import threading
        
        def make_request():
            try:
                response = self.session.get(f"{self.base_url}/api/scap-content/", timeout=30)
                return response.status_code == 200
            except:
                return False
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(make_request) for _ in range(10)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]
                
                success_rate = sum(results) / len(results)
                if success_rate >= 0.8:  # 80% success rate
                    self.log_result("/api/scap-content/", "GET", "PASS", 
                                  f"Concurrent requests succeeded ({success_rate*100:.1f}%)", 0, 200)
                    return True
                else:
                    self.log_result("/api/scap-content/", "GET", "FAIL", 
                                  f"Concurrent requests failed ({success_rate*100:.1f}%)", 0, 0)
        except Exception as e:
            self.log_result("/api/scap-content/", "GET", "FAIL", 
                          f"Concurrent test error: {str(e)}", 0, 0)
        
        return False
    
    def test_response_time_limits(self) -> bool:
        """Test response time limits"""
        endpoints = [
            ("/api/scap-content/", "GET"),
            ("/api/host-groups/", "GET"),
            ("/api/hosts/", "GET")
        ]
        
        passed = 0
        for endpoint, method in endpoints:
            try:
                start_time = time.time()
                response = getattr(self.session, method.lower())(
                    f"{self.base_url}{endpoint}", timeout=30
                )
                response_time = time.time() - start_time
                
                # Response should be under 5 seconds for normal operations
                if response_time < 5.0 and response.status_code == 200:
                    self.log_result(endpoint, method, "PASS", 
                                  f"Response time acceptable ({response_time:.2f}s)", response_time, response.status_code)
                    passed += 1
                elif response.status_code != 200:
                    self.log_result(endpoint, method, "FAIL", 
                                  f"Failed request - Status: {response.status_code}", response_time, response.status_code)
                else:
                    self.log_result(endpoint, method, "WARN", 
                                  f"Slow response time ({response_time:.2f}s)", response_time, response.status_code)
                    passed += 0.5  # Partial credit for slow but working endpoints
            except Exception as e:
                self.log_result(endpoint, method, "FAIL", 
                              f"Performance test error: {str(e)}", 0, 0)
        
        return passed >= len(endpoints) * 0.7  # 70% pass rate
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all validation tests"""
        print("🔍 Starting Backend API Validation for OpenWatch Host Groups")
        print("=" * 70)
        
        overall_success = True
        test_categories = {}
        
        # Health check (prerequisite)
        print("\n📋 Health Check")
        print("-" * 30)
        if not self.test_health_endpoint():
            print("❌ Health check failed - aborting tests")
            return {"success": False, "error": "Health check failed"}
        
        # Authentication (prerequisite)
        print("\n🔐 Authentication")
        print("-" * 30)
        if not self.authenticate():
            print("❌ Authentication failed - aborting tests")
            return {"success": False, "error": "Authentication failed"}
        
        # Core API Tests
        print("\n📊 SCAP Content API Tests")
        print("-" * 30)
        test_categories["scap_content"] = self.test_scap_content_endpoint()
        if not test_categories["scap_content"]:
            overall_success = False
        
        print("\n👥 Host Groups API Tests")
        print("-" * 30)
        test_categories["host_groups"] = self.test_host_groups_endpoints()
        if not test_categories["host_groups"]:
            overall_success = False
        
        print("\n💻 Hosts API Tests")
        print("-" * 30)
        test_categories["hosts"] = self.test_hosts_endpoint()
        if not test_categories["hosts"]:
            overall_success = False
        
        print("\n⚠️  Error Handling Tests")
        print("-" * 30)
        test_categories["error_handling"] = self.test_error_handling()
        
        print("\n🚀 Performance Tests")
        print("-" * 30)
        test_categories["performance"] = self.test_performance()
        
        # Summary
        print("\n" + "=" * 70)
        print("📈 VALIDATION SUMMARY")
        print("=" * 70)
        
        passed_tests = sum(1 for result in self.test_results if result["status"] == "PASS")
        failed_tests = sum(1 for result in self.test_results if result["status"] == "FAIL")
        warned_tests = sum(1 for result in self.test_results if result["status"] in ["WARN", "INFO"])
        total_tests = len(self.test_results)
        
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"⚠️  Warnings/Info: {warned_tests}")
        print(f"📊 Total: {total_tests}")
        print(f"📈 Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        # Category breakdown
        print("\n📋 Category Results:")
        for category, success in test_categories.items():
            status = "✅ PASS" if success else "❌ FAIL"
            print(f"  {category.replace('_', ' ').title()}: {status}")
        
        # Critical Issues
        critical_failures = [
            result for result in self.test_results 
            if result["status"] == "FAIL" and result["endpoint"] in [
                "/api/scap-content/", "/api/host-groups/", "/api/hosts/"
            ]
        ]
        
        if critical_failures:
            print(f"\n🚨 Critical Issues Found: {len(critical_failures)}")
            for failure in critical_failures[:5]:  # Show first 5
                print(f"  - {failure['method']} {failure['endpoint']}: {failure['details']}")
        
        return {
            "success": overall_success,
            "total_tests": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "warnings": warned_tests,
            "categories": test_categories,
            "critical_failures": critical_failures,
            "detailed_results": self.test_results
        }


def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate OpenWatch Backend API')
    parser.add_argument('--url', default='http://localhost:8000', 
                       help='Backend URL (default: http://localhost:8000)')
    parser.add_argument('--output', help='Output results to JSON file')
    args = parser.parse_args()
    
    # Run validation
    validator = APIValidator(args.url)
    results = validator.run_all_tests()
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n📄 Results saved to: {args.output}")
    
    # Exit with appropriate code
    sys.exit(0 if results["success"] else 1)


if __name__ == "__main__":
    main()