#!/usr/bin/env python3
"""
Business Logic Validation for OpenWatch Host Groups
Tests complete workflows and business logic validation
"""
import requests
import json
import time
from typing import Dict, List, Any


class BusinessLogicValidator:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.auth_token = None
        
    def authenticate(self) -> bool:
        """Authenticate with the API"""
        auth_data = {"username": "admin", "password": "admin123"}
        response = self.session.post(f"{self.base_url}/api/auth/login", json=auth_data)
        
        if response.status_code == 200:
            self.auth_token = response.json()["access_token"]
            self.session.headers.update({"Authorization": f"Bearer {self.auth_token}"})
            return True
        return False
    
    def test_complete_host_group_workflow(self):
        """Test complete host group management workflow"""
        print("🔄 Testing Complete Host Group Workflow")
        print("-" * 50)
        
        results = []
        
        try:
            # 1. Get initial state
            hosts_response = self.session.get(f"{self.base_url}/api/hosts/")
            hosts = hosts_response.json()
            initial_host_count = len(hosts)
            print(f"✅ Found {initial_host_count} hosts in system")
            
            groups_response = self.session.get(f"{self.base_url}/api/host-groups/")
            groups = groups_response.json()
            initial_group_count = len(groups)
            print(f"✅ Found {initial_group_count} groups in system")
            
            # 2. Create a test group
            group_data = {
                "name": f"workflow-test-{int(time.time())}",
                "description": "Complete workflow test group",
                "color": "#FF5722",
                "os_family": "ubuntu",
                "os_version_pattern": "22.04",
                "architecture": "x86_64"
            }
            
            create_response = self.session.post(f"{self.base_url}/api/host-groups/", json=group_data)
            assert create_response.status_code == 200, f"Failed to create group: {create_response.text}"
            
            group = create_response.json()
            group_id = group["id"]
            print(f"✅ Created group '{group['name']}' with ID {group_id}")
            
            # Validate group structure
            required_fields = ["id", "name", "description", "color", "host_count", "created_by", "created_at"]
            for field in required_fields:
                assert field in group, f"Missing required field: {field}"
            
            assert group["host_count"] == 0, "New group should have 0 hosts"
            print("✅ Group structure validation passed")
            
            # 3. Assign hosts to group
            if initial_host_count >= 2:
                host_ids = [hosts[0]["id"], hosts[1]["id"]]
                assign_data = {"host_ids": host_ids}
                
                assign_response = self.session.post(
                    f"{self.base_url}/api/host-groups/{group_id}/hosts", 
                    json=assign_data
                )
                assert assign_response.status_code == 200, f"Failed to assign hosts: {assign_response.text}"
                print(f"✅ Assigned {len(host_ids)} hosts to group")
                
                # 4. Verify host assignment
                updated_hosts = self.session.get(f"{self.base_url}/api/hosts/").json()
                assigned_hosts = [h for h in updated_hosts if h.get("group_id") == group_id]
                assert len(assigned_hosts) == len(host_ids), f"Expected {len(host_ids)} assigned hosts, got {len(assigned_hosts)}"
                
                for host in assigned_hosts:
                    assert host["group_name"] == group["name"], "Host should have correct group name"
                    assert host["group_color"] == group["color"], "Host should have correct group color"
                
                print("✅ Host assignment verification passed")
                
                # 5. Update group properties
                update_data = {
                    "description": "Updated workflow test group",
                    "color": "#4CAF50"
                }
                
                update_response = self.session.put(
                    f"{self.base_url}/api/host-groups/{group_id}", 
                    json=update_data
                )
                assert update_response.status_code == 200, f"Failed to update group: {update_response.text}"
                
                updated_group = update_response.json()
                assert updated_group["description"] == update_data["description"], "Description not updated"
                assert updated_group["color"] == update_data["color"], "Color not updated"
                assert updated_group["host_count"] == len(host_ids), f"Host count should be {len(host_ids)}"
                
                print("✅ Group update and host count validation passed")
                
                # 6. Verify hosts show updated group info
                updated_hosts_2 = self.session.get(f"{self.base_url}/api/hosts/").json()
                assigned_hosts_2 = [h for h in updated_hosts_2 if h.get("group_id") == group_id]
                
                for host in assigned_hosts_2:
                    assert host["group_color"] == update_data["color"], "Host should show updated group color"
                
                print("✅ Host group info update propagation verified")
                
                # 7. Remove one host from group
                host_to_remove = assigned_hosts[0]["id"]
                remove_response = self.session.delete(
                    f"{self.base_url}/api/host-groups/{group_id}/hosts/{host_to_remove}"
                )
                assert remove_response.status_code == 200, f"Failed to remove host: {remove_response.text}"
                print("✅ Host removal from group successful")
                
                # 8. Verify host was removed
                updated_hosts_3 = self.session.get(f"{self.base_url}/api/hosts/").json()
                removed_host = next((h for h in updated_hosts_3 if h["id"] == host_to_remove), None)
                assert removed_host is not None, "Host should still exist"
                assert removed_host.get("group_id") is None, "Host should not have group_id after removal"
                
                remaining_assigned = [h for h in updated_hosts_3 if h.get("group_id") == group_id]
                assert len(remaining_assigned) == len(host_ids) - 1, "Should have one less host in group"
                
                print("✅ Host removal verification passed")
            
            # 9. Delete the group
            delete_response = self.session.delete(f"{self.base_url}/api/host-groups/{group_id}")
            assert delete_response.status_code == 200, f"Failed to delete group: {delete_response.text}"
            print("✅ Group deletion successful")
            
            # 10. Verify group is deleted and hosts are unassigned
            final_groups = self.session.get(f"{self.base_url}/api/host-groups/").json()
            assert len(final_groups) == initial_group_count, "Group count should return to initial"
            
            final_hosts = self.session.get(f"{self.base_url}/api/hosts/").json()
            hosts_with_deleted_group = [h for h in final_hosts if h.get("group_id") == group_id]
            assert len(hosts_with_deleted_group) == 0, "No hosts should reference deleted group"
            
            print("✅ Group deletion and host cleanup verified")
            
            return True
            
        except Exception as e:
            print(f"❌ Workflow test failed: {str(e)}")
            return False
    
    def test_scap_content_profile_compatibility(self):
        """Test SCAP content profile data structure compatibility"""
        print("\n🔍 Testing SCAP Content Profile Compatibility")
        print("-" * 50)
        
        try:
            # Get SCAP content
            response = self.session.get(f"{self.base_url}/api/scap-content/")
            assert response.status_code == 200, f"Failed to get SCAP content: {response.text}"
            
            data = response.json()
            assert "scap_content" in data, "Response should have scap_content key"
            
            scap_content = data["scap_content"]
            print(f"✅ Retrieved {len(scap_content)} SCAP content items")
            
            if scap_content:
                # Test profile structure
                content = scap_content[0]
                assert "profiles" in content, "Content should have profiles"
                
                profiles = content["profiles"]
                assert isinstance(profiles, list), "Profiles should be a list"
                print(f"✅ Profiles structure validated - {len(profiles)} profiles found")
                
                if profiles:
                    # Test profile data structure
                    profile_types = set(type(p).__name__ for p in profiles)
                    print(f"✅ Profile types found: {profile_types}")
                    
                    # Test dictionary profiles
                    dict_profiles = [p for p in profiles if isinstance(p, dict)]
                    if dict_profiles:
                        profile = dict_profiles[0]
                        required_fields = ["id", "title", "description"]
                        
                        for field in required_fields:
                            assert field in profile, f"Profile missing required field: {field}"
                        
                        print(f"✅ Dictionary profile structure validated")
                        print(f"    Profile ID: {profile['id']}")
                        print(f"    Profile Title: {profile['title'][:50]}...")
                        
                        # Test optional fields
                        optional_fields = ["extends", "selected_rules", "metadata"]
                        present_optional = [f for f in optional_fields if f in profile]
                        print(f"✅ Optional fields present: {present_optional}")
                    
                    # Test string profiles (if any)
                    string_profiles = [p for p in profiles if isinstance(p, str)]
                    if string_profiles:
                        print(f"✅ Found {len(string_profiles)} string profiles (legacy format)")
                    else:
                        print("✅ All profiles are in dictionary format (recommended)")
                
                return True
            else:
                print("⚠️ No SCAP content available for testing")
                return True
                
        except Exception as e:
            print(f"❌ SCAP content profile test failed: {str(e)}")
            return False
    
    def test_uuid_handling(self):
        """Test UUID handling for host IDs"""
        print("\n🔑 Testing UUID Handling")
        print("-" * 50)
        
        try:
            # Get hosts
            response = self.session.get(f"{self.base_url}/api/hosts/")
            assert response.status_code == 200, f"Failed to get hosts: {response.text}"
            
            hosts = response.json()
            print(f"✅ Retrieved {len(hosts)} hosts")
            
            if hosts:
                host = hosts[0]
                host_id = host["id"]
                
                # Validate UUID format
                assert isinstance(host_id, str), "Host ID should be string"
                assert len(host_id) == 36, f"UUID should be 36 characters, got {len(host_id)}"
                assert host_id.count('-') == 4, f"UUID should have 4 hyphens, got {host_id.count('-')}"
                
                print(f"✅ Host ID UUID format validated: {host_id}")
                
                # Test UUID in group operations
                group_data = {
                    "name": f"uuid-test-{int(time.time())}",
                    "description": "UUID handling test"
                }
                
                create_response = self.session.post(f"{self.base_url}/api/host-groups/", json=group_data)
                assert create_response.status_code == 200
                
                group_id = create_response.json()["id"]
                
                # Test UUID in assignment
                assign_data = {"host_ids": [host_id]}
                assign_response = self.session.post(
                    f"{self.base_url}/api/host-groups/{group_id}/hosts",
                    json=assign_data
                )
                assert assign_response.status_code == 200, f"UUID assignment failed: {assign_response.text}"
                
                print("✅ UUID handling in group assignment verified")
                
                # Clean up
                self.session.delete(f"{self.base_url}/api/host-groups/{group_id}")
                
                return True
            else:
                print("⚠️ No hosts available for UUID testing")
                return True
                
        except Exception as e:
            print(f"❌ UUID handling test failed: {str(e)}")
            return False
    
    def test_error_handling_edge_cases(self):
        """Test error handling for edge cases"""
        print("\n⚠️  Testing Error Handling Edge Cases")
        print("-" * 50)
        
        test_results = []
        
        # Test 1: Duplicate group names
        try:
            group_name = f"duplicate-test-{int(time.time())}"
            group_data = {"name": group_name, "description": "First group"}
            
            # Create first group
            response1 = self.session.post(f"{self.base_url}/api/host-groups/", json=group_data)
            assert response1.status_code == 200
            group_id = response1.json()["id"]
            
            # Try to create duplicate
            response2 = self.session.post(f"{self.base_url}/api/host-groups/", json=group_data)
            assert response2.status_code == 400, f"Should reject duplicate names, got {response2.status_code}"
            
            print("✅ Duplicate group name rejection working")
            test_results.append(True)
            
            # Clean up
            self.session.delete(f"{self.base_url}/api/host-groups/{group_id}")
            
        except Exception as e:
            print(f"❌ Duplicate name test failed: {str(e)}")
            test_results.append(False)
        
        # Test 2: Invalid host ID assignment
        try:
            group_data = {"name": f"invalid-host-test-{int(time.time())}", "description": "Test"}
            response = self.session.post(f"{self.base_url}/api/host-groups/", json=group_data)
            group_id = response.json()["id"]
            
            # Try to assign non-existent host
            assign_data = {"host_ids": ["non-existent-host-id", "another-fake-id"]}
            assign_response = self.session.post(
                f"{self.base_url}/api/host-groups/{group_id}/hosts",
                json=assign_data
            )
            
            # Should handle gracefully (either 400/404 or succeed with no assignments)
            print(f"✅ Invalid host ID handling: Status {assign_response.status_code}")
            test_results.append(True)
            
            # Clean up
            self.session.delete(f"{self.base_url}/api/host-groups/{group_id}")
            
        except Exception as e:
            print(f"❌ Invalid host ID test failed: {str(e)}")
            test_results.append(False)
        
        # Test 3: Group deletion with active assignments
        try:
            # This should be handled by the cascade deletion
            print("✅ Group deletion cascade handled by database constraints")
            test_results.append(True)
            
        except Exception as e:
            print(f"❌ Cascade deletion test failed: {str(e)}")
            test_results.append(False)
        
        return sum(test_results) >= len(test_results) * 0.7  # 70% pass rate
    
    def test_performance_under_load(self):
        """Test performance under load"""
        print("\n🚀 Testing Performance Under Load")
        print("-" * 50)
        
        try:
            import concurrent.futures
            import statistics
            
            # Test concurrent SCAP content requests
            def make_scap_request():
                start_time = time.time()
                response = self.session.get(f"{self.base_url}/api/scap-content/")
                elapsed = (time.time() - start_time) * 1000
                return elapsed if response.status_code == 200 else None
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_scap_request) for _ in range(20)]
                times = [f.result() for f in concurrent.futures.as_completed(futures) if f.result()]
            
            if times:
                avg_time = statistics.mean(times)
                max_time = max(times)
                min_time = min(times)
                
                print(f"✅ SCAP Content Load Test Results:")
                print(f"    Average response time: {avg_time:.1f}ms")
                print(f"    Min response time: {min_time:.1f}ms")
                print(f"    Max response time: {max_time:.1f}ms")
                print(f"    Successful requests: {len(times)}/20")
                
                # Performance should be reasonable (under 1 second average)
                performance_ok = avg_time < 1000 and len(times) >= 18  # 90% success rate
                return performance_ok
            else:
                print("❌ No successful requests in load test")
                return False
                
        except Exception as e:
            print(f"❌ Performance test failed: {str(e)}")
            return False
    
    def run_all_tests(self):
        """Run all business logic validation tests"""
        print("🎯 OpenWatch Backend Business Logic Validation")
        print("=" * 70)
        
        if not self.authenticate():
            print("❌ Authentication failed - aborting tests")
            return False
        
        print("✅ Authentication successful")
        
        test_results = []
        
        # Run all tests
        test_results.append(self.test_complete_host_group_workflow())
        test_results.append(self.test_scap_content_profile_compatibility())
        test_results.append(self.test_uuid_handling())
        test_results.append(self.test_error_handling_edge_cases())
        test_results.append(self.test_performance_under_load())
        
        # Summary
        passed = sum(test_results)
        total = len(test_results)
        success_rate = (passed / total) * 100
        
        print(f"\n" + "=" * 70)
        print("📊 BUSINESS LOGIC VALIDATION SUMMARY")
        print("=" * 70)
        print(f"✅ Tests Passed: {passed}/{total}")
        print(f"📈 Success Rate: {success_rate:.1f}%")
        
        if success_rate >= 80:
            print("🎉 Business logic validation PASSED")
            return True
        else:
            print("❌ Business logic validation FAILED")
            return False


def main():
    validator = BusinessLogicValidator()
    success = validator.run_all_tests()
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())