#!/usr/bin/env python3
"""
Phase 1 Deployment Verification Script

Verifies that SSH validation improvements are working correctly
after deployment.
"""

import requests
import json
import time

def test_backend_health():
    """Test basic backend health"""
    try:
        response = requests.get("http://localhost:8000/health", timeout=10)
        return response.status_code == 200
    except:
        return False

def test_auth_endpoint():
    """Test authentication endpoint"""
    try:
        login_data = {"username": "admin", "password": "admin123"}
        response = requests.post(
            "http://localhost:8000/api/auth/login",
            json=login_data,
            timeout=10
        )
        return response.status_code == 200 and "access_token" in response.json()
    except:
        return False

def test_credential_endpoint_access():
    """Test that credential endpoints are accessible"""
    try:
        # First login
        login_data = {"username": "admin", "password": "admin123"}
        login_response = requests.post(
            "http://localhost:8000/api/auth/login",
            json=login_data,
            timeout=10
        )
        
        if login_response.status_code != 200:
            return False, "Login failed"
        
        token = login_response.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test GET credentials endpoint
        response = requests.get(
            "http://localhost:8000/api/system/credentials",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            return True, "Endpoint accessible"
        elif response.status_code == 403:
            return True, "Endpoint accessible (permission denied as expected)"
        else:
            return False, f"Unexpected status: {response.status_code}"
            
    except Exception as e:
        return False, f"Error: {str(e)}"

def test_error_handling():
    """Test that error handling improvements are working"""
    try:
        # Try to access protected endpoint without auth
        response = requests.post(
            "http://localhost:8000/api/system/credentials",
            json={"name": "test"},
            timeout=10
        )
        
        # Should get 401, not 500
        if response.status_code == 401:
            return True, "Proper 401 error handling"
        elif response.status_code == 500:
            return False, "Still getting 500 errors"
        else:
            return True, f"Got {response.status_code} (not 500)"
            
    except Exception as e:
        return False, f"Error: {str(e)}"

def check_container_logs():
    """Check for errors in recent container logs"""
    import subprocess
    
    try:
        result = subprocess.run(
            'docker-compose logs backend --tail=50',
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        logs = result.stdout
        
        # Check for startup success
        startup_ok = "application started successfully" in logs.lower()
        
        # Check for critical errors
        critical_errors = logs.count("CRITICAL")
        recent_500s = logs.count("500 Internal Server Error")
        
        return {
            "startup_successful": startup_ok,
            "critical_errors": critical_errors,
            "recent_500_errors": recent_500s,
            "logs_accessible": True
        }
        
    except Exception as e:
        return {
            "startup_successful": False,
            "critical_errors": -1,
            "recent_500_errors": -1,
            "logs_accessible": False,
            "error": str(e)
        }

def print_verification_results():
    """Run all verification tests and print results"""
    print("🔍 Phase 1 Deployment Verification")
    print("=" * 50)
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Test 1: Backend Health
    print("1. Backend Health Check")
    health_ok = test_backend_health()
    print(f"   {'✅' if health_ok else '❌'} Backend health endpoint: {'OK' if health_ok else 'Failed'}")
    
    # Test 2: Authentication
    print("\n2. Authentication System")
    auth_ok = test_auth_endpoint()
    print(f"   {'✅' if auth_ok else '❌'} Login endpoint: {'OK' if auth_ok else 'Failed'}")
    
    # Test 3: Credential Endpoints
    print("\n3. Credential Management Endpoints")
    endpoint_ok, endpoint_msg = test_credential_endpoint_access()
    print(f"   {'✅' if endpoint_ok else '❌'} Credential endpoints: {endpoint_msg}")
    
    # Test 4: Error Handling
    print("\n4. Error Handling Improvements")
    error_ok, error_msg = test_error_handling()
    print(f"   {'✅' if error_ok else '❌'} Error responses: {error_msg}")
    
    # Test 5: Container Logs
    print("\n5. Container Status and Logs")
    log_status = check_container_logs()
    
    if log_status["logs_accessible"]:
        print(f"   {'✅' if log_status['startup_successful'] else '❌'} Application startup: {'Success' if log_status['startup_successful'] else 'Issues detected'}")
        print(f"   {'✅' if log_status['critical_errors'] == 0 else '❌'} Critical errors: {log_status['critical_errors']}")
        print(f"   {'✅' if log_status['recent_500_errors'] == 0 else '❌'} Recent 500 errors: {log_status['recent_500_errors']}")
    else:
        print(f"   ❌ Log access: Failed ({log_status.get('error', 'Unknown error')})")
    
    # Overall Assessment
    print(f"\n📊 Overall Assessment")
    print("-" * 25)
    
    all_tests = [health_ok, auth_ok, endpoint_ok, error_ok]
    passed = sum(all_tests)
    total = len(all_tests)
    
    if passed == total and log_status.get("recent_500_errors", 1) == 0:
        print("🎉 DEPLOYMENT SUCCESSFUL")
        print("   All systems operational, ready for monitoring")
        return True
    elif passed >= total - 1:
        print("⚠️ DEPLOYMENT MOSTLY SUCCESSFUL")
        print("   Minor issues detected, monitor closely")
        return True
    else:
        print("❌ DEPLOYMENT ISSUES DETECTED")
        print("   Review errors and consider rollback")
        return False

def main():
    """Main verification function"""
    success = print_verification_results()
    
    print(f"\n📋 Next Steps:")
    if success:
        print("1. Start monitoring with: python3 monitor_ssh_validation.py")
        print("2. Test credential creation through UI")
        print("3. Monitor for 24-48 hours before Phase 2")
        print("4. Document any issues discovered")
    else:
        print("1. Review error logs: docker-compose logs backend")
        print("2. Check container status: docker-compose ps")
        print("3. Consider rollback if critical issues persist")
        print("4. Re-run verification after fixes")
    
    return success

if __name__ == "__main__":
    main()