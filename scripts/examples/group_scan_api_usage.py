"""
Example usage of the Group Scan Progress API
Demonstrates how to use the new endpoints for tracking group scan progress
"""
import asyncio
import aiohttp
import json
from datetime import datetime
from typing import Dict, Any


class GroupScanAPIClient:
    """Example client for Group Scan API endpoints"""
    
    def __init__(self, base_url: str = "http://localhost:8000", auth_token: str = None):
        self.base_url = base_url
        self.auth_token = auth_token
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {auth_token}" if auth_token else ""
        }
    
    async def initiate_group_scan(self, group_id: int, scan_config: Dict[str, Any] = None) -> Dict:
        """Initiate a group scan for all hosts in a group"""
        url = f"{self.base_url}/api/host-groups/{group_id}/scan"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=self.headers, json=scan_config or {}) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise Exception(f"Failed to initiate group scan: {response.status} - {error_text}")
    
    async def get_scan_progress(self, session_id: str) -> Dict:
        """Get real-time progress of a group scan"""
        url = f"{self.base_url}/api/host-groups/scan-sessions/{session_id}/progress"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise Exception(f"Failed to get scan progress: {response.status} - {error_text}")
    
    async def get_host_scan_details(self, session_id: str) -> list:
        """Get detailed status of each host in a group scan"""
        url = f"{self.base_url}/api/host-groups/scan-sessions/{session_id}/hosts"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise Exception(f"Failed to get host details: {response.status} - {error_text}")
    
    async def cancel_group_scan(self, session_id: str) -> Dict:
        """Cancel an ongoing group scan"""
        url = f"{self.base_url}/api/host-groups/scan-sessions/{session_id}/cancel"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=self.headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise Exception(f"Failed to cancel group scan: {response.status} - {error_text}")
    
    async def get_active_scans(self) -> list:
        """Get all active scan sessions"""
        url = f"{self.base_url}/api/host-groups/scan-sessions/active"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise Exception(f"Failed to get active scans: {response.status} - {error_text}")
    
    async def get_group_scan_summary(self, session_id: str) -> Dict:
        """Get comprehensive summary of a completed group scan"""
        url = f"{self.base_url}/api/host-groups/scan-sessions/{session_id}/summary"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise Exception(f"Failed to get scan summary: {response.status} - {error_text}")
    
    async def list_scan_sessions(self, status: str = None, group_id: int = None, limit: int = 20) -> Dict:
        """List group scan sessions with filtering"""
        url = f"{self.base_url}/api/host-groups/scan-sessions"
        params = {"limit": limit}
        
        if status:
            params["status"] = status
        if group_id:
            params["group_id"] = group_id
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self.headers, params=params) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise Exception(f"Failed to list scan sessions: {response.status} - {error_text}")


async def example_group_scan_workflow():
    """
    Example workflow demonstrating the complete group scan process
    """
    # Initialize client (you would need a valid auth token)
    client = GroupScanAPIClient(
        base_url="http://localhost:8000", 
        auth_token="your_jwt_token_here"
    )
    
    try:
        # 1. Initiate a group scan
        print("🚀 Initiating group scan...")
        group_id = 1  # Replace with actual group ID
        scan_config = {
            "content_id": 1,  # SCAP content ID
            "profile_id": "xccdf_org.ssgproject.content_profile_standard",
            "priority": "high",
            "stagger_delay": 30,  # 30 seconds between scans
            "max_concurrent": 3,  # Maximum 3 concurrent scans
            "email_notify": True
        }
        
        scan_response = await client.initiate_group_scan(group_id, scan_config)
        session_id = scan_response["session_id"]
        
        print(f"✅ Group scan initiated successfully!")
        print(f"   Session ID: {session_id}")
        print(f"   Group: {scan_response['group_name']}")
        print(f"   Total hosts: {scan_response['total_hosts']}")
        print(f"   Status: {scan_response['status']}")
        print(f"   Estimated completion: {scan_response.get('estimated_completion', 'Unknown')}")
        
        # 2. Monitor progress in real-time
        print(f"\n📊 Monitoring scan progress...")
        while True:
            progress = await client.get_scan_progress(session_id)
            print(f"   Progress: {progress['progress_percentage']:.1f}% "
                  f"({progress['hosts_completed']}/{progress['total_hosts']} hosts)")
            print(f"   Status: {progress['status']}")
            print(f"   Scanning: {progress['hosts_scanning']}, "
                  f"Pending: {progress['hosts_pending']}, "
                  f"Failed: {progress['hosts_failed']}")
            
            if progress["status"] in ["completed", "failed", "cancelled"]:
                break
            
            await asyncio.sleep(10)  # Check every 10 seconds
        
        # 3. Get detailed host results
        print(f"\n🔍 Getting detailed host scan results...")
        host_details = await client.get_host_scan_details(session_id)
        
        for host in host_details:
            print(f"   Host: {host['host_name']} ({host['hostname']})")
            print(f"   Status: {host['status']}")
            if host['scan_results']:
                results = host['scan_results']
                print(f"   Results: {results['passed_rules']}/{results['total_rules']} passed, "
                      f"Score: {results['score']}")
            if host['error_message']:
                print(f"   Error: {host['error_message']}")
            print()
        
        # 4. Get comprehensive summary
        print(f"\n📈 Getting scan summary...")
        summary = await client.get_group_scan_summary(session_id)
        
        print(f"   Final Status: {summary['status']}")
        print(f"   Duration: {summary['scan_duration_minutes']} minutes")
        print(f"   Successful scans: {summary['successful_scans']}/{summary['total_hosts']}")
        print(f"   Failed scans: {summary['failed_scans']}")
        print(f"   Average compliance score: {summary['average_compliance_score']}%")
        print(f"   Total rules checked: {summary['total_rules_checked']}")
        print(f"   Total failed rules: {summary['total_failed_rules']}")
        
        print(f"\n✅ Group scan workflow completed successfully!")
        
    except Exception as e:
        print(f"❌ Error in group scan workflow: {e}")


async def example_scan_management():
    """
    Example of scan session management operations
    """
    client = GroupScanAPIClient(auth_token="your_jwt_token_here")
    
    try:
        # List all active scans
        print("📋 Getting active scans...")
        active_scans = await client.get_active_scans()
        
        if active_scans:
            print(f"Found {len(active_scans)} active scans:")
            for scan in active_scans:
                print(f"   {scan['session_id']}: {scan['group_name']} "
                      f"({scan['progress_percentage']:.1f}% complete)")
        else:
            print("No active scans found.")
        
        # List recent scan sessions
        print(f"\n📜 Getting recent scan sessions...")
        sessions = await client.list_scan_sessions(limit=10)
        
        print(f"Found {len(sessions['sessions'])} recent sessions:")
        for session in sessions["sessions"]:
            print(f"   {session['session_id'][:8]}... - {session['group_name']} "
                  f"({session['status']}, {session['progress_percentage']:.1f}%)")
        
    except Exception as e:
        print(f"❌ Error in scan management: {e}")


if __name__ == "__main__":
    print("🔧 Group Scan API Example Usage")
    print("=" * 50)
    
    # Note: This example requires a running OpenWatch backend with valid authentication
    # Replace 'your_jwt_token_here' with an actual JWT token
    
    print("\n⚠️  This example requires:")
    print("   - OpenWatch backend running on localhost:8000")
    print("   - Valid JWT authentication token")
    print("   - At least one host group with active hosts")
    print("   - SCAP content uploaded to the system")
    
    # Uncomment to run the examples (with proper authentication)
    # asyncio.run(example_group_scan_workflow())
    # asyncio.run(example_scan_management())
    
    print("\n💡 API Endpoints implemented:")
    print("   POST /api/host-groups/{group_id}/scan - Initiate group scan")
    print("   GET  /api/host-groups/scan-sessions/{session_id}/progress - Get progress")
    print("   GET  /api/host-groups/scan-sessions/{session_id}/hosts - Get host details")
    print("   POST /api/host-groups/scan-sessions/{session_id}/cancel - Cancel scan")
    print("   GET  /api/host-groups/scan-sessions/active - Get active scans")
    print("   GET  /api/host-groups/scan-sessions/{session_id}/summary - Get summary")
    print("   GET  /api/host-groups/scan-sessions - List scan sessions")