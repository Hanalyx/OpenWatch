#!/usr/bin/env python3
"""
SSH Validation Monitoring Dashboard

Tracks the success rate and error patterns of SSH credential creation
after Phase 1 deployment.
"""

import subprocess
import time
import json
from datetime import datetime, timedelta
from collections import defaultdict

def get_log_stats(since_minutes=60):
    """Get statistics from backend logs"""
    since = datetime.now() - timedelta(minutes=since_minutes)
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")
    
    cmd = f'docker-compose logs backend --since "{since_str}"'
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        logs = result.stdout
    except subprocess.TimeoutExpired:
        return {"error": "Log retrieval timeout"}
    except Exception as e:
        return {"error": f"Log retrieval failed: {e}"}
    
    # Count different types of events
    stats = {
        "credential_creates": logs.count("POST /api/system/credentials"),
        "successful_stores": logs.count("Stored system credential"),
        "validation_errors": logs.count("validation failed"),
        "500_errors": logs.count("500 Internal Server Error"),
        "400_errors": logs.count("400 Bad Request"),
        "ssh_key_creates": logs.count("auth_method': 'ssh_key'"),
        "password_creates": logs.count("auth_method': 'password'"),
        "both_creates": logs.count("auth_method': 'both'"),
        "ssh_validation_failures": logs.count("Invalid SSH key"),
        "permission_errors": logs.count("403 Forbidden"),
        "auth_errors": logs.count("401 Unauthorized")
    }
    
    # Extract specific error messages
    error_lines = [line for line in logs.split('\n') if 'ERROR' in line and 'credential' in line.lower()]
    stats["recent_errors"] = error_lines[-5:] if error_lines else []
    
    return stats

def get_health_status():
    """Check container health"""
    try:
        result = subprocess.run('docker-compose ps', shell=True, capture_output=True, text=True)
        return "healthy" if "Up" in result.stdout else "degraded"
    except:
        return "unknown"

def print_dashboard():
    """Print monitoring dashboard"""
    print("🔍 SSH Validation Monitoring Dashboard")
    print("=" * 60)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Get health status
    health = get_health_status()
    health_emoji = "✅" if health == "healthy" else "⚠️" if health == "degraded" else "❓"
    print(f"System Health: {health_emoji} {health.upper()}")
    
    print("\n📊 Last Hour Statistics:")
    print("-" * 30)
    
    stats = get_log_stats(60)
    
    if "error" in stats:
        print(f"❌ Error: {stats['error']}")
        return
    
    total_attempts = stats["credential_creates"]
    successful = stats["successful_stores"]
    
    # Calculate success rate
    if total_attempts > 0:
        success_rate = (successful / total_attempts) * 100
        error_rate = ((stats["validation_errors"] + stats["500_errors"]) / total_attempts) * 100
    else:
        success_rate = 0
        error_rate = 0
    
    # Main metrics
    print(f"🎯 Credential Creation Attempts: {total_attempts}")
    print(f"✅ Successful: {successful} ({success_rate:.1f}%)")
    print(f"❌ Failed: {total_attempts - successful}")
    
    # Error breakdown
    print(f"\n🚨 Error Breakdown:")
    print(f"   Validation Errors: {stats['validation_errors']}")
    print(f"   500 Server Errors: {stats['500_errors']}")
    print(f"   400 Bad Requests: {stats['400_errors']}")
    print(f"   Auth/Permission: {stats['auth_errors'] + stats['permission_errors']}")
    
    # Credential types
    print(f"\n🔑 By Authentication Method:")
    print(f"   SSH Keys: {stats['ssh_key_creates']}")
    print(f"   Passwords: {stats['password_creates']}")
    print(f"   Both: {stats['both_creates']}")
    
    # SSH-specific metrics
    print(f"\n🔐 SSH Key Specific:")
    print(f"   SSH Validation Failures: {stats['ssh_validation_failures']}")
    
    # Status indicators
    print(f"\n📈 Health Indicators:")
    
    if stats["500_errors"] == 0:
        print("   ✅ No 500 errors (critical bugs fixed)")
    else:
        print(f"   ❌ {stats['500_errors']} 500 errors detected!")
    
    if success_rate >= 90:
        print("   ✅ High success rate (>90%)")
    elif success_rate >= 75:
        print("   ⚠️ Moderate success rate (75-90%)")
    else:
        print("   ❌ Low success rate (<75%)")
    
    if total_attempts == 0:
        print("   ℹ️ No credential creation attempts in last hour")
    
    # Recent errors
    if stats["recent_errors"]:
        print(f"\n🚨 Recent Errors (last 5):")
        for error in stats["recent_errors"]:
            # Clean up log line for readability
            error_clean = error.split(" - ")[-1][:80]
            print(f"   {error_clean}...")
    else:
        print(f"\n✅ No recent errors detected")

def print_24h_summary():
    """Print 24-hour summary"""
    print(f"\n📋 24-Hour Summary:")
    print("-" * 20)
    
    stats_24h = get_log_stats(24 * 60)  # 24 hours
    
    if "error" not in stats_24h:
        total_24h = stats_24h["credential_creates"]
        successful_24h = stats_24h["successful_stores"]
        
        if total_24h > 0:
            success_rate_24h = (successful_24h / total_24h) * 100
            print(f"Total Attempts: {total_24h}")
            print(f"Success Rate: {success_rate_24h:.1f}%")
            print(f"500 Errors: {stats_24h['500_errors']}")
        else:
            print("No credential creation activity")

def main():
    """Main monitoring loop"""
    try:
        while True:
            # Clear screen
            print("\033[2J\033[H")
            
            print_dashboard()
            print_24h_summary()
            
            print(f"\n⏱️ Next update in 30 seconds... (Ctrl+C to exit)")
            time.sleep(30)
            
    except KeyboardInterrupt:
        print("\n\n👋 Monitoring stopped by user")
    except Exception as e:
        print(f"\n❌ Monitoring error: {e}")

if __name__ == "__main__":
    print("🚀 Starting SSH Validation Monitoring...")
    print("This will track credential creation success/failure rates post-deployment")
    print("Press Ctrl+C to stop\n")
    
    main()