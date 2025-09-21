#!/usr/bin/env python3
"""
Execute git and build commands for OpenWatch RPM 1.2.1-7
This script handles the git repository initialization, commit, and RPM build.
"""

import subprocess
import os
import sys
from pathlib import Path

def execute_command(cmd, cwd=None, capture_output=True):
    """Execute a command and return success status"""
    try:
        print(f"\n▶ Executing: {cmd}")
        if isinstance(cmd, str):
            result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=capture_output, text=True)
        else:
            result = subprocess.run(cmd, cwd=cwd, capture_output=capture_output, text=True)
        
        if result.stdout and capture_output:
            print(f"✓ Output: {result.stdout.strip()}")
        if result.stderr and capture_output:
            print(f"⚠ Error: {result.stderr.strip()}")
        
        if result.returncode == 0:
            print(f"✅ Success")
        else:
            print(f"❌ Failed with exit code {result.returncode}")
        
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False, "", str(e)

def main():
    """Main execution function"""
    print("🚀 OpenWatch RPM 1.2.1-7 Build Process")
    print("=" * 50)
    
    # Change to openwatch directory
    openwatch_dir = "/home/rracine/hanalyx/openwatch"
    if not os.path.exists(openwatch_dir):
        print(f"❌ ERROR: Directory not found: {openwatch_dir}")
        return False
    
    os.chdir(openwatch_dir)
    print(f"📁 Working directory: {os.getcwd()}")
    
    # Step 1: Git repository setup
    print(f"\n📋 Step 1: Git Repository Setup")
    print("-" * 30)
    
    git_dir = Path(".git")
    if not git_dir.exists():
        print("🔧 Initializing git repository...")
        success, _, _ = execute_command("git init")
        if not success:
            print("❌ Failed to initialize git repository")
            return False
        
        success, _, _ = execute_command("git branch -m main")
        if not success:
            print("❌ Failed to rename branch to main")
            return False
    else:
        print("ℹ️ Git repository already exists")
    
    # Check git status
    success, output, error = execute_command("git status --porcelain")
    if not success:
        print("❌ Failed to check git status")
        return False
    
    if output.strip():
        print(f"📝 Found {len(output.strip().splitlines())} changed files")
    else:
        print("ℹ️ No changes detected")
    
    # Step 2: Commit changes
    print(f"\n📋 Step 2: Committing Changes")
    print("-" * 30)
    
    # Add all files
    success, _, _ = execute_command("git add .")
    if not success:
        print("❌ Failed to add files to git")
        return False
    
    # Create commit
    commit_msg = '''Fix owadm directory permission handling for production installations

- Handle permission errors gracefully in CreateRequiredDirectories with warnings instead of failures
- Improve production vs development environment detection in CheckEnvironmentFiles  
- Skip chmod operations when permissions are already correct
- Add proper logging for production installation detection
- Remove emojis from owadm output for terminal compatibility
- Update RPM to version 1.2.1-7 with comprehensive cleanup script
- Switch to system containers instead of rootless for compatibility

Resolves the operation not permitted errors on security/keys directory
and missing backend/app/main.py issues reported in ow-fedora-error9.txt

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>'''
    
    success, output, error = execute_command(f'git commit -m "{commit_msg}"')
    if not success:
        if "nothing to commit" in error or "nothing to commit" in output:
            print("ℹ️ No changes to commit - repository is clean")
        else:
            print(f"❌ Git commit failed: {error}")
            return False
    else:
        print("✅ Changes committed successfully")
    
    # Step 3: Build RPM
    print(f"\n📋 Step 3: Building RPM")
    print("-" * 30)
    
    rpm_dir = "packaging/rpm"
    build_script = f"{rpm_dir}/build-rpm.sh"
    
    if not os.path.exists(build_script):
        print(f"❌ Build script not found: {build_script}")
        return False
    
    # Make executable
    success, _, _ = execute_command(f"chmod +x {build_script}")
    if not success:
        print("❌ Failed to make build script executable")
        return False
    
    # Change to RPM directory and build
    os.chdir(rpm_dir)
    print(f"📁 Changed to directory: {os.getcwd()}")
    
    success, output, error = execute_command("./build-rpm.sh", capture_output=False)
    if not success:
        print("❌ RPM build failed")
        return False
    
    # Step 4: Verify results
    print(f"\n📋 Step 4: Verification")
    print("-" * 30)
    
    dist_dir = "dist"
    if os.path.exists(dist_dir):
        print(f"📦 Contents of {dist_dir}:")
        execute_command(f"ls -la {dist_dir}")
        
        # Check for version 1.2.1-7
        version_7_files = [f for f in os.listdir(dist_dir) if "1.2.1-7" in f]
        if version_7_files:
            print(f"\n✅ Version 1.2.1-7 files found:")
            for f in version_7_files:
                print(f"   📄 {f}")
                execute_command(f"stat {dist_dir}/{f}")
        else:
            print("❌ Version 1.2.1-7 RPM not found!")
            return False
    else:
        print(f"❌ Dist directory not found: {dist_dir}")
        return False
    
    print(f"\n🎉 Build Completed Successfully!")
    print("=" * 50)
    print("✅ OpenWatch RPM version 1.2.1-7 has been built")
    print("✅ This version includes the owladm permission fixes")
    print("✅ The user can now install this RPM to resolve the errors")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)