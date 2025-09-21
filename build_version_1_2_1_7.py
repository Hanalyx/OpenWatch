#!/usr/bin/env python3

import subprocess
import os
import sys
from pathlib import Path

def run_command(cmd, cwd=None, check=True):
    """Run a command and return the result"""
    try:
        print(f"Running: {cmd}")
        if isinstance(cmd, str):
            result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, check=check)
        else:
            result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=check)
        
        if result.stdout:
            print(f"STDOUT: {result.stdout}")
        if result.stderr:
            print(f"STDERR: {result.stderr}")
        
        return result.stdout, result.stderr, result.returncode
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        if check:
            raise
        return e.stdout, e.stderr, e.returncode

def main():
    print("=== Building OpenWatch RPM Version 1.2.1-7 ===")
    
    # Set working directory
    openwatch_dir = Path("/home/rracine/hanalyx/openwatch")
    if not openwatch_dir.exists():
        print(f"ERROR: OpenWatch directory not found: {openwatch_dir}")
        return 1
    
    os.chdir(openwatch_dir)
    print(f"Working directory: {os.getcwd()}")
    
    # Step 1: Initialize git if needed and check status
    print("\n=== Step 1: Git Repository Setup ===")
    
    git_dir = openwatch_dir / ".git"
    if not git_dir.exists():
        print("Initializing git repository...")
        run_command(["git", "init"])
        run_command(["git", "branch", "-m", "main"])
    else:
        print("Git repository already exists")
    
    # Check git status
    stdout, stderr, code = run_command(["git", "status"], check=False)
    if code != 0:
        print("Git status failed, repository may not be properly initialized")
        return 1
    
    # Step 2: Add all files and commit
    print("\n=== Step 2: Committing Changes ===")
    
    run_command(["git", "add", "."])
    
    commit_message = """Fix owadm directory permission handling for production installations

- Handle permission errors gracefully in CreateRequiredDirectories with warnings instead of failures
- Improve production vs development environment detection in CheckEnvironmentFiles  
- Skip chmod operations when permissions are already correct
- Add proper logging for production installation detection
- Remove emojis from owadm output for terminal compatibility
- Update RPM to version 1.2.1-7 with comprehensive cleanup script
- Switch to system containers instead of rootless for compatibility

Resolves the 'operation not permitted' errors on security/keys directory
and missing backend/app/main.py issues reported in ow-fedora-error9.txt

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>"""

    stdout, stderr, code = run_command(["git", "commit", "-m", commit_message], check=False)
    if code != 0:
        if "nothing to commit" in stderr or "nothing to commit" in stdout:
            print("No changes to commit - repository is up to date")
        else:
            print(f"Git commit failed: {stderr}")
            return 1
    else:
        print("Changes committed successfully!")
    
    # Step 3: Build RPM
    print("\n=== Step 3: Building RPM Version 1.2.1-7 ===")
    
    rpm_dir = openwatch_dir / "packaging" / "rpm"
    build_script = rpm_dir / "build-rpm.sh"
    
    if not build_script.exists():
        print(f"ERROR: Build script not found: {build_script}")
        return 1
    
    # Make script executable
    run_command(["chmod", "+x", str(build_script)])
    
    # Run build script
    os.chdir(rpm_dir)
    stdout, stderr, code = run_command(["./build-rpm.sh"], check=False)
    
    if code != 0:
        print(f"RPM build failed with exit code {code}")
        return 1
    
    # Step 4: Verify results
    print("\n=== Step 4: Verification ===")
    
    dist_dir = rpm_dir / "dist"
    if dist_dir.exists():
        print(f"Contents of {dist_dir}:")
        run_command(["ls", "-la", str(dist_dir)])
        
        # Look for 1.2.1-7 specifically
        v7_files = list(dist_dir.glob("openwatch-1.2.1-7*"))
        if v7_files:
            print(f"\n✓ Version 1.2.1-7 RPMs found:")
            for f in v7_files:
                print(f"  - {f.name}")
                
            # Show file stats
            for f in v7_files:
                if f.suffix == ".rpm":
                    run_command(["stat", str(f)])
        else:
            print("ERROR: Version 1.2.1-7 RPM not found!")
            return 1
    else:
        print(f"ERROR: Dist directory not found: {dist_dir}")
        return 1
    
    print("\n=== Build Completed Successfully! ===")
    print("Version 1.2.1-7 RPM has been built and should resolve the permission errors.")
    return 0

if __name__ == "__main__":
    sys.exit(main())