#!/usr/bin/env python3

import subprocess
import os
import sys

def run_command(cmd, cwd=None):
    """Run a command and return the result"""
    try:
        result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, check=True)
        return result.stdout, result.stderr, 0
    except subprocess.CalledProcessError as e:
        return e.stdout, e.stderr, e.returncode

def main():
    # Change to openwatch directory
    openwatch_dir = '/home/rracine/hanalyx/openwatch'
    os.chdir(openwatch_dir)
    print(f"Current directory: {os.getcwd()}")
    
    # Initialize git if needed
    if not os.path.exists('.git'):
        print("Initializing git repository...")
        stdout, stderr, code = run_command('git init')
        if code != 0:
            print(f"Git init failed: {stderr}")
            return 1
        
        stdout, stderr, code = run_command('git branch -m main')
        if code != 0:
            print(f"Branch rename failed: {stderr}")
            return 1
    else:
        print("Git repository already exists")
    
    # Check git status
    print("\nChecking git status...")
    stdout, stderr, code = run_command('git status')
    print(stdout)
    if stderr:
        print(f"Stderr: {stderr}")
    
    # Add all files
    print("\nAdding all files...")
    stdout, stderr, code = run_command('git add .')
    if code != 0:
        print(f"Git add failed: {stderr}")
        return 1
    
    # Commit changes
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

    print("\nCommitting changes...")
    stdout, stderr, code = run_command(f'git commit -m "{commit_message}"')
    if code != 0:
        print(f"Git commit failed: {stderr}")
        if "nothing to commit" in stderr:
            print("No changes to commit")
        else:
            return 1
    else:
        print("Commit successful!")
    
    # Build RPM
    print("\nBuilding RPM...")
    rpm_dir = os.path.join(openwatch_dir, 'packaging', 'rpm')
    
    # Make build script executable
    build_script = os.path.join(rpm_dir, 'build-rpm.sh')
    stdout, stderr, code = run_command(f'chmod +x {build_script}')
    
    # Run build script
    stdout, stderr, code = run_command('./build-rpm.sh', cwd=rpm_dir)
    print(f"Build output:\n{stdout}")
    if stderr:
        print(f"Build stderr:\n{stderr}")
    
    if code != 0:
        print(f"Build failed with code {code}")
        return 1
    
    # Check for created RPMs
    dist_dir = os.path.join(rpm_dir, 'dist')
    if os.path.exists(dist_dir):
        print(f"\nContents of {dist_dir}:")
        stdout, stderr, code = run_command(f'ls -la {dist_dir}')
        print(stdout)
        
        # Check for version 1.2.1-7
        stdout, stderr, code = run_command(f'ls -la {dist_dir}/openwatch-1.2.1-7*')
        if code == 0:
            print(f"\nVersion 1.2.1-7 RPM found:")
            print(stdout)
            
            # Show file stats
            stdout, stderr, code = run_command(f'stat {dist_dir}/openwatch-1.2.1-7*.rpm')
            if code == 0:
                print(f"File stats:\n{stdout}")
        else:
            print("Version 1.2.1-7 RPM not found")
    
    print("\nOperations completed!")
    return 0

if __name__ == '__main__':
    sys.exit(main())