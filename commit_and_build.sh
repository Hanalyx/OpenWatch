#!/bin/bash

# Script to commit owadm changes and build RPM version 1.2.1-7

set -e

echo "Step 1: Navigate to OpenWatch directory and check git status"
cd /home/rracine/hanalyx/openwatch
pwd

# Initialize git if not already done
if [ ! -d ".git" ]; then
    echo "Initializing git repository..."
    git init
    git branch -m main
fi

echo "Current git status:"
git status

echo "Step 2: Commit all changes"
git add .
git commit -m "Fix owadm directory permission handling for production installations

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

Co-Authored-By: Claude <noreply@anthropic.com>"

echo "Step 3: Build RPM version 1.2.1-7"
cd packaging/rpm
chmod +x build-rpm.sh
./build-rpm.sh

echo "Step 4: Verify the new RPM was created"
ls -la dist/openwatch-1.2.1-7*

echo "Step 5: Show file modification times to confirm the new binary is different"
if [ -f "dist/openwatch-1.2.1-6.x86_64.rpm" ]; then
    stat dist/openwatch-1.2.1-6.x86_64.rpm
fi
if [ -f "dist/openwatch-1.2.1-7.x86_64.rpm" ]; then
    stat dist/openwatch-1.2.1-7.x86_64.rpm
fi

echo "Build completed successfully!"