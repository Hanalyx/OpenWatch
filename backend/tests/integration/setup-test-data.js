// Setup test data for E2E testing

const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

const API_URL = 'http://localhost:8000';

async function getAuthToken() {
    try {
        const response = await axios.post(`${API_URL}/api/auth/login`, {
            username: 'admin',
            password: 'admin123'
        });
        return response.data.access_token;
    } catch (error) {
        console.error('Failed to authenticate:', error.response?.data || error.message);
        throw error;
    }
}

async function createTestHosts(token) {
    const hosts = [
        {
            hostname: 'test-host-01.local',
            ip_address: '192.168.1.101',
            os_type: 'linux',
            os_version: 'Ubuntu 22.04',
            ssh_port: 22
        },
        {
            hostname: 'test-host-02.local',
            ip_address: '192.168.1.102', 
            os_type: 'linux',
            os_version: 'Ubuntu 22.04',
            ssh_port: 22
        },
        {
            hostname: 'test-host-03.local',
            ip_address: '192.168.1.103',
            os_type: 'linux', 
            os_version: 'RHEL 9',
            ssh_port: 22
        }
    ];

    console.log('Creating test hosts...');
    
    for (const host of hosts) {
        try {
            await axios.post(`${API_URL}/api/hosts`, host, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
            console.log(`  ✓ Created host: ${host.hostname}`);
        } catch (error) {
            if (error.response?.status === 409) {
                console.log(`  - Host already exists: ${host.hostname}`);
            } else {
                console.error(`  ✗ Failed to create host ${host.hostname}:`, error.response?.data || error.message);
            }
        }
    }
}

async function uploadTestScapContent(token) {
    console.log('\nUploading test SCAP content...');
    
    // Check if we already have SCAP content
    try {
        const response = await axios.get(`${API_URL}/api/scap-content`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (response.data.content && response.data.content.length > 0) {
            console.log('  - SCAP content already exists, skipping upload');
            return;
        }
    } catch (error) {
        console.error('Failed to check existing content:', error.message);
    }

    // Look for test SCAP file
    const scapFile = path.join(__dirname, '../tests/ssg-ubuntu2204-ds.xml');
    if (!fs.existsSync(scapFile)) {
        console.log('  ! No test SCAP file found, skipping upload');
        return;
    }

    const formData = new FormData();
    formData.append('file', fs.createReadStream(scapFile));
    formData.append('title', 'Ubuntu 22.04 Security Guide');

    try {
        await axios.post(`${API_URL}/api/scap-content/upload`, formData, {
            headers: {
                ...formData.getHeaders(),
                'Authorization': `Bearer ${token}`
            }
        });
        console.log('  ✓ SCAP content uploaded successfully');
    } catch (error) {
        console.error('  ✗ Failed to upload SCAP content:', error.response?.data || error.message);
    }
}

async function setupTestData() {
    console.log('=== Setting up test data for E2E testing ===\n');
    
    try {
        // Get auth token
        console.log('Authenticating...');
        const token = await getAuthToken();
        console.log('✓ Authentication successful\n');

        // Create test hosts
        await createTestHosts(token);

        // Upload SCAP content
        await uploadTestScapContent(token);

        console.log('\n=== Test data setup complete ===');
    } catch (error) {
        console.error('\n✗ Setup failed:', error.message);
        process.exit(1);
    }
}

// Run setup if called directly
if (require.main === module) {
    setupTestData();
}

module.exports = { setupTestData };