"""
Tests for Group Compliance Scanning
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from datetime import datetime
import json

from backend.app.main import app
from backend.app.schemas.group_compliance import (
    GroupComplianceScanRequest,
    ComplianceFramework,
    RemediationMode
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mock_user():
    return {
        "user_id": 1,
        "username": "test_user",
        "role": "admin",
        "permissions": ["scans:create", "reports:view"]
    }


@pytest.fixture
def mock_db():
    return MagicMock()


class TestGroupComplianceAPI:
    """Test group compliance scanning API endpoints"""

    @patch('backend.app.routes.group_compliance.get_db')
    @patch('backend.app.routes.group_compliance.get_current_user')
    def test_start_compliance_scan_success(self, mock_get_user, mock_get_db, client, mock_user, mock_db):
        """Test successful compliance scan initiation"""
        mock_get_user.return_value = mock_user
        mock_get_db.return_value = mock_db
        
        # Mock database responses
        mock_group = MagicMock()
        mock_group.id = 1
        mock_group.name = "Test Group"
        mock_group.scap_content_id = 1
        mock_group.default_profile_id = "stig_profile"
        mock_group.compliance_framework = "disa-stig"
        
        mock_db.query.return_value.filter.return_value.first.return_value = mock_group
        
        # Mock hosts query
        mock_hosts = [
            MagicMock(id="host1", hostname="server1", ip_address="10.0.0.1"),
            MagicMock(id="host2", hostname="server2", ip_address="10.0.0.2")
        ]
        mock_db.execute.return_value.fetchall.return_value = mock_hosts
        
        # Mock SCAP content
        mock_scap = MagicMock()
        mock_scap.id = 1
        mock_scap.title = "RHEL 8 STIG"
        mock_db.query.return_value.filter.return_value.first.return_value = mock_scap
        
        scan_request = {
            "scap_content_id": 1,
            "profile_id": "stig_profile",
            "compliance_framework": "disa-stig",
            "remediation_mode": "report_only",
            "email_notifications": True,
            "generate_reports": True,
            "concurrent_scans": 5
        }
        
        response = client.post("/api/group-compliance/1/scan", json=scan_request)
        
        assert response.status_code == 200
        data = response.json()
        assert "session_id" in data
        assert data["group_id"] == 1
        assert data["group_name"] == "Test Group"
        assert data["total_hosts"] == 2
        assert data["compliance_framework"] == "disa-stig"

    def test_compliance_scan_request_validation(self):
        """Test compliance scan request validation"""
        # Valid request
        valid_request = GroupComplianceScanRequest(
            scap_content_id=1,
            profile_id="test_profile",
            compliance_framework=ComplianceFramework.DISA_STIG,
            remediation_mode=RemediationMode.REPORT_ONLY
        )
        assert valid_request.scap_content_id == 1
        assert valid_request.compliance_framework == ComplianceFramework.DISA_STIG
        
        # Test enum validation
        with pytest.raises(ValueError):
            GroupComplianceScanRequest(
                compliance_framework="invalid_framework"
            )

    @patch('backend.app.routes.group_compliance.get_db')
    @patch('backend.app.routes.group_compliance.get_current_user')
    def test_get_compliance_report(self, mock_get_user, mock_get_db, client, mock_user, mock_db):
        """Test compliance report generation"""
        mock_get_user.return_value = mock_user
        mock_get_db.return_value = mock_db
        
        # Mock group
        mock_group = MagicMock()
        mock_group.id = 1
        mock_group.name = "Test Group"
        mock_db.query.return_value.filter.return_value.first.return_value = mock_group
        
        # Mock compliance data
        mock_compliance_data = [
            MagicMock(
                host_id="host1",
                hostname="server1",
                ip_address="10.0.0.1",
                os_family="rhel",
                total_rules=100,
                passed_rules=85,
                failed_rules=15,
                score=85.0,
                severity_high=2,
                severity_medium=5,
                severity_low=8,
                compliance_framework="disa-stig",
                completed_at=datetime.utcnow()
            )
        ]
        mock_db.execute.return_value.fetchall.return_value = mock_compliance_data
        
        response = client.get("/api/group-compliance/1/report")
        
        assert response.status_code == 200
        data = response.json()
        assert data["group_id"] == 1
        assert data["group_name"] == "Test Group"
        assert data["total_hosts"] == 1
        assert "overall_compliance_score" in data
        assert "host_compliance_summary" in data

    @patch('backend.app.routes.group_compliance.get_db')
    @patch('backend.app.routes.group_compliance.get_current_user')
    def test_schedule_compliance_scan(self, mock_get_user, mock_get_db, client, mock_user, mock_db):
        """Test compliance scan scheduling"""
        mock_get_user.return_value = mock_user
        mock_get_db.return_value = mock_db
        
        # Mock group
        mock_group = MagicMock()
        mock_group.id = 1
        mock_db.query.return_value.filter.return_value.first.return_value = mock_group
        
        schedule_request = {
            "enabled": True,
            "cron_expression": "0 2 * * 0",  # Weekly Sunday 2 AM
            "scap_content_id": 1,
            "profile_id": "stig_profile",
            "compliance_framework": "disa-stig",
            "email_notifications": True
        }
        
        response = client.post("/api/group-compliance/1/schedule", json=schedule_request)
        
        assert response.status_code == 200
        data = response.json()
        assert "scheduled successfully" in data["message"]

    def test_compliance_framework_enum(self):
        """Test compliance framework enumeration"""
        frameworks = [
            ComplianceFramework.DISA_STIG,
            ComplianceFramework.CIS,
            ComplianceFramework.NIST_800_53,
            ComplianceFramework.PCI_DSS,
            ComplianceFramework.HIPAA
        ]
        
        for framework in frameworks:
            assert framework.value in [
                "disa-stig", "cis", "nist-800-53", "pci-dss", "hipaa"
            ]

    @patch('backend.app.routes.group_compliance.get_db')
    @patch('backend.app.routes.group_compliance.get_current_user')
    def test_missing_group_error(self, mock_get_user, mock_get_db, client, mock_user, mock_db):
        """Test error handling for missing group"""
        mock_get_user.return_value = mock_user
        mock_get_db.return_value = mock_db
        
        # Mock group not found
        mock_db.query.return_value.filter.return_value.first.return_value = None
        
        scan_request = {
            "scap_content_id": 1,
            "remediation_mode": "report_only"
        }
        
        response = client.post("/api/group-compliance/999/scan", json=scan_request)
        
        assert response.status_code == 404
        assert "not found" in response.json()["detail"]

    @patch('backend.app.routes.group_compliance.get_db')
    @patch('backend.app.routes.group_compliance.get_current_user')
    def test_no_hosts_error(self, mock_get_user, mock_get_db, client, mock_user, mock_db):
        """Test error handling for groups with no active hosts"""
        mock_get_user.return_value = mock_user
        mock_get_db.return_value = mock_db
        
        # Mock group exists
        mock_group = MagicMock()
        mock_group.id = 1
        mock_db.query.return_value.filter.return_value.first.return_value = mock_group
        
        # Mock no hosts
        mock_db.execute.return_value.fetchall.return_value = []
        
        scan_request = {
            "scap_content_id": 1,
            "remediation_mode": "report_only"
        }
        
        response = client.post("/api/group-compliance/1/scan", json=scan_request)
        
        assert response.status_code == 400
        assert "No active hosts found" in response.json()["detail"]


class TestComplianceSchemas:
    """Test compliance scanning schemas"""

    def test_scan_request_defaults(self):
        """Test default values in scan request schema"""
        request = GroupComplianceScanRequest()
        
        assert request.remediation_mode == RemediationMode.REPORT_ONLY
        assert request.email_notifications == False
        assert request.generate_reports == True
        assert request.concurrent_scans == 5
        assert request.scan_timeout == 3600

    def test_scan_request_validation_limits(self):
        """Test validation limits for scan request"""
        # Test concurrent scans limits
        with pytest.raises(ValueError):
            GroupComplianceScanRequest(concurrent_scans=0)  # Below minimum
        
        with pytest.raises(ValueError):
            GroupComplianceScanRequest(concurrent_scans=25)  # Above maximum
        
        # Test timeout limits
        with pytest.raises(ValueError):
            GroupComplianceScanRequest(scan_timeout=100)  # Below minimum
        
        with pytest.raises(ValueError):
            GroupComplianceScanRequest(scan_timeout=10000)  # Above maximum

    def test_remediation_mode_enum(self):
        """Test remediation mode enumeration"""
        modes = [
            RemediationMode.NONE,
            RemediationMode.REPORT_ONLY,
            RemediationMode.AUTO_APPLY,
            RemediationMode.MANUAL_REVIEW
        ]
        
        for mode in modes:
            request = GroupComplianceScanRequest(remediation_mode=mode)
            assert request.remediation_mode == mode


if __name__ == "__main__":
    pytest.main([__file__, "-v"])