"""
Unit tests for XCCDFVariable model

Tests validation logic for XCCDF variables that enable scan-time customization.
"""

import pytest
from pydantic import ValidationError

from app.models.mongo_models import XCCDFVariable


class TestXCCDFVariableBasic:
    """Test basic XCCDFVariable creation and validation"""

    def test_create_string_variable(self):
        """Test creating a string variable"""
        var = XCCDFVariable(
            id="login_banner_text",
            title="Login Banner Text",
            description="Text to display in /etc/issue",
            type="string",
            default_value="Authorized Users Only",
            interactive=True,
            sensitive=False,
        )

        assert var.id == "login_banner_text"
        assert var.type == "string"
        assert var.default_value == "Authorized Users Only"
        assert var.interactive is True
        assert var.sensitive is False

    def test_create_number_variable(self):
        """Test creating a numeric variable"""
        var = XCCDFVariable(
            id="var_accounts_tmout",
            title="Account Inactivity Timeout",
            description="Timeout in seconds",
            type="number",
            default_value="600",
            interactive=True,
        )

        assert var.id == "var_accounts_tmout"
        assert var.type == "number"
        assert var.default_value == "600"

    def test_create_boolean_variable(self):
        """Test creating a boolean variable"""
        var = XCCDFVariable(id="enable_selinux", title="Enable SELinux", type="boolean", default_value="true")

        assert var.type == "boolean"
        assert var.default_value == "true"

    def test_sensitive_variable(self):
        """Test sensitive variable (passwords, keys)"""
        var = XCCDFVariable(
            id="grub2_bootloader_password", title="GRUB2 Password Hash", type="string", default_value="", sensitive=True
        )

        assert var.sensitive is True


class TestXCCDFVariableValidation:
    """Test XCCDFVariable validation logic"""

    def test_invalid_type(self):
        """Test that invalid types are rejected"""
        with pytest.raises(ValidationError) as exc_info:
            XCCDFVariable(id="test_var", title="Test", type="invalid_type", default_value="test")  # Invalid

        assert "Invalid type" in str(exc_info.value)

    def test_valid_types(self):
        """Test all valid types"""
        for var_type in ["string", "number", "boolean"]:
            var = XCCDFVariable(
                id=f"test_{var_type}", title=f"Test {var_type}", type=var_type, default_value="test_value"
            )
            assert var.type == var_type


class TestXCCDFVariableConstraints:
    """Test constraint validation"""

    def test_numeric_constraints_valid(self):
        """Test valid numeric constraints"""
        var = XCCDFVariable(
            id="var_accounts_tmout",
            title="Timeout",
            type="number",
            default_value="600",
            constraints={"min_value": 60, "max_value": 3600},
        )

        assert var.constraints["min_value"] == 60
        assert var.constraints["max_value"] == 3600

    def test_numeric_constraints_invalid_range(self):
        """Test that min > max is rejected"""
        with pytest.raises(ValidationError) as exc_info:
            XCCDFVariable(
                id="test_var",
                title="Test",
                type="number",
                default_value="100",
                constraints={"min_value": 100, "max_value": 50},  # Invalid: min > max
            )

        assert "min_value cannot be greater than max_value" in str(exc_info.value)

    def test_string_constraints_valid(self):
        """Test valid string constraints"""
        var = XCCDFVariable(
            id="login_banner",
            title="Banner",
            type="string",
            default_value="test",
            constraints={"min_length": 10, "max_length": 2000},
        )

        assert var.constraints["min_length"] == 10
        assert var.constraints["max_length"] == 2000

    def test_string_constraints_invalid_range(self):
        """Test that min_length > max_length is rejected"""
        with pytest.raises(ValidationError) as exc_info:
            XCCDFVariable(
                id="test_var",
                title="Test",
                type="string",
                default_value="test",
                constraints={"min_length": 100, "max_length": 50},  # Invalid
            )

        assert "min_length cannot be greater than max_length" in str(exc_info.value)

    def test_string_pattern_valid(self):
        """Test valid regex pattern"""
        var = XCCDFVariable(
            id="grub_password",
            title="GRUB Password",
            type="string",
            default_value="grub.pbkdf2.sha512.test",
            constraints={"pattern": "^grub\\.pbkdf2\\.sha512\\."},
        )

        assert "pattern" in var.constraints

    def test_string_pattern_invalid_regex(self):
        """Test invalid regex pattern is rejected"""
        with pytest.raises(ValidationError) as exc_info:
            XCCDFVariable(
                id="test_var",
                title="Test",
                type="string",
                default_value="test",
                constraints={"pattern": "^[invalid(regex"},  # Invalid regex
            )

        assert "Invalid regex pattern" in str(exc_info.value)

    def test_choices_constraint(self):
        """Test choices constraint (enum-like)"""
        var = XCCDFVariable(
            id="timeout_preset",
            title="Timeout Preset",
            type="number",
            default_value="600",
            constraints={"choices": ["300", "600", "900", "1800"]},
        )

        assert var.constraints["choices"] == ["300", "600", "900", "1800"]


class TestXCCDFVariableDefaults:
    """Test default values"""

    def test_interactive_default_true(self):
        """Test interactive defaults to True"""
        var = XCCDFVariable(id="test_var", title="Test", type="string", default_value="test")

        assert var.interactive is True

    def test_sensitive_default_false(self):
        """Test sensitive defaults to False"""
        var = XCCDFVariable(id="test_var", title="Test", type="string", default_value="test")

        assert var.sensitive is False

    def test_description_optional(self):
        """Test description is optional"""
        var = XCCDFVariable(id="test_var", title="Test", type="string", default_value="test")

        assert var.description is None

    def test_constraints_optional(self):
        """Test constraints are optional"""
        var = XCCDFVariable(id="test_var", title="Test", type="string", default_value="test")

        assert var.constraints is None


class TestXCCDFVariableSerialization:
    """Test model serialization for MongoDB storage"""

    def test_model_dump_excludes_none(self):
        """Test that None values are excluded when serializing"""
        var = XCCDFVariable(
            id="test_var",
            title="Test",
            type="string",
            default_value="test",
            # description=None (not provided)
            # constraints=None (not provided)
        )

        data = var.model_dump()

        assert "description" not in data  # Should be excluded
        assert "constraints" not in data  # Should be excluded
        assert "id" in data
        assert "title" in data
        assert "type" in data

    def test_model_dump_includes_provided_values(self):
        """Test that explicitly provided values are included"""
        var = XCCDFVariable(
            id="test_var",
            title="Test",
            description="Test description",
            type="string",
            default_value="test",
            constraints={"min_length": 5},
        )

        data = var.model_dump()

        assert "description" in data
        assert "constraints" in data
        assert data["description"] == "Test description"
        assert data["constraints"]["min_length"] == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
