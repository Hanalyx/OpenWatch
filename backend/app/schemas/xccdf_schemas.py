#!/usr/bin/env python3
"""
Pydantic schemas for XCCDF generation API endpoints
"""

from pydantic import BaseModel, Field
from typing import Dict, List, Optional


class XCCDFBenchmarkRequest(BaseModel):
    """Request schema for XCCDF Benchmark generation"""

    benchmark_id: str = Field(
        ..., description="Unique benchmark identifier (e.g., 'openwatch-nist-800-53r5')"
    )
    title: str = Field(..., description="Human-readable benchmark title")
    description: str = Field(..., description="Detailed description of the benchmark")
    version: str = Field(..., description="Benchmark version string (e.g., '1.0.0')")
    framework: Optional[str] = Field(
        None,
        description="Framework to filter by (nist, cis, stig, pci_dss, iso27001, hipaa)",
    )
    framework_version: Optional[str] = Field(
        None, description="Specific framework version (e.g., '800-53r5', 'v2.0.0')"
    )
    rule_filter: Optional[Dict] = Field(
        None, description="Additional MongoDB query filter for rules"
    )

    class Config:
        schema_extra = {
            "example": {
                "benchmark_id": "openwatch-nist-800-53r5",
                "title": "NIST SP 800-53 Revision 5 Security Controls",
                "description": "NIST Special Publication 800-53 Revision 5 security and privacy controls for information systems and organizations",
                "version": "1.0.0",
                "framework": "nist",
                "framework_version": "800-53r5",
            }
        }


class XCCDFBenchmarkResponse(BaseModel):
    """Response schema for XCCDF Benchmark generation"""

    benchmark_xml: str = Field(..., description="Generated XCCDF Benchmark XML content")
    rules_count: int = Field(..., description="Number of rules included in benchmark")
    variables_count: int = Field(..., description="Number of XCCDF variables defined")
    profiles_count: int = Field(..., description="Number of profiles created")
    generated_at: str = Field(..., description="ISO 8601 timestamp of generation")


class XCCDFTailoringRequest(BaseModel):
    """Request schema for XCCDF Tailoring file generation"""

    tailoring_id: str = Field(..., description="Unique tailoring identifier")
    benchmark_href: str = Field(
        ..., description="Reference to benchmark file (path or URL)"
    )
    benchmark_version: str = Field(
        ..., description="Version of benchmark being tailored"
    )
    profile_id: str = Field(..., description="Base profile to customize")
    variable_overrides: Dict[str, str] = Field(
        ..., description="Variable ID to custom value mappings"
    )
    title: Optional[str] = Field(None, description="Custom title for tailored profile")
    description: Optional[str] = Field(
        None, description="Description of customizations"
    )

    class Config:
        schema_extra = {
            "example": {
                "tailoring_id": "custom_tailoring_production",
                "benchmark_href": "openwatch-nist-800-53r5.xml",
                "benchmark_version": "1.0.0",
                "profile_id": "nist_800_53_r5",
                "variable_overrides": {
                    "var_accounts_tmout": "600",
                    "login_banner_text": "Authorized Access Only - Production Environment",
                },
                "title": "Production Environment Customization",
                "description": "Custom variable values for production systems",
            }
        }


class XCCDFTailoringResponse(BaseModel):
    """Response schema for XCCDF Tailoring generation"""

    tailoring_xml: str = Field(..., description="Generated XCCDF Tailoring XML content")
    variables_overridden: int = Field(..., description="Number of variables customized")
    generated_at: str = Field(..., description="ISO 8601 timestamp of generation")


class XCCDFValidationRequest(BaseModel):
    """Request schema for XCCDF validation"""

    xccdf_content: str = Field(..., description="XCCDF XML content to validate")
    xccdf_type: str = Field(
        ..., description="Type of XCCDF document (benchmark, tailoring)"
    )


class XCCDFValidationResponse(BaseModel):
    """Response schema for XCCDF validation"""

    valid: bool = Field(..., description="Whether the XCCDF is valid")
    errors: List[str] = Field(
        default_factory=list, description="Validation errors if any"
    )
    warnings: List[str] = Field(
        default_factory=list, description="Validation warnings if any"
    )
