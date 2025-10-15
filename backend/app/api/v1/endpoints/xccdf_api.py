#!/usr/bin/env python3
"""
XCCDF Generation API Endpoints

Provides REST API for generating XCCDF benchmarks and tailoring files
from MongoDB compliance rules.
"""

from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorClient
from datetime import datetime, timezone
from typing import Dict
import logging

from ....schemas.xccdf_schemas import (
    XCCDFBenchmarkRequest,
    XCCDFBenchmarkResponse,
    XCCDFTailoringRequest,
    XCCDFTailoringResponse
)
from ....services.xccdf_generator_service import XCCDFGeneratorService
from ....services.mongo_integration_service import get_mongo_service
from ....auth import get_current_user

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/generate-benchmark", response_model=XCCDFBenchmarkResponse)
async def generate_benchmark(
    request: XCCDFBenchmarkRequest,
    mongo_service = Depends(get_mongo_service),
    current_user: Dict = Depends(get_current_user)
):
    """
    Generate XCCDF Benchmark XML from MongoDB rules
    
    Creates a compliant XCCDF 1.2 Benchmark with:
    - Rules filtered by framework/version
    - XCCDF Value elements for variables
    - Profiles for framework compliance
    - Groups for categorization
    
    The generated benchmark can be used with oscap for scanning.
    """
    try:
        db = mongo_service.mongo_manager.database

        logger.info(
            f"User {current_user.get('username')} generating benchmark: {request.benchmark_id}"
        )

        # Create generator service
        generator = XCCDFGeneratorService(db)
        
        # Generate benchmark XML
        benchmark_xml = await generator.generate_benchmark(
            benchmark_id=request.benchmark_id,
            title=request.title,
            description=request.description,
            version=request.version,
            framework=request.framework,
            framework_version=request.framework_version,
            rule_filter=request.rule_filter
        )
        
        # Count statistics from generated XML
        # (In production, you'd parse the XML to get these counts)
        # For now, query MongoDB separately
        query = {"is_latest": True}
        if request.rule_filter:
            query.update(request.rule_filter)
        if request.framework and request.framework_version:
            query[f"frameworks.{request.framework}.{request.framework_version}"] = {"$exists": True}
        
        rules_count = await db.compliance_rules.count_documents(query)
        
        # Count unique variables
        rules = await db.compliance_rules.find(query).to_list(length=None)
        all_vars = set()
        for rule in rules:
            if rule.get('xccdf_variables'):
                all_vars.update(rule['xccdf_variables'].keys())
        variables_count = len(all_vars)
        
        # Count profiles (framework versions found)
        frameworks_found = set()
        for rule in rules:
            for fw, versions in rule.get('frameworks', {}).items():
                for version in versions.keys():
                    frameworks_found.add((fw, version))
        profiles_count = len(frameworks_found)
        
        return XCCDFBenchmarkResponse(
            benchmark_xml=benchmark_xml,
            rules_count=rules_count,
            variables_count=variables_count,
            profiles_count=profiles_count,
            generated_at=datetime.now(timezone.utc).isoformat()
        )
        
    except Exception as e:
        logger.error(f"Failed to generate benchmark: {e}")
        raise HTTPException(status_code=500, detail=f"Benchmark generation failed: {str(e)}")


@router.post("/generate-tailoring", response_model=XCCDFTailoringResponse)
async def generate_tailoring(
    request: XCCDFTailoringRequest,
    mongo_service = Depends(get_mongo_service),
    current_user: Dict = Depends(get_current_user)
):
    """
    Generate XCCDF Tailoring file for variable customization
    
    Tailoring files allow users to override XCCDF variable values
    without modifying the original benchmark. This enables:
    - Environment-specific configurations (dev, staging, prod)
    - Organization-specific policies
    - Temporary exceptions
    
    The tailoring file is passed to oscap with --tailoring-file flag.
    """
    try:
        db = mongo_service.mongo_manager.database

        logger.info(
            f"User {current_user.get('username')} generating tailoring: {request.tailoring_id}"
        )

        # Create generator service
        generator = XCCDFGeneratorService(db)
        
        # Generate tailoring XML
        tailoring_xml = await generator.generate_tailoring(
            tailoring_id=request.tailoring_id,
            benchmark_href=request.benchmark_href,
            benchmark_version=request.benchmark_version,
            profile_id=request.profile_id,
            variable_overrides=request.variable_overrides,
            title=request.title,
            description=request.description
        )
        
        return XCCDFTailoringResponse(
            tailoring_xml=tailoring_xml,
            variables_overridden=len(request.variable_overrides),
            generated_at=datetime.now(timezone.utc).isoformat()
        )
        
    except Exception as e:
        logger.error(f"Failed to generate tailoring: {e}")
        raise HTTPException(status_code=500, detail=f"Tailoring generation failed: {str(e)}")


@router.get("/frameworks")
async def list_frameworks(
    mongo_service = Depends(get_mongo_service),
    current_user: Dict = Depends(get_current_user)
):
    """
    List available frameworks and their versions
    
    Returns all frameworks that have rules in the database,
    useful for populating UI dropdowns when generating benchmarks.
    """
    try:
        db = mongo_service.mongo_manager.database

        # Aggregate frameworks from all latest rules
        pipeline = [
            {"$match": {"is_latest": True}},
            {"$project": {"frameworks": 1}},
            {"$unwind": "$frameworks"},
        ]
        
        frameworks = {}
        async for doc in db.compliance_rules.aggregate(pipeline):
            for fw, versions in doc.get('frameworks', {}).items():
                if fw not in frameworks:
                    frameworks[fw] = set()
                frameworks[fw].update(versions.keys())
        
        # Convert sets to sorted lists
        frameworks = {
            fw: sorted(list(versions))
            for fw, versions in frameworks.items()
        }
        
        return {
            "frameworks": frameworks,
            "total_frameworks": len(frameworks)
        }
        
    except Exception as e:
        logger.error(f"Failed to list frameworks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/variables")
async def list_variables(
    framework: str = None,
    framework_version: str = None,
    mongo_service = Depends(get_mongo_service),
    current_user: Dict = Depends(get_current_user)
):
    """
    List all XCCDF variables available for customization
    
    Optionally filter by framework/version to see only variables
    relevant to a specific benchmark.
    """
    try:
        db = mongo_service.mongo_manager.database

        # Build query
        query = {"is_latest": True, "xccdf_variables": {"$exists": True, "$ne": None}}
        
        if framework and framework_version:
            query[f"frameworks.{framework}.{framework_version}"] = {"$exists": True}
        
        # Collect all unique variables
        all_variables = {}
        async for rule in db.compliance_rules.find(query):
            if rule.get('xccdf_variables'):
                for var_id, var_def in rule['xccdf_variables'].items():
                    if var_id not in all_variables:
                        all_variables[var_id] = var_def
        
        return {
            "variables": all_variables,
            "total_variables": len(all_variables)
        }
        
    except Exception as e:
        logger.error(f"Failed to list variables: {e}")
        raise HTTPException(status_code=500, detail=str(e))
