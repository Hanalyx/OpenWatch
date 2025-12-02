"""
MongoDB Integration Test API Endpoints
Provides endpoints for testing MongoDB functionality
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..services.mongo_integration_service import MongoIntegrationService, get_mongo_service

router = APIRouter()


class MongoHealthResponse(BaseModel):
    """Response model for MongoDB health check"""

    status: str
    message: str = None
    database: str = None
    collections: List[str] = None
    document_count: Dict[str, int] = None
    stats: Dict[str, int] = None


class MongoTestResponse(BaseModel):
    """Response model for MongoDB comprehensive test"""

    status: str
    tests: Dict[str, Any]
    errors: List[str] = []
    failed_tests: List[str] = []
    start_time: str
    end_time: str


@router.get("/health", response_model=MongoHealthResponse)
async def mongodb_health_check(
    service: MongoIntegrationService = Depends(get_mongo_service),
) -> MongoHealthResponse:
    """
    Check MongoDB connection health and basic statistics
    """
    try:
        health_data = await service.health_check()
        return MongoHealthResponse(**health_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MongoDB health check failed: {str(e)}")


@router.post("/run-integration-test", response_model=MongoTestResponse)
async def run_mongodb_integration_test(
    service: MongoIntegrationService = Depends(get_mongo_service),
) -> MongoTestResponse:
    """
    Run comprehensive MongoDB integration test suite

    This endpoint will:
    1. Test MongoDB connection and health
    2. Create test compliance rules with all relationships
    3. Test platform-based queries
    4. Test framework-based queries
    5. Test complex queries with joins
    6. Test index performance
    7. Clean up test data
    """
    try:
        test_results = await service.run_comprehensive_test()
        return MongoTestResponse(**test_results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MongoDB integration test failed: {str(e)}")


@router.get("/query/platform/{platform}/{version}")
async def query_rules_by_platform(
    platform: str,
    version: str,
    service: MongoIntegrationService = Depends(get_mongo_service),
) -> Dict[str, Any]:
    """
    Query compliance rules by platform and version

    Args:
        platform: Platform name (rhel, ubuntu, windows)
        version: Platform version (8, 9, 20.04, etc.)
    """
    try:
        rules = await service.query_rules_by_platform(platform, version)
        return {
            "platform": platform,
            "version": version,
            "rule_count": len(rules),
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "name": rule.metadata.get("name", ""),
                    "severity": rule.severity,
                    "category": rule.category,
                }
                for rule in rules
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Platform query failed: {str(e)}")


@router.get("/query/framework/{framework}/{version}")
async def query_rules_by_framework(
    framework: str,
    version: str,
    service: MongoIntegrationService = Depends(get_mongo_service),
) -> Dict[str, Any]:
    """
    Query compliance rules by framework and version

    Args:
        framework: Framework name (nist, cis, stig, etc.)
        version: Framework version (800-53r5, rhel8_v2.0.0, etc.)
    """
    try:
        rules = await service.query_rules_by_framework(framework, version)
        return {
            "framework": framework,
            "version": version,
            "rule_count": len(rules),
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "name": rule.metadata.get("name", ""),
                    "severity": rule.severity,
                    "framework_mappings": getattr(rule.frameworks, framework, {}).get(version, []),
                }
                for rule in rules
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Framework query failed: {str(e)}")


@router.get("/rule/{rule_id}/complete")
async def get_rule_with_intelligence(
    rule_id: str, service: MongoIntegrationService = Depends(get_mongo_service)
) -> Dict[str, Any]:
    """
    Get complete rule data including intelligence and remediation scripts

    Args:
        rule_id: OpenWatch rule identifier
    """
    try:
        result = await service.get_rule_with_intelligence(rule_id)
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])

        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Rule query failed: {str(e)}")


@router.delete("/test-data/cleanup")
async def cleanup_test_data(
    service: MongoIntegrationService = Depends(get_mongo_service),
) -> Dict[str, str]:
    """
    Clean up test data from MongoDB
    """
    try:
        await service.cleanup_test_data()
        return {"status": "success", "message": "Test data cleaned up successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cleanup failed: {str(e)}")


@router.get("/database/stats")
async def get_database_stats(
    service: MongoIntegrationService = Depends(get_mongo_service),
) -> Dict[str, Any]:
    """
    Get detailed MongoDB database statistics
    """
    try:
        health = await service.health_check()
        if health["status"] != "healthy":
            raise HTTPException(status_code=503, detail="Database not healthy")

        return {
            "status": "healthy",
            "database_name": health["database"],
            "collections": health["collections"],
            "document_counts": health["document_count"],
            "storage_stats": health["stats"],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stats query failed: {str(e)}")
