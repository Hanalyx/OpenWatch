#!/usr/bin/env python3
"""
Simple HTTP server to serve platform and framework statistics 
for testing while main backend server doesn't reload
"""
import asyncio
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, '/home/rracine/hanalyx/openwatch/backend')

from app.api.v1.endpoints.compliance_rules_api import get_platform_statistics_from_files, get_framework_statistics_from_files

async def get_all_rules_from_files(query_params):
    """Get paginated rules from converted files"""
    import json
    from pathlib import Path
    
    # Parse query parameters
    offset = int(query_params.get('offset', ['0'])[0])
    limit = int(query_params.get('limit', ['25'])[0])
    search = query_params.get('search', [''])[0]
    framework = query_params.get('framework', [''])[0]
    severity = query_params.get('severity', [''])[0]
    category = query_params.get('category', [''])[0]
    platform = query_params.get('platform', [''])[0]
    
    # Path to converted rules
    rules_path = Path("/home/rracine/hanalyx/openwatch/data/compliance_rules_converted")
    
    if not rules_path.exists():
        return {
            "rules": [],
            "total_count": 0,
            "offset": offset,
            "limit": limit,
            "has_next": False,
            "has_prev": False,
            "filters_applied": {
                "framework": framework,
                "severity": severity,
                "category": category,
                "platform": platform,
                "search": search
            }
        }
    
    # Load and filter all rules
    all_rules = []
    
    for json_file in rules_path.glob("*.json"):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                rule = json.load(f)
            
            # Apply filters
            if search and search.lower() not in (
                rule.get('metadata', {}).get('name', '').lower() + 
                rule.get('metadata', {}).get('description', '').lower() + 
                rule.get('rule_id', '').lower()
            ):
                continue
                
            if framework and framework not in rule.get('frameworks', {}):
                continue
                
            if severity and rule.get('severity') != severity:
                continue
                
            if category and rule.get('category') != category:
                continue
                
            if platform and platform not in rule.get('platform_implementations', {}):
                continue
            
            # Format rule for frontend
            formatted_rule = {
                "rule_id": rule.get("rule_id", ""),
                "scap_rule_id": rule.get("scap_rule_id", ""),
                "metadata": rule.get("metadata", {}),
                "severity": rule.get("severity", "medium"),
                "category": rule.get("category", "system"),
                "tags": rule.get("tags", []),
                "frameworks": rule.get("frameworks", {}),
                "platform_implementations": rule.get("platform_implementations", {}),
                "dependencies": rule.get("dependencies", {"requires": [], "conflicts": [], "related": []}),
                "created_at": rule.get("imported_at", "2025-01-01T00:00:00Z"),
                "updated_at": rule.get("updated_at", "2025-01-01T00:00:00Z")
            }
            
            all_rules.append(formatted_rule)
            
        except Exception as e:
            continue
    
    # Calculate pagination
    total_count = len(all_rules)
    start_idx = offset
    end_idx = offset + limit
    paginated_rules = all_rules[start_idx:end_idx]
    
    return {
        "rules": paginated_rules,
        "total_count": total_count,
        "offset": offset,
        "limit": limit,
        "has_next": end_idx < total_count,
        "has_prev": offset > 0,
        "filters_applied": {
            "framework": framework or None,
            "severity": severity or None,
            "category": category or None,
            "platform": platform or None,
            "search": search or None
        }
    }

class StatisticsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        
        # Handle CORS
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        try:
            if parsed_url.path == '/platform-stats':
                # Platform statistics
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(get_platform_statistics_from_files())
                response = {
                    "success": True,
                    "data": result,
                    "message": f"Retrieved statistics for {result.get('total_platforms', 0)} platforms (from converted files)"
                }
                
            elif parsed_url.path == '/framework-stats':
                # Framework statistics  
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(get_framework_statistics_from_files())
                response = {
                    "success": True,
                    "data": result,
                    "message": f"Retrieved statistics for {result.get('total_frameworks', 0)} frameworks (from converted files)"
                }
                
            elif parsed_url.path == '/all-rules':
                # All rules data with pagination
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(get_all_rules_from_files(query_params))
                response = {
                    "success": True,
                    "data": result,
                    "message": f"Retrieved {len(result.get('rules', []))} compliance rules (from converted files)"
                }
                
            else:
                response = {
                    "success": False,
                    "message": "Available endpoints: /platform-stats, /framework-stats, /all-rules"
                }
                
        except Exception as e:
            response = {
                "success": False,
                "message": f"Error: {str(e)}"
            }
            
        self.wfile.write(json.dumps(response, indent=2).encode('utf-8'))
    
    def do_OPTIONS(self):
        # Handle preflight CORS requests
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

if __name__ == '__main__':
    print("Starting statistics server on port 8002...")
    print("Endpoints:")
    print("  http://localhost:8002/platform-stats")
    print("  http://localhost:8002/framework-stats")
    
    server = HTTPServer(('localhost', 8002), StatisticsHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()