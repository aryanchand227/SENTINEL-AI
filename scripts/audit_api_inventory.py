"""
Inspect all registered API endpoints from app.openapi() and route objects.
"""

from __future__ import annotations

import json

from backend.app.main import app

openapi = app.openapi()
paths = openapi.get("paths", {})

endpoints = []
for path, methods_dict in paths.items():
    for method, details in methods_dict.items():
        if method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            continue

        # Check security requirement
        security = details.get("security", [])
        has_security = bool(security)

        endpoints.append(
            {
                "path": path,
                "method": method.upper(),
                "operation_id": details.get("operationId"),
                "summary": details.get("summary", ""),
                "description": details.get("description", ""),
                "tags": details.get("tags", []),
                "parameters": [p.get("name") for p in details.get("parameters", [])],
                "requires_auth": has_security,
                "responses": list(details.get("responses", {}).keys()),
            }
        )

print(f"Total API Endpoints registered in OpenAPI: {len(endpoints)}")
print(json.dumps(endpoints, indent=2))
