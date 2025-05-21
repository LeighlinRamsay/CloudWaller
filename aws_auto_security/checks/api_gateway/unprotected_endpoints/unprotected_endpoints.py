# File: checks/api_gateway/unprotected_endpoints/unprotected_endpoints.py
#!/usr/bin/env python3
"""
Plugin ID: api_unprotected_endpoints
Description: Detect API Gateway methods with no authorization (authType=NONE, apiKeyRequired=False).
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.apigw = session.client('apigateway')

    def run(self):
        findings = []
        # List all REST APIs
        paginator = self.apigw.get_paginator('get_rest_apis')
        for page in paginator.paginate():
            for api in page.get('items', []):
                api_id = api['id']
                try:
                    # Get all resources for this API
                    resps = self.apigw.get_resources(restApiId=api_id, embed=['methods'])
                    for res in resps.get('items', []):
                        for method, conf in res.get('resourceMethods', {}).items():
                            # fetch details only if method exists
                            m = self.apigw.get_method(
                                restApiId=api_id,
                                resourceId=res['id'],
                                httpMethod=method
                            )
                            auth = m.get('authorizationType', 'NONE')
                            key_req = m.get('apiKeyRequired', False)
                            if auth == 'NONE' and not key_req:
                                findings.append((
                                    f"{api_id}:{res['path']}.{method}",
                                    "Method allows anonymous (no auth, no API key)"
                                ))
                except ClientError:
                    continue
        return findings
