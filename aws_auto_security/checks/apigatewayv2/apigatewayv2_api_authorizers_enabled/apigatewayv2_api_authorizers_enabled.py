#!/usr/bin/env python3
"""
Plugin ID: apigatewayv2_api_authorizers_enabled
Flags V2 APIs with no authorizers configured.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("apigatewayv2")

    def run(self):
        findings = []
        for page in self.client.get_paginator("get_apis").paginate():
            for api in page.get("Items", []):
                api_id = api["ApiId"]
                try:
                    auths = self.client.get_authorizers(ApiId=api_id).get("Items", [])
                    if not auths:
                        findings.append((api_id, "No authorizers"))
                except ClientError as e:
                    findings.append((api_id, f"Error listing authorizers: {e}"))
        return findings
