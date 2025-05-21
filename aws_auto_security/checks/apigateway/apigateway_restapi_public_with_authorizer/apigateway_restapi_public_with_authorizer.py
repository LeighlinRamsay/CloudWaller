#!/usr/bin/env python3
"""
Plugin ID: apigateway_restapi_public_with_authorizer
Flags PUBLIC REST APIs missing authorizers.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("apigateway")

    def run(self):
        findings = []
        for page in self.client.get_paginator("get_rest_apis").paginate():
            for api in page.get("items", []):
                api_id = api["id"]
                try:
                    cfg = self.client.get_rest_api(restApiId=api_id)["endpointConfiguration"]
                    types = cfg.get("types", [])
                    if "PRIVATE" not in types:
                        auths = self.client.get_authorizers(restApiId=api_id).get("items", [])
                        if not auths:
                            findings.append((api_id, "Public API missing authorizer"))
                except ClientError as e:
                    findings.append((api_id, f"Error checking authorizers: {e}"))
        return findings
