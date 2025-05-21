#!/usr/bin/env python3
"""
Plugin ID: apigateway_restapi_authorizers_enabled
Flags REST APIs with no authorizers configured.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("apigateway")

    def run(self):
        findings = []
        for page in self.client.get_paginator("get_rest_apis").paginate():
            for api in page.get("items", []):
                rid = api["id"]
                auths = self.client.get_authorizers(restApiId=rid).get("items", [])
                if not auths:
                    findings.append((rid, "No authorizers"))
        return findings
