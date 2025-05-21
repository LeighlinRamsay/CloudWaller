#!/usr/bin/env python3
"""
Plugin ID: apigatewayv2_api_access_logging_enabled
Checks that API Gateway V2 stages have access logging configured.
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
                    stages = self.client.get_stages(ApiId=api_id).get("Items", [])
                    for st in stages:
                        als = st.get("AccessLogSettings", {})
                        if not als.get("DestinationArn"):
                            findings.append((f"{api_id}:{st['StageName']}", "Access logging not enabled"))
                except ClientError as e:
                    findings.append((api_id, f"Error fetching stages: {e}"))
        return findings
