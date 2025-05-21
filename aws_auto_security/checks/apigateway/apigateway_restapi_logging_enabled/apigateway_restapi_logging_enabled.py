# File: checks/apigateway/apigateway_restapi_logging_enabled/apigateway_restapi_logging_enabled.py

#!/usr/bin/env python3
"""
Plugin ID: apigateway_restapi_logging_enabled
Description: Check if API Gateway Stage has logging enabled.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("apigateway")

    def run(self):
        findings = []
        try:
            pages = self.client.get_paginator("get_rest_apis").paginate()
        except ValueError:
            pages = [self.client.get_rest_apis()]
        for page in pages:
            for api in page.get("items", []):
                api_id = api.get("id")
                try:
                    stages = self.client.get_stages(restApiId=api_id).get("item", [])
                    for st in stages:
                        if not st.get("accessLogSettings"):
                            findings.append((f"{api_id}:{st.get('stageName')}", "Logging not enabled"))
                except ClientError:
                    continue
        return findings
