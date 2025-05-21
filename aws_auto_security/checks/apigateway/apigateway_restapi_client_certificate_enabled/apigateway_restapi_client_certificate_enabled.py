# File: checks/apigateway/apigateway_restapi_client_certificate_enabled/apigateway_restapi_client_certificate_enabled.py

#!/usr/bin/env python3
"""
Plugin ID: apigateway_restapi_client_certificate_enabled
Description: Check if API Gateway REST API has a client certificate configured.
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
                    rest = self.client.get_rest_api(restApiId=api_id)
                    if not rest.get("clientCertificateId"):
                        findings.append((api_id, "Client certificate not enabled"))
                except ClientError:
                    continue
        return findings
