# File: checks/lambda/no_timeout/no_timeout.py
#!/usr/bin/env python3
"""
Plugin ID: lambda_no_timeout
Description: Detect Lambda functions with no or infinite timeout (Timeout at max limit).
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.lambda_client = session.client('lambda')

    def run(self):
        findings = []
        paginator = self.lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for fn in page.get('Functions', []):
                name = fn['FunctionName']
                try:
                    cfg = self.lambda_client.get_function_configuration(FunctionName=name)
                    timeout = cfg.get('Timeout', 0)
                    # AWS max timeout is 900 seconds; treat that as 'infinite' or not set
                    if timeout >= 900:
                        findings.append((name, f"Function timeout is {timeout}s (max limit)"))
                except ClientError:
                    continue
        return findings
