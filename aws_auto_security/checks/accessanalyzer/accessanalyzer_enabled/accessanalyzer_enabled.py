#!/usr/bin/env python3
"""
Plugin ID: accessanalyzer_enabled
Checks whether IAM Access Analyzer has at least one analyzer in this account.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("accessanalyzer")

    def run(self):
        findings = []
        try:
            resp = self.client.list_analyzers()
            analyzers = resp.get("analyzers", [])
            if not analyzers:
                findings.append(("Account", "No Access Analyzer analyzers found"))
        except ClientError as e:
            findings.append(("AccessAnalyzer", f"Error listing analyzers: {e}"))
        return findings
