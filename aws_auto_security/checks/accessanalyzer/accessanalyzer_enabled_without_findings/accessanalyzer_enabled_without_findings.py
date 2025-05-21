#!/usr/bin/env python3
"""
Plugin ID: accessanalyzer_enabled_without_findings
Flags any analyzer that exists but has generated zero findings.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("accessanalyzer")

    def run(self):
        findings = []
        try:
            for analyzer in self.client.list_analyzers().get("analyzers", []):
                arn = analyzer["arn"]
                finds = self.client.list_findings(analyzerArn=arn).get("findings", [])
                if not finds:
                    findings.append((arn, "Analyzer has no findings"))
        except ClientError as e:
            findings.append(("AccessAnalyzer", f"Error checking findings: {e}"))
        return findings
