#!/usr/bin/env python3
"""
Plugin ID: acm_certificates_transparency_logs_enabled
Checks that CT logging is enabled on each certificate.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("acm")

    def run(self):
        findings = []
        paginator = self.client.get_paginator("list_certificates")
        for page in paginator.paginate(CertificateStatuses=["ISSUED"]):
            for cert in page.get("CertificateSummaryList", []):
                arn = cert["CertificateArn"]
                opts = self.client.list_tags_for_certificate(CertificateArn=arn).get("Tags", [])
                ct = next((t for t in opts if t["Key"]=="CertificateTransparencyLoggingPreference"), None)
                if not ct or ct["Value"]!="ENABLED":
                    findings.append((arn, "CT logging not enabled"))
        return findings
