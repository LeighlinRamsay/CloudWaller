#!/usr/bin/env python3
"""
Plugin ID: acm_certificates_expiration_check
Flags certificates expiring within 30 days.
"""

from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("acm")

    def run(self):
        findings = []
        cutoff = datetime.now(timezone.utc) + timedelta(days=30)
        paginator = self.client.get_paginator("list_certificates")
        for page in paginator.paginate(CertificateStatuses=["ISSUED"]):
            for cert in page.get("CertificateSummaryList", []):
                arn = cert["CertificateArn"]
                info = self.client.describe_certificate(CertificateArn=arn)["Certificate"]
                exp = info["NotAfter"]
                if exp < cutoff:
                    findings.append((arn, f"Expires on {exp.isoformat()}"))
        return findings
