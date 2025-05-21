#!/usr/bin/env python3
"""
Plugin ID: ami_old_images
Flags AMIs older than a fixed cutoff (e.g. two years).
"""

from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client("ec2")

    def run(self):
        findings = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=730)
        for page in self.ec2.get_paginator("describe_images").paginate(Owners=['self']):
            for img in page.get("Images", []):
                created = datetime.fromisoformat(img['CreationDate'].replace('Z','+00:00'))
                if created < cutoff:
                    findings.append((img['ImageId'], f"Created on {img['CreationDate']}"))
        return findings
