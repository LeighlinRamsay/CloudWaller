# File: checks/cloud_checks/cloudtrail/cloudtrail.py
#!/usr/bin/env python3
"""
Plugin ID: cloudtrail
Description: Check that CloudTrail is enabled and configured as a multi-region trail.
"""

from botocore.exceptions import ClientError
import boto3

class Plugin:
    def __init__(self, session):
        # boto3 Session passed as session; we need a CloudTrail client
        self.ct = session.client('cloudtrail')

    def run(self):
        """
        Verifies that at least one CloudTrail exists and is multi-region.
        Returns a list of (resource_id, issue_description) tuples.
        """
        findings = []
        try:
            resp = self.ct.describe_trails(includeShadowTrails=False)
            trails = resp.get('trailList', [])
            is_multi = any(t.get('IsMultiRegionTrail') for t in trails)
            if not trails or not is_multi:
                findings.append(('CloudTrail', 'CloudTrail is disabled or not multi-region'))
        except ClientError as e:
            findings.append(('CloudTrail', f'Error checking CloudTrail: {e}'))
        return findings
