# File: checks/s3/s3_missing_versioning/s3_missing_versioning.py

#!/usr/bin/env python3
"""
Plugin ID: s3_missing_versioning
Description: S3 bucket security check for versioning configuration.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.s3 = session.client('s3')

    def run(self):
        """
        Scan all buckets to ensure versioning is enabled.
        Returns a list of (bucket_name, issue_description) tuples.
        """
        findings = []
        buckets = self.s3.list_buckets().get('Buckets', [])
        for b in buckets:
            name = b['Name']
            try:
                ver = self.s3.get_bucket_versioning(Bucket=name)
                if ver.get('Status') != 'Enabled':
                    findings.append((name, 'Bucket versioning is not enabled'))
            except ClientError:
                continue
        return findings
