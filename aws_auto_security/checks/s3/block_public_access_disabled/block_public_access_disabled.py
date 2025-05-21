# File: checks/s3/block_public_access_disabled/block_public_access_disabled.py

#!/usr/bin/env python3
"""
Plugin ID: block_public_access_disabled
Description: S3 bucket security check for Public Access Block configuration.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.s3 = session.client('s3')

    def run(self):
        """
        Scan all buckets to ensure Public Access Block is fully enabled.
        Returns a list of (bucket_name, issue_description) tuples.
        """
        findings = []
        buckets = self.s3.list_buckets().get('Buckets', [])
        for b in buckets:
            name = b['Name']
            try:
                cfg = self.s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
                if not all(cfg.get(opt, False) for opt in [
                    'BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'
                ]):
                    findings.append((name, 'Public Access Block incomplete or missing'))
            except self.s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                findings.append((name, 'No Public Access Block configuration'))
            except ClientError:
                continue
        return findings
