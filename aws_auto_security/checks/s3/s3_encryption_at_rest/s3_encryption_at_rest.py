# File: checks/s3/s3_encryption_at_rest/s3_encryption_at_rest.py

#!/usr/bin/env python3
"""
Plugin ID: s3_encryption_at_rest
Description: S3 bucket security check for server-side encryption at rest.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.s3 = session.client('s3')

    def run(self):
        """
        Scan all buckets for default SSE configuration (SSE-S3 or SSE-KMS).
        Returns a list of (bucket_name, issue_description) tuples.
        """
        findings = []
        buckets = self.s3.list_buckets().get('Buckets', [])
        for b in buckets:
            name = b['Name']
            try:
                enc = self.s3.get_bucket_encryption(Bucket=name)['ServerSideEncryptionConfiguration']
                rules = enc.get('Rules', [])
                if not any(r.get('ApplyServerSideEncryptionByDefault') for r in rules):
                    findings.append((name, 'Bucket has no default SSE config'))
            except ClientError:
                findings.append((name, 'Bucket has no encryption configuration'))
        return findings
