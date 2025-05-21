# File: checks/s3/s3_logging_disabled/s3_logging_disabled.py

#!/usr/bin/env python3
"""
Plugin ID: s3_logging_disabled
Description: S3 bucket security check for access logging configuration.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.s3 = session.client('s3')

    def run(self):
        """
        Scan all buckets to ensure access logging is enabled.
        Returns a list of (bucket_name, issue_description) tuples.
        """
        findings = []
        buckets = self.s3.list_buckets().get('Buckets', [])
        for b in buckets:
            name = b['Name']
            try:
                log = self.s3.get_bucket_logging(Bucket=name).get('LoggingEnabled')
                if not log:
                    findings.append((name, 'Bucket access logging is not enabled'))
            except ClientError:
                continue
        return findings
