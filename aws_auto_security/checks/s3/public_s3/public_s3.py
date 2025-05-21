# File: checks/s3/public_s3/public_s3.py

#!/usr/bin/env python3
"""
Plugin ID: public_s3
Description: S3 bucket security check for public ACL grants.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        # boto3 Session
        self.s3 = session.client('s3')

    def run(self):
        """
        Scan all buckets for ACL grants to AllUsers or AuthenticatedUsers.
        Returns a list of (bucket_name, issue_description) tuples.
        """
        findings = []
        buckets = self.s3.list_buckets().get('Buckets', [])
        for b in buckets:
            name = b['Name']
            try:
                acl = self.s3.get_bucket_acl(Bucket=name)
                for grant in acl.get('Grants', []):
                    uri = grant.get('Grantee', {}).get('URI', '')
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        findings.append((name, 'Bucket ACL allows public access'))
                        break
            except ClientError:
                # ignore buckets we cannot access
                continue
        return findings
