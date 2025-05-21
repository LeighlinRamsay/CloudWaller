# File: checks/s3/s3_open_bucket_policy/s3_open_bucket_policy.py

#!/usr/bin/env python3
"""
Plugin ID: s3_open_bucket_policy
Description: S3 bucket security check for open bucket policies.
"""

import json
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.s3 = session.client('s3')

    def run(self):
        """
        Scan all buckets for bucket policies allowing wildcard Principal or Resource.
        Returns a list of (bucket_name, issue_description) tuples.
        """
        findings = []
        buckets = []
        try:
            buckets = self.s3.list_buckets().get('Buckets', [])
        except ClientError:
            return findings

        for b in buckets:
            name = b['Name']
            try:
                policy_str = self.s3.get_bucket_policy(Bucket=name)['Policy']
                doc = json.loads(policy_str)
                stmts = doc.get('Statement', [])
                if not isinstance(stmts, list):
                    stmts = [stmts]
                for s in stmts:
                    princ = s.get('Principal')
                    res   = s.get('Resource')
                    if princ == '*' or (
                        isinstance(princ, dict) and (
                            princ.get('AWS') == '*' or
                            (isinstance(princ.get('AWS'), list) and '*' in princ.get('AWS'))
                        )
                    ) or res == '*' or (
                        isinstance(res, list) and '*' in res
                    ):
                        findings.append((name, 'Bucket policy allows wildcard Principal or Resource'))
                        break
            except ClientError as e:
                code = e.response.get('Error', {}).get('Code', '')
                if code == 'NoSuchBucketPolicy':
                    # No policy is not an issue
                    continue
                # Other errors (e.g., access denied) skip
                continue

        return findings
