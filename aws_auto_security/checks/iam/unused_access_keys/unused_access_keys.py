#!/usr/bin/env python3
"""
Plugin ID: unused_access_keys
Description: IAM access keys not used in over 90 days.
"""

from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client('iam')
        self.cutoff = datetime.now(timezone.utc) - timedelta(days=90)

    def run(self):
        """
        Scan all IAM users for access keys whose LastUsedDate < cutoff.
        Returns a list of (user_name, issue_description) tuples.
        """
        findings = []
        u_pag = self.iam.get_paginator('list_users')
        for u_page in u_pag.paginate():
            for u in u_page.get('Users', []):
                name = u['UserName']
                ak_pag = self.iam.get_paginator('list_access_keys')
                for ak_page in ak_pag.paginate(UserName=name):
                    for key in ak_page.get('AccessKeyMetadata', []):
                        kid = key['AccessKeyId']
                        try:
                            lu = self.iam.get_access_key_last_used(AccessKeyId=kid)['AccessKeyLastUsed']
                            last = lu.get('LastUsedDate') or key['CreateDate']
                        except ClientError:
                            last = key['CreateDate']
                        if last < self.cutoff:
                            findings.append((name, f"Access key {kid} last used {last.date()}"))
        return findings
