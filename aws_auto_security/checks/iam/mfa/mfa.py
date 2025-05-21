#!/usr/bin/env python3
"""
Plugin ID: mfa
Description: Check that root and all IAM users have MFA devices.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client('iam')

    def run(self):
        """
        Verify root account and each IAM user have at least one MFA device.
        Returns a list of (entity, issue_description) tuples.
        """
        findings = []
        # root
        summary = self.iam.get_account_summary().get('SummaryMap', {})
        if summary.get('AccountMFAEnabled', 0) == 0:
            findings.append(('root', 'Root account does not have MFA enabled'))
        # users
        u_pag = self.iam.get_paginator('list_users')
        for u_page in u_pag.paginate():
            for u in u_page.get('Users', []):
                name = u['UserName']
                try:
                    mfas = self.iam.list_mfa_devices(UserName=name).get('MFADevices', [])
                    if not mfas:
                        findings.append((name, 'IAM user does not have MFA enabled'))
                except ClientError:
                    continue
        return findings
