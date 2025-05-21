#!/usr/bin/env python3
"""
Plugin ID: console_no_password_rotation
Description: IAM users with console access and no password rotation (ExpirePasswords=False).
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client('iam')

    def run(self):
        """
        If the account password policy does not expire passwords, list all console users.
        Returns a list of (user_name, issue_description) tuples.
        """
        findings = []
        try:
            policy = self.iam.get_account_password_policy()['PasswordPolicy']
            expire = policy.get('ExpirePasswords', False)
        except self.iam.exceptions.NoSuchEntityException:
            expire = False

        if not expire:
            # any user with login profile
            u_pag = self.iam.get_paginator('list_users')
            for u_page in u_pag.paginate():
                for u in u_page.get('Users', []):
                    name = u['UserName']
                    try:
                        self.iam.get_login_profile(UserName=name)
                        findings.append((name, 'IAM user has console access and no password rotation policy'))
                    except self.iam.exceptions.NoSuchEntityException:
                        continue
        return findings
