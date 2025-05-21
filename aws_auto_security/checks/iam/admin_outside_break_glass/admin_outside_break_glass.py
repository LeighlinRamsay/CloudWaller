#!/usr/bin/env python3
"""
Plugin ID: admin_outside_break_glass
Description: IAM users with AdministratorAccess but not in “break-glass” group.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client('iam')
        self.break_glass = {'break-glass-admin'}

    def run(self):
        """
        List users with AdministratorAccess attached and not in the break-glass-admin group.
        Returns a list of (user_name, issue_description) tuples.
        """
        findings = []
        u_pag = self.iam.get_paginator('list_users')
        for u_page in u_pag.paginate():
            for u in u_page.get('Users', []):
                name = u['UserName']
                # groups
                groups = {g['GroupName'] for g in self.iam.list_groups_for_user(UserName=name)['Groups']}
                if groups & self.break_glass:
                    continue
                # attached policies
                at = {p['PolicyName'] for p in self.iam.list_attached_user_policies(UserName=name)['AttachedPolicies']}
                if 'AdministratorAccess' in at:
                    findings.append((name, 'User has AdministratorAccess outside break-glass'))
        return findings
