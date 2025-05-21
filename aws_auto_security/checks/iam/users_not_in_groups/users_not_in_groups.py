#!/usr/bin/env python3
"""
Plugin ID: users_not_in_groups
Description: IAM users not assigned to any group.
"""

class Plugin:
    def __init__(self, session):
        self.iam = session.client('iam')

    def run(self):
        """
        List users who are not in any IAM group.
        Returns a list of (user_name, issue_description) tuples.
        """
        findings = []
        u_pag = self.iam.get_paginator('list_users')
        for u_page in u_pag.paginate():
            for u in u_page.get('Users', []):
                name = u['UserName']
                groups = self.iam.list_groups_for_user(UserName=name)['Groups']
                if not groups:
                    findings.append((name, 'User is not in any IAM group'))
        return findings
