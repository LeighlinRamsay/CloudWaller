#!/usr/bin/env python3
"""
Plugin ID: wildcard_trust
Description: IAM roles whose trust policy allows Principal="*".
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client('iam')

    def run(self):
        """
        Scan all IAM roles' AssumeRolePolicyDocument for Principal="*" in trust.
        Returns a list of (role_name, issue_description) tuples.
        """
        findings = []
        r_pag = self.iam.get_paginator('list_roles')
        for r_page in r_pag.paginate():
            for r in r_page.get('Roles', []):
                name = r['RoleName']
                try:
                    doc = r.get('AssumeRolePolicyDocument', {})
                    stmts = doc.get('Statement', [])
                    if not isinstance(stmts, list):
                        stmts = [stmts]
                    for s in stmts:
                        princ = s.get('Principal')
                        if princ=='*' or (isinstance(princ, dict) and (
                            princ.get('AWS')=='*' or (isinstance(princ.get('AWS'), list) and '*' in princ.get('AWS'))
                        )):
                            findings.append((name, 'Role trust policy allows Principal="*"'))
                            break
                except ClientError:
                    continue
        return findings
