#!/usr/bin/env python3
"""
Plugin ID: dangerous_iam_role_action
Description: IAM roles whose policies allow wildcard actions (“*”).
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client('iam')

    def run(self):
        """
        Scan all IAM roles for any policy (inline or attached) allowing Action="*" .
        Returns a list of (role_name, issue_description) tuples.
        """
        findings = []
        r_pag = self.iam.get_paginator('list_roles')
        for r_page in r_pag.paginate():
            for r in r_page.get('Roles', []):
                role = r['RoleName']
                # inline policies
                ip_pag = self.iam.get_paginator('list_role_policies')
                for ip_page in ip_pag.paginate(RoleName=role):
                    for pname in ip_page.get('PolicyNames', []):
                        try:
                            doc = self.iam.get_role_policy(RoleName=role, PolicyName=pname)['PolicyDocument']
                            stmts = doc.get('Statement', [])
                            if not isinstance(stmts, list):
                                stmts = [stmts]
                            for s in stmts:
                                acts = s.get('Action')
                                if s.get('Effect')=='Allow' and (acts=='*' or (isinstance(acts, list) and '*' in acts)):
                                    findings.append((role, 'Role allows wildcard (*) actions'))
                                    break
                        except ClientError:
                            continue
                # attached managed
                ap_pag = self.iam.get_paginator('list_attached_role_policies')
                for ap_page in ap_pag.paginate(RoleName=role):
                    for ap in ap_page.get('AttachedPolicies', []):
                        try:
                            pol = self.iam.get_policy(PolicyArn=ap['PolicyArn'])['Policy']
                            ver_id = pol['DefaultVersionId']
                            doc = self.iam.get_policy_version(
                                PolicyArn=ap['PolicyArn'], VersionId=ver_id
                            )['PolicyVersion']['Document']
                            stmts = doc.get('Statement', [])
                            if not isinstance(stmts, list):
                                stmts = [stmts]
                            for s in stmts:
                                acts = s.get('Action')
                                if s.get('Effect')=='Allow' and (acts=='*' or (isinstance(acts, list) and '*' in acts)):
                                    findings.append((role, 'Role allows wildcard (*) actions'))
                                    break
                        except ClientError:
                            continue
        return findings
