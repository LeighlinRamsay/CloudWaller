#!/usr/bin/env python3
"""
Plugin ID: ec2_role_permissive
Description: IAM roles attached to EC2 instance profiles with wildcard actions.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client('iam')

    def run(self):
        """
        Scan instance-profile-backed roles for policies allowing Action="*".
        Returns a list of (role_name, issue_description) tuples.
        """
        findings = []
        # list all roles
        r_pag = self.iam.get_paginator('list_roles')
        for r_page in r_pag.paginate():
            for r in r_page.get('Roles', []):
                name = r['RoleName']
                # find instance profiles for this role
                profs = self.iam.list_instance_profiles_for_role(RoleName=name)['InstanceProfiles']
                if not profs:
                    continue
                # gather all policy documents
                docs = []
                for prof in profs:
                    for role in prof.get('Roles', []):
                        # inline
                        for pname in self.iam.list_role_policies(RoleName=role['RoleName'])['PolicyNames']:
                            try:
                                docs.append(self.iam.get_role_policy(
                                    RoleName=role['RoleName'], PolicyName=pname
                                )['PolicyDocument'])
                            except ClientError:
                                pass
                        # attached
                        for ap in self.iam.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']:
                            try:
                                pol = self.iam.get_policy(PolicyArn=ap['PolicyArn'])['Policy']
                                doc = self.iam.get_policy_version(
                                    PolicyArn=ap['PolicyArn'], VersionId=pol['DefaultVersionId']
                                )['PolicyVersion']['Document']
                                docs.append(doc)
                            except ClientError:
                                pass
                # inspect docs
                for doc in docs:
                    stmts = doc.get('Statement', [])
                    if not isinstance(stmts, list):
                        stmts = [stmts]
                    for s in stmts:
                        acts = s.get('Action')
                        if s.get('Effect')=='Allow' and (acts=='*' or (isinstance(acts, list) and '*' in acts)):
                            findings.append((name, 'EC2-attached role allows wildcard actions'))
                            break
        return findings
