# File: aws_auto_security/checks/iam/attachvolume_permission/attachvolume_permission.py

#!/usr/bin/env python3
"""
Plugin ID: attachvolume_permission
Description: IAM policies that allow ec2:AttachVolume on Resource="*".
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client('iam')

    def run(self):
        """
        Scan both user and role policies for statements allowing ec2:AttachVolume on "*".
        Returns a list of (entity_name, issue_description) tuples.
        """
        findings = []

        # Iterate over IAM users and roles
        for etype in ('user', 'role'):
            # Build paginator for list_users or list_roles
            paginator = self.iam.get_paginator(f'list_{etype}s')
            names = []
            for page in paginator.paginate():
                key = f'{etype.capitalize()}s'  # "Users" or "Roles"
                for ent in page.get(key, []):
                    names.append(ent[f'{etype.capitalize()}Name'])

            for name in names:
                # 1) Inline policies
                list_inline = getattr(self.iam, f'list_{etype}_policies')
                inline_pols = list_inline(**{f"{etype.capitalize()}Name": name})['PolicyNames']
                for pol_name in inline_pols:
                    try:
                        get_policy = (self.iam.get_user_policy if etype=='user'
                                      else self.iam.get_role_policy)
                        doc = get_policy(**{f"{etype.capitalize()}Name": name, 'PolicyName':pol_name})['PolicyDocument']
                        stmts = doc.get('Statement', [])
                        if not isinstance(stmts, list):
                            stmts = [stmts]
                        for s in stmts:
                            acts = s.get('Action')
                            # check for AttachVolume or wildcard
                            if (acts == 'ec2:AttachVolume'
                                or (isinstance(acts, list) and 'ec2:AttachVolume' in acts)
                                or acts == '*'):
                                res = s.get('Resource')
                                if res == '*' or (isinstance(res, list) and '*' in res):
                                    findings.append((name, 'Policy allows ec2:AttachVolume on resource "*"'))
                                    break
                    except ClientError:
                        continue

                # 2) Attached managed policies
                list_attached = getattr(self.iam, f'list_attached_{etype}_policies')
                attached = list_attached(**{f"{etype.capitalize()}Name": name})['AttachedPolicies']
                for ap in attached:
                    try:
                        pol = self.iam.get_policy(PolicyArn=ap['PolicyArn'])['Policy']
                        ver = pol['DefaultVersionId']
                        doc = self.iam.get_policy_version(
                            PolicyArn=ap['PolicyArn'], VersionId=ver
                        )['PolicyVersion']['Document']
                        stmts = doc.get('Statement', [])
                        if not isinstance(stmts, list):
                            stmts = [stmts]
                        for s in stmts:
                            acts = s.get('Action')
                            if (acts == 'ec2:AttachVolume'
                                or (isinstance(acts, list) and 'ec2:AttachVolume' in acts)
                                or acts == '*'):
                                res = s.get('Resource')
                                if res == '*' or (isinstance(res, list) and '*' in res):
                                    findings.append((name, 'Managed policy allows ec2:AttachVolume on resource "*"'))
                                    break
                    except ClientError:
                        continue

        return findings
