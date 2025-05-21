#!/usr/bin/env python3
"""
Plugin ID: immutable_tag_enforcement
Description: IAM policies allowing ec2:DeleteTags without tag-based conditions.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client('iam')

    def run(self):
        """
        Scan both user and role policies for statements allowing ec2:DeleteTags without Condition.
        Returns a list of (entity_name, issue_description) tuples.
        """
        findings = []
        for etype in ('user', 'role'):
            list_ids = (self.iam.list_users if etype=='user' else self.iam.list_roles)()
            ids = [e[f'{etype.capitalize()}Name'] for e in list_ids.get(f'{etype.capitalize()}s', [])]
            for name in ids:
                # inline
                in_p = (self.iam.list_user_policies if etype=='user' else self.iam.list_role_policies)
                for pname in in_p(**{f"{etype.capitalize()}Name": name})['PolicyNames']:
                    try:
                        doc = (self.iam.get_user_policy if etype=='user'
                               else self.iam.get_role_policy)(**{f"{etype.capitalize()}Name": name, 'PolicyName':pname})['PolicyDocument']
                        for s in ([] if 'Statement' not in doc else (doc['Statement'] 
                                    if isinstance(doc['Statement'], list) else [doc['Statement']])):
                            acts = s.get('Action')
                            if acts=='ec2:DeleteTags' or (isinstance(acts,list) and 'ec2:DeleteTags' in acts) or acts=='*':
                                if not s.get('Condition'):
                                    findings.append((name, 'Allows ec2:DeleteTags without tag conditions'))
                                    break
                    except ClientError:
                        continue
                # attached
                at_p = (self.iam.list_attached_user_policies if etype=='user' else self.iam.list_attached_role_policies)
                for ap in at_p(**{f"{etype.capitalize()}Name": name})['AttachedPolicies']:
                    try:
                        pol = self.iam.get_policy(PolicyArn=ap['PolicyArn'])['Policy']
                        ver = pol['DefaultVersionId']
                        doc = self.iam.get_policy_version(PolicyArn=ap['PolicyArn'], VersionId=ver)['PolicyVersion']['Document']
                        for s in ([] if 'Statement' not in doc else (doc['Statement'] 
                                    if isinstance(doc['Statement'], list) else [doc['Statement']])):
                            acts = s.get('Action')
                            if acts=='ec2:DeleteTags' or (isinstance(acts,list) and 'ec2:DeleteTags' in acts) or acts=='*':
                                if not s.get('Condition'):
                                    findings.append((name, 'Managed policy allows ec2:DeleteTags without tag conditions'))
                                    break
                    except ClientError:
                        continue
        return findings
