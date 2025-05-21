# File: checks/iam/create_key_limits/create_key_limits.py
#!/usr/bin/env python3
"""
Plugin ID: iam_create_access_key_limits
Description: Detect policies granting CreateAccessKey or RotateAccessKey without delete/list limits.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client('iam')

    def run(self):
        findings = []
        paginator = self.iam.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            for pol in page.get('Policies', []):
                arn = pol['Arn']
                try:
                    ver = self.iam.get_policy(PolicyArn=arn)['Policy']['DefaultVersionId']
                    doc = self.iam.get_policy_version(PolicyArn=arn, VersionId=ver)['PolicyVersion']['Document']
                    for stmt in doc.get('Statement', [] if isinstance(doc.get('Statement', []), list) else [doc['Statement']]):
                        acts = stmt.get('Action')
                        if (acts == 'iam:CreateAccessKey' or acts == 'iam:RotateAccessKey' or
                            (isinstance(acts, list) and any(a in ('iam:CreateAccessKey','iam:RotateAccessKey') for a in acts))):
                            cond = stmt.get('Condition')
                            if not cond:
                                findings.append((arn, "Policy allows Create/RotateAccessKey without limitations"))
                except ClientError:
                    continue
        return findings
