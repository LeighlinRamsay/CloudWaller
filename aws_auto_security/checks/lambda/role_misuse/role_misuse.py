# File: checks/lambda/role_misuse/role_misuse.py
#!/usr/bin/env python3
"""
Plugin ID: lambda_role_misuse
Description: Identify Lambda functions whose role includes PassRole or AssumeRole on foreign roles.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.lambda_client = session.client('lambda')
        self.iam = session.client('iam')

    def run(self):
        findings = []
        funcs = self.lambda_client.list_functions().get('Functions', [])
        for fn in funcs:
            fn_name = fn['FunctionName']
            role_arn = fn['Role']
            try:
                pols = self.iam.list_role_policies(RoleName=role_arn.split('/')[-1])['PolicyNames']
                # inline
                for pname in pols:
                    doc = self.iam.get_role_policy(RoleName=role_arn.split('/')[-1], PolicyName=pname)['PolicyDocument']
                    for stmt in doc.get('Statement', [] if isinstance(doc.get('Statement', []), list) else [doc['Statement']]):
                        acts = stmt.get('Action')
                        if acts in ('iam:PassRole','sts:AssumeRole') or (isinstance(acts, list) and any(a in ('iam:PassRole','sts:AssumeRole') for a in acts)):
                            resources = stmt.get('Resource')
                            # if any resource ARN is not the function's own role
                            if resources != role_arn:
                                findings.append((fn_name, f"{acts} permitted on {resources}"))
            except ClientError:
                continue
        return findings
