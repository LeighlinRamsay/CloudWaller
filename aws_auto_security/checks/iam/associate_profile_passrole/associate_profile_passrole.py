#!/usr/bin/env python3
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client("iam")

    def run(self):
        findings = []
        paginator = self.iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for pol in page.get("Policies", []):
                arn = pol["Arn"]
                try:
                    ver = self.iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
                    doc = self.iam.get_policy_version(PolicyArn=arn, VersionId=ver)["PolicyVersion"]["Document"]
                    stmts = doc.get("Statement")
                    stmts = stmts if isinstance(stmts, list) else [stmts]
                    for s in stmts:
                        acts = s.get("Action")
                        acts = acts if isinstance(acts, list) else [acts]
                        if "ec2:AssociateIamInstanceProfile" in acts and "iam:PassRole" in acts:
                            findings.append((arn, "Combines AssociateIamInstanceProfile & PassRole"))
                            break
                except ClientError:
                    continue
        return findings
