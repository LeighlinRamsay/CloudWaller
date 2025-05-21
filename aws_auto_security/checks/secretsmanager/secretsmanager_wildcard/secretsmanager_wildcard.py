#!/usr/bin/env python3
"""
Plugin ID: secretsmanager_wildcard
Flags roles with secretsmanager:GetSecretValue on wildcard (*) ARNs.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client("iam")

    def run(self):
        findings = []
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                name = role["RoleName"]
                # inline
                for pname in self.iam.list_role_policies(RoleName=name)["PolicyNames"]:
                    doc = self.iam.get_role_policy(RoleName=name, PolicyName=pname)["PolicyDocument"]
                    stmts = doc.get("Statement") or []
                    stmts = stmts if isinstance(stmts, list) else [stmts]
                    for s in stmts:
                        acts = s.get("Action") or []
                        acts = acts if isinstance(acts, list) else [acts]
                        if "secretsmanager:GetSecretValue" in acts:
                            res = s.get("Resource") or []
                            res = res if isinstance(res, list) else [res]
                            if any(r == "*" for r in res):
                                findings.append((name, f"GetSecretValue on wildcard"))
                # managed
                for ap in self.iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
                    ver = self.iam.get_policy(PolicyArn=ap["PolicyArn"])["Policy"]["DefaultVersionId"]
                    doc = self.iam.get_policy_version(
                        PolicyArn=ap["PolicyArn"], VersionId=ver
                    )["PolicyVersion"]["Document"]
                    stmts = doc.get("Statement") or []
                    stmts = stmts if isinstance(stmts, list) else [stmts]
                    for s in stmts:
                        acts = s.get("Action") or []
                        acts = acts if isinstance(acts, list) else [acts]
                        if "secretsmanager:GetSecretValue" in acts:
                            res = s.get("Resource") or []
                            res = res if isinstance(res, list) else [res]
                            if any(r == "*" for r in res):
                                findings.append((name, f"GetSecretValue on wildcard"))
        return findings
