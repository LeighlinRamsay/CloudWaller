#!/usr/bin/env python3
"""
Plugin ID: ssm_root_permissions
Detects IAM roles with ssm:GetParameter* permissions over the root (/) parameter path.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client("iam")

    def _check_stmt(self, stmt, role):
        acts = stmt.get("Action") or []
        acts = acts if isinstance(acts, list) else [acts]
        res = stmt.get("Resource") or []
        res = res if isinstance(res, list) else [res]
        if any(a.startswith("ssm:GetParameter") for a in acts):
            for r in res:
                if r == "*" or r.endswith(":parameter/*"):
                    return (role, f"{acts} on {r}")
        return None

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
                        f = self._check_stmt(s, name)
                        if f:
                            findings.append(f)
                # managed
                for ap in self.iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
                    ver = self.iam.get_policy(PolicyArn=ap["PolicyArn"])["Policy"]["DefaultVersionId"]
                    doc = self.iam.get_policy_version(
                        PolicyArn=ap["PolicyArn"], VersionId=ver
                    )["PolicyVersion"]["Document"]
                    stmts = doc.get("Statement") or []
                    stmts = stmts if isinstance(stmts, list) else [stmts]
                    for s in stmts:
                        f = self._check_stmt(s, name)
                        if f:
                            findings.append(f)
        return findings
