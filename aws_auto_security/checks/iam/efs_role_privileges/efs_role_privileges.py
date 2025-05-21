#!/usr/bin/env python3
"""
Plugin ID: efs_role_privileges
Identifies IAM roles granting ClientMount or CreateTags on any EFS resources.
"""

from botocore.exceptions import ClientError

ACTIONS = {"elasticfilesystem:ClientMount", "ec2:CreateTags"}

class Plugin:
    def __init__(self, session):
        self.iam = session.client("iam")

    def _check_statements(self, stmts, role):
        findings = []
        for stmt in stmts:
            acts = stmt.get("Action") or []
            acts = acts if isinstance(acts, list) else [acts]
            rescs = stmt.get("Resource") or []
            rescs = rescs if isinstance(rescs, list) else [rescs]
            if any(a in ACTIONS for a in acts) and any(r == "*" or "elasticfilesystem:" in r for r in rescs):
                findings.append((role, f"Allows {acts} on {rescs}"))
        return findings

    def run(self):
        findings = []
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                name = role["RoleName"]
                # Inline policies
                for pname in self.iam.list_role_policies(RoleName=name)["PolicyNames"]:
                    doc = self.iam.get_role_policy(RoleName=name, PolicyName=pname)["PolicyDocument"]
                    stmts = doc.get("Statement") or []
                    stmts = stmts if isinstance(stmts, list) else [stmts]
                    findings += self._check_statements(stmts, name)
                # Attached managed policies
                for ap in self.iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
                    ver = self.iam.get_policy(PolicyArn=ap["PolicyArn"])["Policy"]["DefaultVersionId"]
                    doc = self.iam.get_policy_version(
                        PolicyArn=ap["PolicyArn"], VersionId=ver
                    )["PolicyVersion"]["Document"]
                    stmts = doc.get("Statement") or []
                    stmts = stmts if isinstance(stmts, list) else [stmts]
                    findings += self._check_statements(stmts, name)
        return findings
