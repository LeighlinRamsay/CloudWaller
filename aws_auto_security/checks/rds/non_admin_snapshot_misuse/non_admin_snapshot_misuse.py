#!/usr/bin/env python3
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client("iam")

    def run(self):
        findings = []
        admins = {"DBAdmins"}

        # Users
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for ent in page.get("Users", []):
                name = ent["UserName"]
                groups = {g["GroupName"] for g in self.iam.list_groups_for_user(UserName=name)["Groups"]}
                if groups & admins:
                    continue
                for pol in self.iam.list_user_policies(UserName=name)["PolicyNames"]:
                    try:
                        doc = self.iam.get_user_policy(UserName=name, PolicyName=pol)["PolicyDocument"]
                        stmts = doc.get("Statement")
                        stmts = stmts if isinstance(stmts, list) else [stmts]
                        for s in stmts:
                            acts = s.get("Action")
                            acts = acts if isinstance(acts, list) else [acts]
                            for a in ("rds:CreateDBSnapshot","rds:RestoreDBInstanceFromDBSnapshot"):
                                if a in acts:
                                    findings.append((name, f"{a} allowed without DBAdmins"))
                    except ClientError:
                        continue
                for ap in self.iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]:
                    try:
                        ver = self.iam.get_policy(PolicyArn=ap["PolicyArn"])["Policy"]["DefaultVersionId"]
                        doc = self.iam.get_policy_version(PolicyArn=ap["PolicyArn"], VersionId=ver)["PolicyVersion"]["Document"]
                        stmts = doc.get("Statement")
                        stmts = stmts if isinstance(stmts, list) else [stmts]
                        for s in stmts:
                            acts = s.get("Action")
                            acts = acts if isinstance(acts, list) else [acts]
                            for a in ("rds:CreateDBSnapshot","rds:RestoreDBInstanceFromDBSnapshot"):
                                if a in acts:
                                    findings.append((name, f"{a} allowed without DBAdmins"))
                    except ClientError:
                        continue

        # Roles
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for ent in page.get("Roles", []):
                name = ent["RoleName"]
                for pol in self.iam.list_role_policies(RoleName=name)["PolicyNames"]:
                    try:
                        doc = self.iam.get_role_policy(RoleName=name, PolicyName=pol)["PolicyDocument"]
                        stmts = doc.get("Statement")
                        stmts = stmts if isinstance(stmts, list) else [stmts]
                        for s in stmts:
                            acts = s.get("Action")
                            acts = acts if isinstance(acts, list) else [acts]
                            for a in ("rds:CreateDBSnapshot","rds:RestoreDBInstanceFromDBSnapshot"):
                                if a in acts:
                                    findings.append((name, f"{a} allowed without DBAdmins"))
                    except ClientError:
                        continue
                for ap in self.iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
                    try:
                        ver = self.iam.get_policy(PolicyArn=ap["PolicyArn"])["Policy"]["DefaultVersionId"]
                        doc = self.iam.get_policy_version(PolicyArn=ap["PolicyArn"], VersionId=ver)["PolicyVersion"]["Document"]
                        stmts = doc.get("Statement")
                        stmts = stmts if isinstance(stmts, list) else [stmts]
                        for s in stmts:
                            acts = s.get("Action")
                            acts = acts if isinstance(acts, list) else [acts]
                            for a in ("rds:CreateDBSnapshot","rds:RestoreDBInstanceFromDBSnapshot"):
                                if a in acts:
                                    findings.append((name, f"{a} allowed without DBAdmins"))
                    except ClientError:
                        continue

        return findings
