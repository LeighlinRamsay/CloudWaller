#!/usr/bin/env python3
"""
Plugin ID: glue_job_privileges
Checks Glue job roles for glue:CreateJob or glue:StartJobRun on wildcard/script ARNs.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.glue = session.client("glue")
        self.iam  = session.client("iam")

    def run(self):
        findings = []
        jobs = self.glue.get_paginator("get_jobs").paginate().build_full_result().get("Jobs", [])
        for job in jobs:
            role_arn = job.get("Role")
            if not role_arn:
                continue
            role_name = role_arn.split("/")[-1]
            # inline policies
            for pname in self.iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
                doc = self.iam.get_role_policy(RoleName=role_name, PolicyName=pname)["PolicyDocument"]
                stmts = doc.get("Statement") or []
                stmts = stmts if isinstance(stmts, list) else [stmts]
                for s in stmts:
                    acts = s.get("Action") or []
                    acts = acts if isinstance(acts, list) else [acts]
                    if any(a in ("glue:CreateJob","glue:StartJobRun") for a in acts):
                        findings.append((job["Name"], f"Role {role_name} allows {acts}"))
                        break
            # attached managed policies
            for ap in self.iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
                ver = self.iam.get_policy(PolicyArn=ap["PolicyArn"])["Policy"]["DefaultVersionId"]
                doc = self.iam.get_policy_version(
                    PolicyArn=ap["PolicyArn"], VersionId=ver
                )["PolicyVersion"]["Document"]
                stmts = doc.get("Statement") or []
                stmts = stmts if isinstance(stmts, list) else [stmts]
                for s in stmts:
                    acts = s.get("Action") or []
                    acts = acts if isinstance(acts, list) else [acts]
                    if any(a in ("glue:CreateJob","glue:StartJobRun") for a in acts):
                        findings.append((job["Name"], f"Role {role_name} allows {acts}"))
                        break
        return findings
