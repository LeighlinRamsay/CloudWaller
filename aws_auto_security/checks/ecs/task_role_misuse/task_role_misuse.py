#!/usr/bin/env python3
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.ecs = session.client("ecs")
        self.iam = session.client("iam")

    def run(self):
        findings = []
        td_arns = self.ecs.list_task_definitions().get("taskDefinitionArns", [])
        for arn in td_arns:
            try:
                td = self.ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
                role_arn = td.get("taskRoleArn")
                if not role_arn:
                    continue
                role = role_arn.split("/")[-1]
                names = self.iam.list_role_policies(RoleName=role)["PolicyNames"]
                for pname in names:
                    doc = self.iam.get_role_policy(RoleName=role, PolicyName=pname)["PolicyDocument"]
                    stmts = doc.get("Statement")
                    stmts = stmts if isinstance(stmts, list) else [stmts]
                    for s in stmts:
                        acts = s.get("Action")
                        acts = acts if isinstance(acts, list) else [acts]
                        if any(a in ("ecs:RunTask","ecs:RegisterTaskDefinition","iam:PassRole") for a in acts):
                            findings.append((arn, f"Role allows {acts}"))
                            break
            except ClientError:
                continue
        return findings
