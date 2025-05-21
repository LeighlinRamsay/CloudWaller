#!/usr/bin/env python3
"""
Plugin ID: dangerous_iam
Description: Detect IAM users who have a wildcard Allow (*) on all actions AND all resources.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client("iam")

    def run(self):
        findings = []

        # paginate through all users
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_name = user["UserName"]

                # examine each attached policy
                ap_paginator = self.iam.get_paginator("list_attached_user_policies")
                for ap_page in ap_paginator.paginate(UserName=user_name):
                    for pol in ap_page.get("AttachedPolicies", []):
                        arn = pol["PolicyArn"]

                        # fetch the default version
                        meta = self.iam.get_policy(PolicyArn=arn)["Policy"]
                        version = meta["DefaultVersionId"]
                        doc = self.iam.get_policy_version(
                            PolicyArn=arn,
                            VersionId=version
                        )["PolicyVersion"]["Document"]

                        # normalize Statement to list
                        statements = doc.get("Statement", [])
                        if not isinstance(statements, list):
                            statements = [statements]

                        for stmt in statements:
                            if stmt.get("Effect") != "Allow":
                                continue

                            # normalize Action & Resource
                            raw_actions   = stmt.get("Action", [])
                            raw_resources = stmt.get("Resource", [])

                            actions = raw_actions if isinstance(raw_actions, list) else [raw_actions]
                            resources = raw_resources if isinstance(raw_resources, list) else [raw_resources]

                            # check wildcard on both
                            if "*" in actions and "*" in resources:
                                findings.append((
                                    user_name,
                                    "User has wildcard Allow (*) on all actions and resources"
                                ))
                                # one hit per user is sufficient
                                break

        return findings
