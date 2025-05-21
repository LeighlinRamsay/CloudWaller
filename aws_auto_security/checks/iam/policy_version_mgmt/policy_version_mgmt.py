#!/usr/bin/env python3
"""
Plugin ID: iam_policy_version_mgmt
Description: Detect customer-managed IAM policies that have reached the
AWS maximum of 5 non-default versions (i.e. need housekeeping).
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.iam = session.client("iam")

    def run(self):
        findings = []
        # Only customer-managed policies (Scope='Local')
        paginator = self.iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for pol in page.get("Policies", []):
                arn = pol["Arn"]
                try:
                    versions = self.iam.list_policy_versions(PolicyArn=arn)["Versions"]
                except ClientError:
                    # skip policies we cannot access
                    continue

                # count non-default versions
                non_default = [v for v in versions if not v.get("IsDefaultVersion", False)]
                if len(non_default) >= 5:
                    findings.append((
                        arn,
                        f"{len(non_default)} non-default versions present (limit is 5)"
                    ))

        return findings
