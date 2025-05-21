#!/usr/bin/env python3
"""
Plugin ID: codebuild_env_secrets
Detects CodeBuild projects with AWS_* env vars or unencrypted SSM references.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.cb  = session.client("codebuild")

    def run(self):
        findings = []
        for page in self.cb.get_paginator("list_projects").paginate():
            for name in page.get("projects", []):
                cfg = self.cb.batch_get_projects(names=[name])['projects'][0]
                for env in cfg.get("environment", {}).get("environmentVariables", []):
                    key, val = env['name'], env['value']
                    if key.startswith("AWS_") or val.startswith("ssm://"):
                        findings.append((name, f"{key} = {val}"))
        return findings
