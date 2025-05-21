#!/usr/bin/env python3
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("cognito-identity")

    def run(self):
        findings = []
        try:
            pools = self.client.list_identity_pools(MaxResults=60).get("IdentityPools", [])
            for p in pools:
                pid = p["IdentityPoolId"]
                roles = self.client.get_identity_pool_roles(IdentityPoolId=pid).get("Roles", {})
                unauth = roles.get("unauthenticated", {}).get("RoleArn")
                if unauth:
                    findings.append((pid, f"Unauthenticated role assigned: {unauth}"))
        except ClientError:
            pass
        return findings
