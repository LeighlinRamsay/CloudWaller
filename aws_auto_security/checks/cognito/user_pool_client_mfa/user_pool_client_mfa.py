#!/usr/bin/env python3
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.idp = session.client("cognito-idp")

    def run(self):
        findings = []
        try:
            pools = self.idp.list_user_pools(MaxResults=60).get("UserPools", [])
            for u in pools:
                pid = u["Id"]
                mfa_cfg = self.idp.describe_user_pool(UserPoolId=pid)["UserPool"].get("MfaConfiguration")
                clients = self.idp.list_user_pool_clients(UserPoolId=pid, MaxResults=60).get("UserPoolClients", [])
                for c in clients:
                    cid = c["ClientId"]
                    flows = self.idp.describe_user_pool_client(UserPoolId=pid, ClientId=cid)["UserPoolClient"].get("ExplicitAuthFlows", [])
                    if "ALLOW_ADMIN_USER_PASSWORD_AUTH" in flows and mfa_cfg != "ON":
                        findings.append((f"{pid}:{cid}", "Allows ADMIN_USER_PASSWORD_AUTH without MFA"))
        except ClientError:
            pass
        return findings
