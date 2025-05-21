#!/usr/bin/env python3
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client("ec2")

    def run(self):
        findings = []
        app_ports = {80,443,8080,3000}
        try:
            sgs = self.ec2.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                gid = sg["GroupId"]
                for perm in sg.get("IpPermissions", []):
                    port = perm.get("FromPort")
                    if port in app_ports:
                        for ip in perm.get("IpRanges", []):
                            if ip.get("CidrIp") == "0.0.0.0/0":
                                findings.append((gid, f"Port {port} open without WAF"))
        except ClientError:
            pass
        return findings
