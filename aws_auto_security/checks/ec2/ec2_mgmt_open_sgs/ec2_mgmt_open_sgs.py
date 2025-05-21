#!/usr/bin/env python3
"""
Plugin ID: ec2_mgmt_open_sgs
Detect security groups allowing 0.0.0.0/0 on port 22, 3389 or other mgmt ports.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client("ec2")

    def run(self):
        findings = []
        mgmt_ports = {22, 3389, 5900}
        for page in self.ec2.get_paginator("describe_security_groups").paginate():
            for sg in page.get("SecurityGroups", []):
                gid = sg["GroupId"]
                for perm in sg.get("IpPermissions", []):
                    p = perm.get("FromPort")
                    if p in mgmt_ports:
                        for ipr in perm.get("IpRanges", []):
                            if ipr.get("CidrIp") == "0.0.0.0/0":
                                findings.append((gid, f"Port {p} open to public"))
        return findings
