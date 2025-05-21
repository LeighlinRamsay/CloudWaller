#!/usr/bin/env python3
"""
Plugin ID: rds_subnet_group_public
Checks if any RDS Subnet Group references a public subnet tag.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.rds = session.client("rds")
        self.ec2 = session.client("ec2")

    def run(self):
        findings = []
        # gather public subnet IDs by tag
        public_subs = {
            s['SubnetId']
            for page in self.ec2.get_paginator("describe_subnets").paginate()
            for s in page.get("Subnets", [])
            if any(t['Key']=='Public' and t['Value']=='true' for t in s.get('Tags',[]))
        }
        for page in self.rds.get_paginator("describe_db_subnet_groups").paginate():
            for grp in page.get("DBSubnetGroups", []):
                gid = grp['DBSubnetGroupName']
                subs = [s['SubnetIdentifier'] for s in grp.get('Subnets',[])]
                if any(s in public_subs for s in subs):
                    findings.append((gid, "Contains public subnet"))
        return findings
