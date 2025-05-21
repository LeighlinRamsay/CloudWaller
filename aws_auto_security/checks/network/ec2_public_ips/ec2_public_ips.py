# File: checks/network/ec2_public_ips/ec2_public_ips.py

#!/usr/bin/env python3
"""
Plugin ID: ec2_public_ips
Description: EC2 instances using public IPs unnecessarily.
"""

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')

    def run(self):
        """
        Lists instances that have a public IP assigned.
        Returns (instance_id, description) tuples.
        """
        findings = []
        for r in self.ec2.describe_instances().get('Reservations', []):
            for i in r.get('Instances', []):
                iid = i['InstanceId']
                if i.get('PublicIpAddress'):
                    findings.append((iid, f"Instance has public IP {i['PublicIpAddress']}"))
        return findings
