# File: checks/network/open_sgs/open_sgs.py

#!/usr/bin/env python3
"""
Plugin ID: open_sgs
Description: Security Groups open to public (0.0.0.0/0).
"""

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')

    def run(self):
        """
        Scan all security groups for rules that allow 0.0.0.0/0.
        Returns a list of (security_group_id, issue_description) tuples.
        """
        findings = []
        for sg in self.ec2.describe_security_groups().get('SecurityGroups', []):
            sg_id = sg['GroupId']
            for perm in sg.get('IpPermissions', []):
                for ip_range in perm.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port = perm.get('FromPort', 'all')
                        findings.append((sg_id, f"SG allows 0.0.0.0/0 on port {port}"))
        return findings
