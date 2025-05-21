# File: checks/network/ec2_not_in_asg/ec2_not_in_asg.py

#!/usr/bin/env python3
"""
Plugin ID: ec2_not_in_asg
Description: EC2 instances not part of an Auto Scaling group.
"""

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')

    def run(self):
        """
        Lists instances without the 'aws:autoscaling:groupName' tag.
        Returns (instance_id, description) tuples.
        """
        findings = []
        for r in self.ec2.describe_instances().get('Reservations', []):
            for i in r.get('Instances', []):
                iid = i['InstanceId']
                tags = {t['Key']: t['Value'] for t in i.get('Tags', [])}
                if 'aws:autoscaling:groupName' not in tags:
                    findings.append((iid, 'Instance not in any Auto Scaling group'))
        return findings
