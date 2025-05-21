# File: checks/ebs/required_tags/required_tags.py

#!/usr/bin/env python3
"""
Plugin ID: required_tags
Description: Ensure every EBS volume has mandatory tags (Owner, Environment, Project).
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')

    def run(self):
        findings = []
        volumes = self.ec2.describe_volumes()['Volumes']
        for v in volumes:
            vid = v['VolumeId']
            tags = {t['Key']: t['Value'] for t in v.get('Tags', [])}
            missing = [k for k in ('Owner','Environment','Project') if k not in tags]
            if missing:
                findings.append((vid, f"Missing tags: {','.join(missing)}"))
        return findings
