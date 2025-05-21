# File: checks/ebs/ebs_unencrypted/ebs_unencrypted.py

#!/usr/bin/env python3
"""
Plugin ID: ebs_unencrypted
Description: At-Rest Encryption: Ensure all EBS volumes are encrypted.
"""

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')

    def run(self):
        findings = []
        volumes = self.ec2.describe_volumes()['Volumes']
        for v in volumes:
            if not v.get('Encrypted', False):
                findings.append((v['VolumeId'], "Volume is not encrypted"))
        return findings
