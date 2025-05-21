# File: checks/ebs/tag_compliance/tag_compliance.py

#!/usr/bin/env python3
"""
Plugin ID: tag_compliance
Description: Detect tag values outside of your approved set (Environment must be one of prod, staging, dev).
"""

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')

    def run(self):
        findings = []
        allowed = {'prod','staging','dev'}
        volumes = self.ec2.describe_volumes()['Volumes']
        for v in volumes:
            vid = v['VolumeId']
            for t in v.get('Tags', []):
                if t['Key']=='Environment' and t['Value'] not in allowed:
                    findings.append((vid, f"Environment tag '{t['Value']}' not in {allowed}"))
        return findings
