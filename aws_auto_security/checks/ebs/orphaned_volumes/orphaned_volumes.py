# File: checks/ebs/orphaned_volumes/orphaned_volumes.py

#!/usr/bin/env python3
"""
Plugin ID: orphaned_volumes
Description: Identify volumes in state 'available' older than retention threshold.
"""

from datetime import datetime, timezone, timedelta

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')
        # fixed retention 30 days
        self.cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    def run(self):
        findings = []
        vols = self.ec2.describe_volumes(Filters=[{'Name':'status','Values':['available']}])['Volumes']
        for v in vols:
            created = v['CreateTime']
            if created < self.cutoff:
                findings.append((v['VolumeId'], f"Unattached volume older than 30d (created {created.date()})"))
        return findings
