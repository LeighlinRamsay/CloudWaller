# File: checks/ebs/snapshot_age_retention/snapshot_age_retention.py

#!/usr/bin/env python3
"""
Plugin ID: snapshot_age_retention
Description: Flag snapshots older than 30 days or without DeleteOn tag.
"""

from datetime import datetime, timezone, timedelta

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')
        self.cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    def run(self):
        findings = []
        snaps = self.ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']
        for s in snaps:
            sid = s['SnapshotId']
            created = s['StartTime']
            if created < self.cutoff:
                findings.append((sid, f"Snapshot older than 30d (created {created.date()})"))
            tags = {t['Key']: t['Value'] for t in s.get('Tags', [])}
            if 'DeleteOn' not in tags:
                findings.append((sid, "Snapshot missing DeleteOn tag"))
        return findings
