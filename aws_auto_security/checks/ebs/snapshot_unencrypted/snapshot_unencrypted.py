# File: checks/ebs/snapshot_unencrypted/snapshot_unencrypted.py

#!/usr/bin/env python3
"""
Plugin ID: snapshot_unencrypted
Description: Flag any snapshot where Encrypted=False.
"""

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')

    def run(self):
        findings = []
        snaps = self.ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']
        for s in snaps:
            if not s.get('Encrypted', False):
                findings.append((s['SnapshotId'], "Snapshot is unencrypted"))
        return findings
