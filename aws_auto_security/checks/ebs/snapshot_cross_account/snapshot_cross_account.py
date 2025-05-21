# File: checks/ebs/snapshot_cross_account/snapshot_cross_account.py

#!/usr/bin/env python3
"""
Plugin ID: snapshot_cross_account
Description: Detect snapshots with permissions granting specific non-owner AWS Account IDs.
"""

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')

    def run(self):
        findings = []
        snaps = self.ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']
        for s in snaps:
            attrs = self.ec2.describe_snapshot_attribute(
                SnapshotId=s['SnapshotId'],
                Attribute='createVolumePermission'
            )['CreateVolumePermissions']
            for p in attrs:
                if 'UserId' in p and p['UserId'] != s['OwnerId']:
                    findings.append((s['SnapshotId'], f"Snapshot shared with account {p['UserId']}"))
        return findings
