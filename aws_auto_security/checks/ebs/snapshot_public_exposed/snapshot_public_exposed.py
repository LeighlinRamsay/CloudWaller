# File: checks/ebs/snapshot_public_exposed/snapshot_public_exposed.py

#!/usr/bin/env python3
"""
Plugin ID: snapshot_public_exposed
Description: Flag any snapshot whose CreateVolumePermission includes All (public).
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
                if p.get('Group') == 'all':
                    findings.append((s['SnapshotId'], "Snapshot is publicly shareable"))
                    break
        return findings
