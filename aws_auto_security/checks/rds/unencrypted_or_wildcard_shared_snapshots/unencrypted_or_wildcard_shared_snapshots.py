#!/usr/bin/env python3
"""
Plugin ID: rds_snapshot_encryption_shared
Checks for:
 - Unencrypted snapshots (Encrypted=False)
 - Snapshots shared publicly or to wildcard account IDs
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.rds = session.client("rds")

    def run(self):
        findings = []
        paginator = self.rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate(MaxRecords=100):
            for snap in page.get("DBSnapshots", []):
                sid = snap["DBSnapshotIdentifier"]
                # 1) encryption
                if not snap.get("Encrypted", False):
                    findings.append((sid, "Snapshot is unencrypted"))
                # 2) sharing
                try:
                    attrs = self.rds.describe_db_snapshot_attributes(
                        DBSnapshotIdentifier=sid
                    )["DBSnapshotAttributesResult"]
                    for perm in attrs.get("DBSnapshotAttributes", []):
                        if perm.get("AttributeName") == "restore" and any(
                            v.endswith(":*") or v == "all" for v in perm.get("AttributeValues", [])
                        ):
                            findings.append((sid, "Snapshot shared with wildcard or public"))
                            break
                except ClientError:
                    # ignore if attributes API fails
                    continue
        return findings
