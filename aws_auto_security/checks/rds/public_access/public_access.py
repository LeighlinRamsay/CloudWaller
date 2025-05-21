# File: checks/rds/public_access/public_access.py
#!/usr/bin/env python3
"""
Plugin ID: rds_public_access
Description: Detect RDS DB instances with PubliclyAccessible=True.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.rds = session.client('rds')

    def run(self):
        findings = []
        try:
            resp = self.rds.describe_db_instances()
            for db in resp.get('DBInstances', []):
                dbid = db['DBInstanceIdentifier']
                if db.get('PubliclyAccessible'):
                    findings.append((dbid, "RDS instance is publicly accessible"))
        except ClientError:
            pass
        return findings
