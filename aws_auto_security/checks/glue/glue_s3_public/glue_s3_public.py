#!/usr/bin/env python3
"""
Plugin ID: glue_s3_public
Checks S3 bucket ACL for any Glue job ScriptLocation buckets that allow public read.
"""

from urllib.parse import urlparse
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.glue = session.client("glue")
        self.s3   = session.client("s3")

    def run(self):
        findings = []
        jobs = self.glue.get_paginator("get_jobs").paginate().build_full_result().get("Jobs", [])
        for job in jobs:
            loc = job.get("Command", {}).get("ScriptLocation")
            if not loc:
                continue
            bucket = urlparse(loc).netloc
            try:
                acl = self.s3.get_bucket_acl(Bucket=bucket)
                for grant in acl.get("Grants", []):
                    if grant.get("Grantee", {}).get("URI", "").endswith("/AllUsers"):
                        findings.append((bucket, f"Bucket {bucket} is publicly readable"))
                        break
            except ClientError:
                continue
        return findings
