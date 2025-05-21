# File: checks/storage/public_code_assets/public_code_assets.py
#!/usr/bin/env python3
"""
Plugin ID: storage_public_code_assets
Description: Detect S3 buckets or ECR repos with public read permissions serving code assets.
"""

import re
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.s3 = session.client('s3')
        self.ecr = session.client('ecr')
        self.pattern = re.compile(r'\.(js|py|html)$')

    def run(self):
        findings = []
        # S3 objects
        bucks = self.s3.list_buckets().get('Buckets', [])
        for b in bucks:
            name = b['Name']
            try:
                acl = self.s3.get_bucket_acl(Bucket=name)
                for grant in acl.get('Grants', []):
                    if grant.get('Grantee',{}).get('URI','').endswith('/AllUsers'):
                        # public read exists; now scan object keys
                        objs = self.s3.list_objects_v2(Bucket=name).get('Contents', [])
                        for o in objs:
                            if self.pattern.search(o['Key']):
                                findings.append((name, f"Public .{o['Key'].split('.')[-1]} file {o['Key']}"))
            except ClientError:
                continue
        # ECR repositories
        repos = self.ecr.describe_repositories().get('repositories',[])
        for r in repos:
            arn = r['repositoryArn']
            try:
                policy = self.ecr.get_repository_policy(repositoryName=r['repositoryName'])['policyText']
                if '"Principal":"*"' in policy or '"Principal": "*"' in policy:
                    findings.append((arn, "ECR repo policy allows public access"))
            except ClientError:
                continue
        return findings
