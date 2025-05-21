# File: checks/security/hardcoded_secrets/hardcoded_secrets.py

#!/usr/bin/env python3
"""
Plugin ID: hardcoded_secrets
Description: Detect hardcoded credentials or secrets in EC2 user-data or Lambda environment variables.
"""

import re
import base64
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.ec2           = session.client('ec2')
        self.lambda_client = session.client('lambda')
        # Compile pattern once, with IGNORECASE flag
        self.secret_pattern = re.compile(
            r'(AKIA[0-9A-Z]{16})|(password\s*=\s*[^&\s]+)|(secret[^=]*=[^&\s]+)',
            flags=re.IGNORECASE
        )

    def run(self):
        findings = []

        # 1) EC2 user data
        try:
            paginator = self.ec2.get_paginator('describe_instances')
            for page in paginator.paginate():
                for res in page.get('Reservations', []):
                    for inst in res.get('Instances', []):
                        iid = inst['InstanceId']
                        try:
                            ud = self.ec2.describe_instance_attribute(
                                InstanceId=iid, Attribute='userData'
                            ).get('UserData', {}).get('Value')
                            if ud:
                                decoded = base64.b64decode(ud).decode('utf-8', errors='ignore')
                                for m in self.secret_pattern.finditer(decoded):
                                    findings.append((
                                        iid,
                                        f"Hardcoded secret '{m.group(0)}' found in EC2 user data"
                                    ))
                        except ClientError:
                            continue
        except ClientError:
            pass

        # 2) Lambda environment variables
        try:
            pag = self.lambda_client.get_paginator('list_functions')
            for page in pag.paginate():
                for fn in page.get('Functions', []):
                    name = fn['FunctionName']
                    try:
                        cfg = self.lambda_client.get_function_configuration(FunctionName=name)
                        env = cfg.get('Environment', {}).get('Variables', {})
                        for key, val in env.items():
                            if self.secret_pattern.search(val):
                                findings.append((
                                    name,
                                    f"Env var '{key}' contains potential secret: '{val}'"
                                ))
                    except ClientError:
                        continue
        except ClientError:
            pass

        return findings
