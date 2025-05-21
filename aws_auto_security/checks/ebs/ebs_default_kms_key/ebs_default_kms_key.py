# File: checks/ebs/ebs_default_kms_key/ebs_default_kms_key.py

#!/usr/bin/env python3
"""
Plugin ID: ebs_default_kms_key
Description: Verify volumes use a customer-managed KMS key rather than the AWS-managed default.
"""

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')

    def run(self):
        findings = []
        default_prefix = 'alias/aws/'
        volumes = self.ec2.describe_volumes()['Volumes']
        for v in volumes:
            kms = v.get('KmsKeyId','')
            if v.get('Encrypted') and kms.startswith(default_prefix):
                findings.append((v['VolumeId'], "Volume uses AWS-managed default KMS key"))
        return findings
