# File: checks/beanstalk/aws_env_vars/aws_env_vars.py
#!/usr/bin/env python3
"""
Plugin ID: beanstalk_aws_env_vars
Description: Scan Elastic Beanstalk environments for AWS_* env vars exposing credentials.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.eb = session.client('elasticbeanstalk')

    def run(self):
        findings = []
        paginator = self.eb.get_paginator('describe_environments')
        for page in paginator.paginate():
            for env in page.get('Environments', []):
                env_id = env['EnvironmentId']
                try:
                    cfg = self.eb.describe_configuration_settings(
                        ApplicationName=env['ApplicationName'],
                        EnvironmentName=env['EnvironmentName']
                    )['ConfigurationSettings'][0]
                    for opt in cfg.get('OptionSettings', []):
                        if opt['Namespace']=='aws:elasticbeanstalk:application:environment':
                            key = opt['OptionName']
                            if key.startswith('AWS_'):
                                findings.append((
                                    env_id,
                                    f"Env var {key} exposing AWS credential"
                                ))
                except ClientError:
                    continue
        return findings
