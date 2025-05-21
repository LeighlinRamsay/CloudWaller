# File: checks/cloud_checks/config_service/config_service.py
#!/usr/bin/env python3
"""
Plugin ID: config_service
Description: Check that AWS Config is enabled (configuration recorder is recording).
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.config = session.client('config')

    def run(self):
        """
        Verifies that at least one configuration recorder is recording.
        Returns a list of (resource_id, issue_description) tuples.
        """
        findings = []
        try:
            status = self.config.describe_configuration_recorder_status()['ConfigurationRecordersStatus']
            if not status or not any(s.get('recording') for s in status):
                findings.append(('AWSConfig', 'AWS Config is not enabled'))
        except ClientError as e:
            findings.append(('AWSConfig', f'Error checking AWS Config: {e}'))
        return findings
