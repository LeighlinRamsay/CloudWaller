# File: checks/cloud_checks/root_account_usage/root_account_usage.py
#!/usr/bin/env python3
"""
Plugin ID: root_account_usage
Description: Check for any root account activity within the last 24 hours.
"""

from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        # boto3 Session passed as session; need CloudTrail client
        self.ct = session.client('cloudtrail')

    def run(self):
        """
        Looks up CloudTrail events for 'root' in the past 24 hours.
        Returns a list of (resource_id, issue_description) tuples.
        """
        findings = []
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=1)
        try:
            events = self.ct.lookup_events(
                LookupAttributes=[{'AttributeKey':'Username','AttributeValue':'root'}],
                StartTime=past,
                EndTime=now,
                MaxResults=1
            )
            if events.get('Events'):
                findings.append(('root', 'Root account was used in the last 24 hours'))
        except ClientError as e:
            findings.append(('root', f'Error checking root account usage: {e}'))
        return findings
