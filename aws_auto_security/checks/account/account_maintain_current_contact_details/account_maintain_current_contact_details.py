#!/usr/bin/env python3
"""
Plugin ID: account_maintain_current_contact_details
Verifies that your AWS Account contact details are set.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("account")

    def run(self):
        findings = []
        try:
            info = self.client.get_contact_information()
            required = ["ContactName", "ContactEmail", "ContactPhoneNumber"]
            missing = [k for k in required if not info.get(k)]
            if missing:
                findings.append(("Account", f"Missing contact fields: {', '.join(missing)}"))
        except ClientError as e:
            findings.append(("Account", f"Error fetching contact info: {e}"))
        return findings
