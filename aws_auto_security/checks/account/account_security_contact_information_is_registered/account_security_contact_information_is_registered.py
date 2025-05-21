# File: checks/account/account_security_contact_information_is_registered/account_security_contact_information_is_registered.py

#!/usr/bin/env python3
"""
Plugin ID: account_security_contact_information_is_registered
Description: Check that a security alternate contact is registered.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("account")

    def run(self):
        findings = []

        try:
            resp = self.client.get_alternate_contact(AlternateContactType="SECURITY")
            alt = resp.get("AlternateContact", {})
            name = alt.get("Name")
            email = alt.get("EmailAddress")
            if not name or not email:
                findings.append((
                    "SECURITY",
                    "Security alternate contact incomplete (Name or EmailAddress missing)"
                ))
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "ResourceNotFoundException":
                findings.append((
                    "SECURITY",
                    "Security alternate contact not configured"
                ))
            else:
                findings.append((
                    "SECURITY",
                    f"Error retrieving SECURITY alternate contact: {code}"
                ))

        return findings
