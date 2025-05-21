# File: checks/account/account_maintain_different_contact_details_to_security_billing_and_operations/account_maintain_different_contact_details_to_security_billing_and_operations.py

#!/usr/bin/env python3
"""
Plugin ID: account_maintain_different_contact_details_to_security_billing_and_operations
Description: Check that billing, operations, and security alternate contacts are all configured.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("account")

    def run(self):
        findings = []
        contact_types = ["BILLING", "OPERATIONS", "SECURITY"]

        for ctype in contact_types:
            try:
                resp = self.client.get_alternate_contact(AlternateContactType=ctype)
                alt = resp.get("AlternateContact", {})
                name = alt.get("Name")
                email = alt.get("EmailAddress")
                if not name or not email:
                    findings.append((
                        ctype,
                        f"{ctype} alternate contact incomplete (Name or EmailAddress missing)"
                    ))
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code == "ResourceNotFoundException":
                    findings.append((
                        ctype,
                        f"{ctype} alternate contact not configured"
                    ))
                else:
                    findings.append((
                        ctype,
                        f"Error retrieving {ctype} alternate contact: {code}"
                    ))

        return findings
