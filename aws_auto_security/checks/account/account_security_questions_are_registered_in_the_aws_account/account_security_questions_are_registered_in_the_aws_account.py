#!/usr/bin/env python3
"""
Plugin ID: account_security_questions_are_registered_in_the_aws_account
AWS does not expose security questions via API; this is a manual check.
Plugin will always return no automated finding.
"""

class Plugin:
    def __init__(self, session):
        pass

    def run(self):
        # Cannot verify via API
        return []
