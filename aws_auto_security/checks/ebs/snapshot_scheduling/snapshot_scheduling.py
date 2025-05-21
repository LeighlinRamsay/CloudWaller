# File: checks/ebs/snapshot_scheduling/snapshot_scheduling.py

#!/usr/bin/env python3
"""
Plugin ID: snapshot_scheduling
Description: Verify account has AWS Config or Lambda ensuring regular snapshots of critical volumes.
"""

class Plugin:
    def __init__(self, session):
        self.config = session.client('config')

    def run(self):
        findings = []
        rules = self.config.describe_config_rules()['ConfigRules']
        # look for any rule with 'snapshot' keyword
        if not any('snapshot' in r['ConfigRuleName'].lower() for r in rules):
            findings.append(('Config', 'No AWS Config rule or Lambda for automated EBS snapshots'))
        return findings
