# File: checks/network/flow_logs/flow_logs.py

#!/usr/bin/env python3
"""
Plugin ID: flow_logs
Description: VPC Flow Logs disabled.
"""

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')

    def run(self):
        """
        Ensure VPC Flow Logs are enabled for every VPC.
        Returns (vpc_id, description) tuples.
        """
        findings = []
        logs = self.ec2.describe_flow_logs().get('FlowLogs', [])
        enabled = {fl['ResourceId'] for fl in logs if fl['ResourceType']=='VPC' and fl['LogStatus']=='ACTIVE'}
        for v in self.ec2.describe_vpcs().get('Vpcs', []):
            vid = v['VpcId']
            if vid not in enabled:
                findings.append((vid, 'VPC Flow Logs not enabled for VPC'))
        return findings
