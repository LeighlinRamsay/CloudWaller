# File: checks/network/nacl/nacl.py

#!/usr/bin/env python3
"""
Plugin ID: nacl
Description: Network ACL insecure rules and missing associations.
"""

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')

    def run(self):
        """
        Checks:
          - Subnets with no associated NACL
          - NACLs allowing all traffic (protocol=-1, Cidr=0.0.0.0/0)
        Returns (resource_id, description) tuples.
        """
        findings = []
        # map subnets to NACLs
        assoc = {}
        for nacl in self.ec2.describe_network_acls().get('NetworkAcls', []):
            for a in nacl.get('Associations', []):
                sid = a.get('SubnetId')
                if sid:
                    assoc.setdefault(sid, []).append(nacl['NetworkAclId'])
        # missing NACL
        for s in self.ec2.describe_subnets().get('Subnets', []):
            sid = s['SubnetId']
            if sid not in assoc:
                findings.append((sid, 'No NACL associated with subnet'))
        # insecure rules
        for nacl in self.ec2.describe_network_acls().get('NetworkAcls', []):
            nid = nacl['NetworkAclId']
            for e in nacl.get('Entries', []):
                if e.get('RuleAction')=='allow' and e.get('Protocol')=='-1' and e.get('CidrBlock')=='0.0.0.0/0':
                    findings.append((nid, 'Network ACL allows all traffic from 0.0.0.0/0'))
        return findings
