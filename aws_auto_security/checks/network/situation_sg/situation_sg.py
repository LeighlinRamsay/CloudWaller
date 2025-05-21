# File: checks/network/situation_sg/situation_sg.py

#!/usr/bin/env python3
"""
Plugin ID: situation_sg
Description: Situational awareness for Security Groups, enforcing that
  - RDS SGs must reference other SGs for both inbound and outbound
  - EC2 SGs must reference other SGs inbound, but may use IPs outbound
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')

    def _get_security_groups(self):
        """
        Retrieve all security groups via paginator to handle >1000 SGs.
        """
        sgs = []
        paginator = self.ec2.get_paginator('describe_security_groups')
        for page in paginator.paginate():
            sgs.extend(page.get('SecurityGroups', []))
        return sgs

    def run(self):
        """
        Scan each SG for situational compliance based on its 'Type' tag:
          - 'rds' requires both inbound and outbound SG-only references
          - 'ec2' requires inbound SG-only references, outbound may be IP
        """
        findings = []
        # Define required behaviour per type
        RULES = {
            'rds': {'inbound': True,  'outbound': True},
            'ec2': {'inbound': True,  'outbound': False},
        }

        try:
            sgs = self._get_security_groups()
        except ClientError:
            return findings

        # Map SG → type tag (lowercased), if present
        type_map = {}
        for sg in sgs:
            gid = sg['GroupId']
            tval = next(
                (t['Value'].lower()
                 for t in sg.get('Tags', [])
                 if t['Key'].lower() == 'type'),
                None
            )
            type_map[gid] = tval

        # Evaluate each SG
        for sg in sgs:
            gid = sg['GroupId']
            role = type_map.get(gid)
            rules = RULES.get(role, {})

            # Inbound checks
            if rules.get('inbound'):
                # must reference SGs, must not include IP ranges
                has_sg = any(p.get('UserIdGroupPairs') for p in sg.get('IpPermissions', []))
                has_ip = any(p.get('IpRanges') for p in sg.get('IpPermissions', []))
                if not has_sg or has_ip:
                    findings.append((
                        gid,
                        'situation_sg',
                        'Inbound missing SG refs or includes IP ranges'
                    ))

            # Outbound checks
            if rules.get('outbound'):
                has_sg_egress = any(p.get('UserIdGroupPairs') for p in sg.get('IpPermissionsEgress', []))
                has_ip_egress = any(p.get('IpRanges') for p in sg.get('IpPermissionsEgress', []))
                if not has_sg_egress or has_ip_egress:
                    findings.append((
                        gid,
                        'situation_sg',
                        'Outbound missing SG refs or includes IP ranges'
                    ))

        return findings
