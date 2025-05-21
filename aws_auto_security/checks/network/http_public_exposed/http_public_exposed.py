# File: checks/network/http_public_exposed/http_public_exposed.py

#!/usr/bin/env python3
"""
Plugin ID: http_public_exposed
Description: HTTP/S security groups exposing instances in public subnets.
"""

class Plugin:
    def __init__(self, session):
        self.ec2 = session.client('ec2')

    def run(self):
        """
        Find security groups allowing port 80/443 to 0.0.0.0/0,
        and flag if attached to instances in public subnets.
        Returns (sg_id, description) tuples.
        """
        findings = []
        # collect all instances
        instances = [i for r in self.ec2.describe_instances().get('Reservations', []) for i in r.get('Instances', [])]
        total = len(instances)
        # evaluate each SG
        for sg in self.ec2.describe_security_groups().get('SecurityGroups', []):
            sg_id = sg['GroupId']
            # only SGs with port 80 or 443 open to public
            if not any(
                p.get('FromPort') in (80,443) and 
                any(ip.get('CidrIp')=='0.0.0.0/0' for ip in p.get('IpRanges', []))
                for p in sg.get('IpPermissions', [])
            ):
                continue
            # find attached instance IDs
            nis = self.ec2.describe_network_interfaces(
                Filters=[{'Name':'group-id','Values':[sg_id]}]
            ).get('NetworkInterfaces', [])
            ids = {ni['Attachment']['InstanceId'] for ni in nis if ni.get('Attachment')}
            # skip if not majority
            if len(ids) <= total / 2:
                continue
            # check public subnet via route table
            for inst in instances:
                iid = inst['InstanceId']
                if iid not in ids:
                    continue
                sub = inst.get('SubnetId')
                rts = self.ec2.describe_route_tables(
                    Filters=[{'Name':'association.subnet-id','Values':[sub]}]
                ).get('RouteTables', [])
                for rt in rts:
                    for r in rt.get('Routes', []):
                        if r.get('DestinationCidrBlock')=='0.0.0.0/0' and r.get('GatewayId','').startswith('igw-'):
                            findings.append(
                                (sg_id, f"SG allows HTTP/S and instance {iid} in public subnet {sub}")
                            )
                            break
        return findings
