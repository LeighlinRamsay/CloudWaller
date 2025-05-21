#!/usr/bin/env python3
"""
Plugin ID: efs_mount_sg_public
Flags EFS mount targets whose security groups allow 0.0.0.0/0.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.efs = session.client("efs")
        self.ec2 = session.client("ec2")

    def run(self):
        findings = []
        # 1) List all file systems
        fs_paginator = self.efs.get_paginator("describe_file_systems")
        for fs_page in fs_paginator.paginate():
            for fs in fs_page.get("FileSystems", []):
                fsid = fs["FileSystemId"]
                # 2) For each FS, page through its mount targets
                mt_paginator = self.efs.get_paginator("describe_mount_targets")
                for mt_page in mt_paginator.paginate(FileSystemId=fsid):
                    for mt in mt_page.get("MountTargets", []):
                        mtid = mt["MountTargetId"]
                        # 3) Check each SG on that mount target
                        for sg in mt.get("SecurityGroups", []):
                            try:
                                sg_desc = self.ec2.describe_security_groups(
                                    GroupIds=[sg]
                                )["SecurityGroups"][0]
                                for perm in sg_desc.get("IpPermissions", []):
                                    for ipr in perm.get("IpRanges", []):
                                        if ipr.get("CidrIp") == "0.0.0.0/0":
                                            findings.append(
                                                (f"{mtid}:{sg}", "Mount-target SG open to public")
                                            )
                                            # stop checking this mount-target
                                            raise StopIteration
                            except StopIteration:
                                break
                            except ClientError:
                                # ignore EC2 errors for this SG
                                continue
        return findings
