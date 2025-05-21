#!/usr/bin/env python3
"""
Plugin ID: appstream_fleet_default_internet_access_disabled
Flags fleets with EnableDefaultInternetAccess=True.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("appstream")

    def run(self):
        findings = []
        for page in self.client.get_paginator("describe_fleets").paginate():
            for f in page.get("Fleets", []):
                name = f["Name"]
                if f.get("EnableDefaultInternetAccess", False):
                    findings.append((name, "DefaultInternetAccessEnabled=True"))
        return findings
