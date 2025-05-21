#!/usr/bin/env python3
"""
Plugin ID: appstream_fleet_maximum_session_duration
Flags fleets with MaxUserDurationInSeconds > 36000.
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
                dur = f.get("MaxUserDurationInSeconds", 0)
                if dur > 36000:
                    findings.append((name, f"MaxUserDurationInSeconds={dur}"))
        return findings
