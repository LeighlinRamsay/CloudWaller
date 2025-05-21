#!/usr/bin/env python3
"""
Plugin ID: appstream_fleet_session_disconnect_timeout
Flags fleets with DisconnectTimeoutInSeconds > 300.
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
                dt = f.get("DisconnectTimeoutInSeconds", 0)
                if dt > 300:
                    findings.append((name, f"DisconnectTimeoutInSeconds={dt}"))
        return findings
