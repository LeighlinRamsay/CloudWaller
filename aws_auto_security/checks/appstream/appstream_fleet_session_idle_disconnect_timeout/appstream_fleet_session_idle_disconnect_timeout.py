#!/usr/bin/env python3
"""
Plugin ID: appstream_fleet_session_idle_disconnect_timeout
Flags fleets with IdleDisconnectTimeoutInSeconds > 600.
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
                idt = f.get("IdleDisconnectTimeoutInSeconds", 0)
                if idt > 600:
                    findings.append((name, f"IdleDisconnectTimeoutInSeconds={idt}"))
        return findings
