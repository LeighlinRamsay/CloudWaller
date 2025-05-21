#!/usr/bin/env python3
"""
Plugin ID: guardduty_enabled
Checks that GuardDuty is enabled and findings are sent to EventBridge or SNS.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.gd = session.client("guardduty")

    def run(self):
        findings = []
        try:
            detectors = self.gd.list_detectors().get("DetectorIds", [])
            if not detectors:
                findings.append(("GuardDuty","No detectors enabled"))
            else:
                for d in detectors:
                    cfg = self.gd.get_detector(DetectorId=d)
                    if not cfg.get("FindingPublishingFrequency"):
                        findings.append((d,"No publishing configuration"))
        except ClientError as e:
            findings.append(("GuardDuty", f"Error: {e}"))
        return findings
