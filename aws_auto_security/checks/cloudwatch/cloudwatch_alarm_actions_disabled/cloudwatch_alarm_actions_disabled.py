#!/usr/bin/env python3
"""
Plugin ID: cloudwatch_alarm_actions_disabled
Checks for CloudWatch MetricAlarms with ActionsEnabled=false.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.client = session.client("cloudwatch")

    def run(self):
        findings = []
        paginator = self.client.get_paginator("describe_alarms")
        for page in paginator.paginate():
            for alarm in page.get("MetricAlarms", []):
                name = alarm.get("AlarmName")
                if alarm.get("ActionsEnabled") is False:
                    findings.append((name, "ActionsEnabled=false"))
        return findings
