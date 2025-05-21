#!/usr/bin/env python3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta

class Plugin:
    def __init__(self, session):
        self.ct = session.client("cloudtrail")

    def run(self):
        findings = []
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=7)
        try:
            events = self.ct.lookup_events(
                LookupAttributes=[{"AttributeKey":"EventName","AttributeValue":"Invoke"}],
                StartTime=past, EndTime=now, MaxResults=50
            ).get("Events", [])
            for ev in events:
                name = ev.get("Resources", [{}])[0].get("ResourceName", "<unknown>")
                api = ev.get("EventName", "")
                if any(x in api for x in ["AttachRolePolicy","CreatePolicy","AttachUserPolicy"]):
                    findings.append((name, f"Invoked escalation API: {api}"))
        except ClientError:
            pass
        return findings
