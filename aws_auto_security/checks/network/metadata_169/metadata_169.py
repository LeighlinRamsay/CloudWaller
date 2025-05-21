#!/usr/bin/env python3
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.elbv2 = session.client("elbv2")

    def run(self):
        findings = []
        try:
            tgs = self.elbv2.describe_target_groups().get("TargetGroups", [])
            for tg in tgs:
                arn = tg["TargetGroupArn"]
                lbs = self.elbv2.describe_listeners(LoadBalancerArn=tg["LoadBalancerArn"]).get("Listeners", [])
                for lst in lbs:
                    rules = self.elbv2.describe_rules(ListenerArn=lst["ListenerArn"]).get("Rules", [])
                    for rule in rules:
                        if "169.254.169.254" in str(rule):
                            findings.append((arn, "Allows metadata service access"))
        except ClientError:
            pass
        return findings
