# File: checks/sns/topic_policy/topic_policy.py
#!/usr/bin/env python3
"""
Plugin ID: sns_topic_policy
Description: Verify SNS topic policies do not allow Principal=\"*\" or broad actions.
"""

import json
from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.sns = session.client('sns')

    def run(self):
        findings = []
        topics = self.sns.list_topics().get('Topics', [])
        for t in topics:
            arn = t['TopicArn']
            try:
                policy_str = self.sns.get_topic_attributes(TopicArn=arn)['Attributes']['Policy']
                doc = json.loads(policy_str)
                for stmt in doc.get('Statement', []):
                    princ = stmt.get('Principal', {})
                    if princ == "*" or (isinstance(princ, dict) and princ.get('AWS') == "*"):
                        findings.append((arn, "Policy allows Principal=\"*\""))
                    actions = stmt.get('Action')
                    if actions == "*" or (isinstance(actions, list) and any(a.endswith("Subscribe") or a.endswith("Publish") for a in actions)):
                        findings.append((arn, "Policy grants broad Publish/Subscribe"))
            except ClientError:
                continue
        return findings
