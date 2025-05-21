class Plugin:
    def __init__(self, session):
        self.config = session.client("config")

    def run(self):
        findings = []
        # Define the high-risk resource types to check coverage for
        required_types = {
            "AWS::S3::Bucket": False,
            "AWS::IAM::User": False,
            "AWS::EC2::VPC": False,
        }

        try:
            rules = []
            paginator = self.config.get_paginator("describe_config_rules")
            for page in paginator.paginate():
                rules.extend(page.get("ConfigRules", []))
        except Exception as e:
            findings.append(("AWSConfig", f"Could not retrieve Config rules: {e}"))
            return findings

        # Mark which resource types have at least one rule
        for rule in rules:
            scope = rule.get("Scope", {})
            for rtype in scope.get("ComplianceResourceTypes", []):
                if rtype in required_types:
                    required_types[rtype] = True

        # Report any missing coverage
        for rtype, covered in required_types.items():
            if not covered:
                findings.append((rtype, f"No AWS Config rule exists for resource type {rtype}"))

        return findings
