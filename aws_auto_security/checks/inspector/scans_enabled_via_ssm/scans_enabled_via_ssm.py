class Plugin:
    def __init__(self, session):
        # Using Inspector classic client to verify assessment targets & templates
        self.inspector = session.client("inspector")

    def run(self):
        findings = []
        try:
            targets = self.inspector.list_assessment_targets().get("assessmentTargetArns", [])
        except Exception as e:
            findings.append(("Inspector", f"Error listing assessment targets: {e}"))
            return findings

        if not targets:
            findings.append(("Inspector", "No Inspector assessment targets configured"))
            return findings

        try:
            templates = self.inspector.list_assessment_templates().get("assessmentTemplateArns", [])
        except Exception as e:
            findings.append(("Inspector", f"Error listing assessment templates: {e}"))
            return findings

        if not templates:
            findings.append(("Inspector", "No Inspector assessment templates configured"))

        return findings
