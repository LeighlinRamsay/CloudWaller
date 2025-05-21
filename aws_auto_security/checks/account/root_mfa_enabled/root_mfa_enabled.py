class Plugin:
    def __init__(self, session):
        # use the IAM client to fetch account-level summary
        self.iam = session.client("iam")

    def run(self):
        findings = []
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]
        except Exception as e:
            # if we can’t retrieve the summary, emit a finding
            findings.append((
                "Account",
                f"Could not check root MFA status: {e}"
            ))
            return findings

        # AccountMFAEnabled == 1 means root MFA is on
        if summary.get("AccountMFAEnabled", 0) < 1:
            findings.append((
                "Account",
                "Root account does not have MFA enabled"
            ))

        return findings
