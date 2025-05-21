from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.securityhub = session.client("securityhub")
        # boto3.Session stores region_name
        self.region = session.region_name

    def run(self):
        findings = []
        try:
            # Attempt to describe the Security Hub settings for this account/region
            self.securityhub.describe_hub()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                # Hub not enabled in this region
                findings.append((self.region, "AWS Security Hub is not enabled in this region"))
            else:
                # Other client errors
                msg = e.response.get("Error", {}).get("Message", str(e))
                findings.append((self.region, f"Error checking Security Hub: {msg}"))
        except Exception as e:
            # Fallback for unexpected errors
            findings.append((self.region, f"Unexpected error: {e}"))
        return findings
