class Plugin:
    def __init__(self, session):
        self.kms = session.client("kms")

    def run(self):
        findings = []
        try:
            paginator = self.kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for key in page.get("Keys", []):
                    key_id = key.get("KeyId")
                    # Describe to filter only customer-managed keys
                    meta = self.kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    if meta.get("KeyManager") != "CUSTOMER":
                        continue
                    # Check rotation status
                    status = self.kms.get_key_rotation_status(KeyId=key_id)
                    if not status.get("KeyRotationEnabled", False):
                        findings.append((key_id, "Automatic rotation is not enabled"))
        except Exception as e:
            findings.append(("KMS", f"Error checking key rotation: {e}"))

        return findings
