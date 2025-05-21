import datetime

class Plugin:
    def __init__(self, session):
        self.iam = session.client("iam")

    def run(self):
        findings = []
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=90)
        try:
            paginator = self.iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    role_name = role['RoleName']
                    # Fetch last used info
                    resp = self.iam.get_role(RoleName=role_name)
                    last_used = resp['Role'].get('RoleLastUsed', {}).get('LastUsedDate')
                    if not last_used or last_used < cutoff:
                        desc = (
                            f"Role '{role_name}' has not been used "
                            f"since {last_used.date() if last_used else 'creation'}."
                        )
                        findings.append((role_name, desc))
        except Exception as e:
            findings.append(("IAM", f"Error checking unused roles: {e}"))

        return findings
