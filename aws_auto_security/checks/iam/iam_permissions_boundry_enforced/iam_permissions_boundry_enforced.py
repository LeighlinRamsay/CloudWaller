class Plugin:
    def __init__(self, session):
        self.iam = session.client("iam")

    def run(self):
        findings = []
        # AWS-managed Administrator policy ARN
        admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"

        # Check IAM users
        users = self.iam.list_users().get("Users", [])
        for u in users:
            name = u["UserName"]
            # gather attached managed policies
            attached = self.iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", [])
            attached_arns = {p["PolicyArn"] for p in attached}
            # gather inline policies
            inline = self.iam.list_user_policies(UserName=name).get("PolicyNames", [])
            # detect admin-level rights
            if admin_arn in attached_arns or any("admin" in p.lower() for p in inline):
                # check for permissions boundary
                if "PermissionsBoundary" not in u:
                    findings.append((name, "User has admin-level rights but no permissions boundary"))

        # Check IAM roles
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for r in page.get("Roles", []):
                name = r["RoleName"]
                # managed
                attached = self.iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", [])
                attached_arns = {p["PolicyArn"] for p in attached}
                # inline
                inline = self.iam.list_role_policies(RoleName=name).get("PolicyNames", [])
                if admin_arn in attached_arns or any("admin" in p.lower() for p in inline):
                    if "PermissionsBoundary" not in r:
                        findings.append((name, "Role has admin-level rights but no permissions boundary"))

        return findings
