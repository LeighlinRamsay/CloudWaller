class Plugin:
    def __init__(self, session):
        self.elbv2 = session.client("elbv2")

    def run(self):
        findings = []
        try:
            paginator = self.elbv2.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    lb_arn = lb["LoadBalancerArn"]
                    lb_name = lb.get("LoadBalancerName")
                    # Describe listeners for this ALB
                    listeners = self.elbv2.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                    # Check HTTP listeners
                    for listener in listeners:
                        if listener.get("Protocol") == "HTTP":
                            actions = listener.get("DefaultActions", [])
                            # Look for a redirect action to HTTPS
                            redirect_ok = any(
                                a.get("Type") == "redirect" and
                                a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
                                for a in actions
                            )
                            if not redirect_ok:
                                findings.append(
                                    (lb_name,
                                     f"Listener on port {listener['Port']} does not redirect to HTTPS")
                                )
        except Exception as e:
            findings.append(("ALB", f"Error checking HTTP→HTTPS redirects: {e}"))

        return findings
