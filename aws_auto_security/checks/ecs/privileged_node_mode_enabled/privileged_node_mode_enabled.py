from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.ecs = session.client("ecs")

    def run(self):
        findings = []
        try:
            # List all ECS clusters
            paginator = self.ecs.get_paginator("list_clusters")
            clusters = []
            for page in paginator.paginate():
                clusters.extend(page.get("clusterArns", []))

            for cluster in clusters:
                # List all tasks in the cluster
                task_paginator = self.ecs.get_paginator("list_tasks")
                for tpage in task_paginator.paginate(cluster=cluster):
                    for task_arn in tpage.get("taskArns", []):
                        # Describe the task to get its definition
                        desc = self.ecs.describe_tasks(
                            cluster=cluster,
                            tasks=[task_arn]
                        )
                        for task in desc.get("tasks", []):
                            td_arn = task.get("taskDefinitionArn")
                            td = self.ecs.describe_task_definition(
                                taskDefinition=td_arn
                            )
                            for cd in td.get("taskDefinition", {}).get("containerDefinitions", []):
                                if cd.get("privileged"):
                                    findings.append(
                                        (
                                            task_arn,
                                            f"Container '{cd.get('name')}' in task '{task_arn}' (cluster '{cluster}') is running in privileged mode"
                                        )
                                    )
        except ClientError as e:
            findings.append(("ECS", f"Error checking privileged containers: {e}"))
        except Exception as e:
            findings.append(("ECS", f"Unexpected error: {e}"))
        return findings
