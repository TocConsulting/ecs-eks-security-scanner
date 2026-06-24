"""Logging & Monitoring Security Checker - G.1-G.4."""

from typing import Dict, Any

from botocore.exceptions import ClientError

from .base import BaseChecker


class LoggingMonitoringChecker(BaseChecker):
    """Check logging and monitoring configuration.

    G.1 (container logging) is an alias for B.6 - evaluated
    in ECSTaskChecker and shared via the checks dict.

    G.2 (Container Insights) is an alias for A.1 - evaluated
    in ECSClusterChecker and shared via the checks dict.
    """

    def _check_guardduty(
        self, region: str
    ) -> Dict[str, Any]:
        """Internal - query GuardDuty detector features."""
        try:
            client = self.get_client("guardduty", region)
            paginator = client.get_paginator(
                "list_detectors"
            )
            detector_ids = []
            for page in paginator.paginate():
                detector_ids.extend(
                    page.get("DetectorIds", [])
                )

            if not detector_ids:
                return {
                    "enabled": False,
                    "ecs_runtime_monitoring": False,
                    "eks_audit_monitoring": False,
                    "eks_runtime_monitoring": False,
                }

            # A region may legitimately host multiple
            # detectors (rare, but allowed). Take the union
            # of enabled features across all of them so we
            # don't miss runtime monitoring just because the
            # first detector listed happens to be a stale
            # one.
            status = "DISABLED"
            features = []
            for detector_id in detector_ids:
                resp = client.get_detector(
                    DetectorId=detector_id
                )
                if resp.get("Status") == "ENABLED":
                    status = "ENABLED"
                features.extend(resp.get("Features", []))

            ecs_runtime = False
            eks_audit = False
            eks_runtime = False

            for feature in features:
                name = feature.get("Name", "")
                feat_status = feature.get(
                    "Status", "DISABLED"
                )
                if (
                    name == "RUNTIME_MONITORING"
                    and feat_status == "ENABLED"
                ):
                    additional = feature.get(
                        "AdditionalConfiguration", []
                    )
                    for ac in additional:
                        ac_name = ac.get("Name", "")
                        ac_status = ac.get(
                            "Status", "DISABLED"
                        )
                        if (
                            ac_name
                            == "ECS_FARGATE_AGENT_MANAGEMENT"
                            and ac_status == "ENABLED"
                        ):
                            ecs_runtime = True
                        # EKS_ADDON_MANAGEMENT covers EKS
                        # Fargate / managed-addon installs.
                        # EC2_AGENT_MANAGEMENT covers EKS
                        # clusters with managed-EC2 node
                        # groups. Either path qualifies as
                        # "EKS runtime monitoring on".
                        if (
                            ac_name in (
                                "EKS_ADDON_MANAGEMENT",
                                "EC2_AGENT_MANAGEMENT",
                            )
                            and ac_status == "ENABLED"
                        ):
                            eks_runtime = True
                elif (
                    name == "EKS_AUDIT_LOGS"
                    and feat_status == "ENABLED"
                ):
                    eks_audit = True

            return {
                "enabled": status == "ENABLED",
                "ecs_runtime_monitoring": ecs_runtime,
                "eks_audit_monitoring": eks_audit,
                "eks_runtime_monitoring": eks_runtime,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "enabled": False,
                "ecs_runtime_monitoring": False,
                "eks_audit_monitoring": False,
                "eks_runtime_monitoring": False,
            })
        except Exception as e:
            self.logger.warning(
                f"GuardDuty check failed: {e}"
            )
            return {
                "enabled": False,
                "ecs_runtime_monitoring": False,
                "eks_audit_monitoring": False,
                "eks_runtime_monitoring": False,
                "error": str(e),
            }

    def check_guardduty(
        self, region: str
    ) -> Dict[str, Any]:
        """G.3 - Check GuardDuty ECS/EKS features enabled.

        Returns a single dict with both ECS and EKS
        runtime/audit feature flags so callers can decide
        which fields are relevant.
        """
        return self._check_guardduty(region)

    # Backwards-compatible aliases retained for the scanner
    # facade. They all return the same shape.
    check_guardduty_ecs = check_guardduty
    check_guardduty_eks = check_guardduty

    def check_vpc_flow_logs(
        self, cluster_arn: str, region: str
    ) -> Dict[str, Any]:
        """G.4 - Check VPC Flow Logs enabled for the
        cluster's VPC."""
        try:
            if not cluster_arn:
                return {"enabled": False}

            vpc_id = None

            # Determine VPC from cluster type
            if ":cluster/" in cluster_arn:
                # ECS cluster - get VPC from services
                # network config
                try:
                    ecs = self.get_client("ecs", region)
                    svc_resp = ecs.list_services(
                        cluster=cluster_arn, maxResults=1
                    )
                    svc_arns = svc_resp.get(
                        "serviceArns", []
                    )
                    if svc_arns:
                        desc = ecs.describe_services(
                            cluster=cluster_arn,
                            services=svc_arns[:1],
                        )
                        for svc in desc.get("services", []):
                            net = svc.get(
                                "networkConfiguration", {}
                            )
                            awsvpc = net.get(
                                "awsvpcConfiguration", {}
                            )
                            subnets = awsvpc.get(
                                "subnets", []
                            )
                            if subnets:
                                ec2 = self.get_client(
                                    "ec2", region
                                )
                                sub_resp = (
                                    ec2.describe_subnets(
                                        SubnetIds=subnets[:1]
                                    )
                                )
                                for sub in sub_resp.get(
                                    "Subnets", []
                                ):
                                    vpc_id = sub.get("VpcId")
                                    break
                except ClientError:
                    pass
            else:
                # EKS cluster - get VPC from cluster config
                try:
                    cluster_name = cluster_arn.split("/")[-1]
                    eks = self.get_client("eks", region)
                    resp = eks.describe_cluster(
                        name=cluster_name
                    )
                    vpc_config = resp.get(
                        "cluster", {}
                    ).get("resourcesVpcConfig", {})
                    vpc_id = vpc_config.get("vpcId")
                except ClientError:
                    pass

            if not vpc_id:
                return {
                    "enabled": False,
                    "flow_log_count": 0,
                }

            client = self.get_client("ec2", region)
            paginator = client.get_paginator(
                "describe_flow_logs"
            )
            flow_logs = []
            for page in paginator.paginate(
                Filters=[{
                    "Name": "resource-id",
                    "Values": [vpc_id],
                }]
            ):
                flow_logs.extend(page.get("FlowLogs", []))
            active_logs = [
                fl for fl in flow_logs
                if fl.get("FlowLogStatus") == "ACTIVE"
            ]
            return {
                "enabled": len(active_logs) > 0,
                "flow_log_count": len(active_logs),
                "vpc_id": vpc_id,
            }
        except ClientError as e:
            return self.handle_client_error(e, {
                "enabled": False,
                "flow_log_count": 0,
            })
        except Exception as e:
            self.logger.warning(
                f"VPC Flow Logs check failed: {e}"
            )
            return {
                "enabled": False,
                "flow_log_count": 0,
                "error": str(e),
            }
