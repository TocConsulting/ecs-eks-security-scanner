#!/usr/bin/env python3
"""Command-line interface for ECS/EKS Security Scanner."""

import logging
import os
import sys
import traceback

import click
from rich.console import Console

from .scanner import ContainerSecurityScanner
from . import __version__

# Configure logging format
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.WARNING,
)

console = Console()

# ASCII Art Banner
BANNER = """[bold red]╔═══════════════════════════════════════════════════════╗
║            ECS/EKS Security Scanner                   ║
║      Comprehensive Container Security Auditing        ║
╚═══════════════════════════════════════════════════════╝[/bold red]"""


def print_banner():
    """Print the ASCII art banner."""
    console.print(BANNER)
    console.print(
        f"[dim]  Version {__version__} | "
        "https://github.com/TocConsulting/"
        "ecs-eks-security-scanner[/dim]\n"
    )


# ====================================================================
# SHARED OPTIONS (composable decorators)
# ====================================================================


def shared_aws_options(f):
    """AWS connection options shared across commands."""
    f = click.option(
        "-r", "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)",
    )(f)
    f = click.option(
        "-p", "--profile",
        default=None,
        help="AWS profile name",
    )(f)
    return f


def shared_output_options(f):
    """Output options shared across commands."""
    f = click.option(
        "-o", "--output-dir",
        default="./output",
        help="Directory for output files (default: ./output)",
    )(f)
    f = click.option(
        "-f", "--output-format",
        type=click.Choice(
            ["json", "csv", "html", "all"],
            case_sensitive=False,
        ),
        default="all",
        help="Report format (default: all)",
    )(f)
    return f


def shared_performance_options(f):
    """Performance and logging options shared across commands."""
    f = click.option(
        "-w", "--max-workers",
        default=5,
        type=click.IntRange(1, 50),
        help="Worker threads for parallel scanning (default: 5, max: 50)",
    )(f)
    f = click.option(
        "-q", "--quiet",
        is_flag=True,
        help="Suppress console output except errors",
    )(f)
    f = click.option(
        "-d", "--debug",
        is_flag=True,
        help="Enable debug logging",
    )(f)
    return f


def shared_options(f):
    """Apply all shared options to a command."""
    f = shared_aws_options(f)
    f = shared_output_options(f)
    f = shared_performance_options(f)
    return f


# ====================================================================
# MAIN CLI GROUP
# ====================================================================


class CustomGroup(click.Group):
    """Custom Click group with banner display."""

    def format_help(self, ctx, formatter):
        """Write the help into the formatter with banner."""
        print_banner()
        super().format_help(ctx, formatter)


@click.group(
    cls=CustomGroup,
    context_settings=dict(help_option_names=["-h", "--help"]),
)
@click.version_option(
    version=__version__,
    prog_name="ECS/EKS Security Scanner",
)
def cli():
    """
    Comprehensive AWS ECS/EKS security scanner for vulnerability
    detection and multi-framework compliance auditing.

    \b
    FRAMEWORKS
    ══════════════════════════════════════════════════════════════
      AWS-FSBP, CIS EKS v2.0.0, EKS-Hardening, PCI DSS v4.0.1,
      HIPAA, SOC 2, ISO 27001:2022, ISO 27017, ISO 27018,
      GDPR, NIST 800-53

    \b
    QUICK START
    ══════════════════════════════════════════════════════════════
      Scan all:       ecs-eks-security-scanner security
      ECS only:       ecs-eks-security-scanner security -s ecs
      EKS only:       ecs-eks-security-scanner security -s eks
      AWS profile:    ecs-eks-security-scanner security -p prod
      Specific region: ecs-eks-security-scanner security -r eu-west-1

    \b
    MORE INFO
    ══════════════════════════════════════════════════════════════
      Run COMMAND --help for detailed options
      Docs: https://github.com/TocConsulting/ecs-eks-security-scanner
    """
    pass


# ====================================================================
# SECURITY COMMAND
# ====================================================================


@cli.command()
@click.option(
    "--service", "-s",
    type=click.Choice(
        ["ecs", "eks", "all"], case_sensitive=False,
    ),
    default="all",
    help="Service to scan (default: all)",
)
@click.option(
    "--cluster", "-c",
    multiple=True,
    help="Specific cluster name(s)/ARN(s) to scan",
)
@click.option(
    "--exclude-cluster",
    multiple=True,
    help="Cluster name(s)/ARN(s) to exclude",
)
@click.option(
    "--compliance-only",
    is_flag=True,
    help="Generate compliance report only",
)
@shared_options
def security(
    service, cluster, exclude_cluster, compliance_only,
    region, profile, output_dir, output_format,
    max_workers, quiet, debug,
):
    """
    Scan ECS/EKS clusters for security vulnerabilities
    and compliance issues.

    \b
    Runs 45 security checks across 8 categories and evaluates
    compliance against 11 frameworks with 128 controls.

    \b
    EXAMPLES:
      ecs-eks-security-scanner security
      ecs-eks-security-scanner security -s ecs -p prod
      ecs-eks-security-scanner security -s eks -r us-west-2
      ecs-eks-security-scanner security -c my-cluster
      ecs-eks-security-scanner security --exclude-cluster dev
      ecs-eks-security-scanner security --compliance-only
      ecs-eks-security-scanner security -f html -o ./reports
    """
    # Configure logging
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger(
            "ecs_eks_security_scanner"
        ).setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)

    if not quiet:
        print_banner()
        console.print(
            "[bold cyan]Starting container security "
            "analysis...[/bold cyan]\n"
        )

    try:
        # Initialize scanner
        scanner = ContainerSecurityScanner(
            region=region,
            profile=profile,
            output_dir=output_dir,
            max_workers=max_workers,
        )

        # Collect clusters
        ecs_clusters = []
        eks_clusters = []

        if service in ("ecs", "all"):
            ecs_clusters = scanner.get_ecs_clusters()
        if service in ("eks", "all"):
            eks_clusters = scanner.get_eks_clusters()

        # Apply --cluster filters
        if cluster:
            cluster_set = set(cluster)
            ecs_clusters = [
                c for c in ecs_clusters
                if (
                    c.get("clusterName") in cluster_set
                    or c.get("clusterArn") in cluster_set
                )
            ]
            eks_clusters = [
                c for c in eks_clusters
                if c.get("name") in cluster_set
            ]

        # Apply --exclude-cluster filters
        if exclude_cluster:
            exclude_set = set(exclude_cluster)
            original_ecs = len(ecs_clusters)
            original_eks = len(eks_clusters)
            ecs_clusters = [
                c for c in ecs_clusters
                if (
                    c.get("clusterName") not in exclude_set
                    and c.get("clusterArn") not in exclude_set
                )
            ]
            eks_clusters = [
                c for c in eks_clusters
                if c.get("name") not in exclude_set
            ]
            excluded = (
                (original_ecs - len(ecs_clusters))
                + (original_eks - len(eks_clusters))
            )
            if not quiet and excluded > 0:
                console.print(
                    f"[yellow]Excluded {excluded} "
                    f"cluster(s)[/yellow]"
                )

        total = len(ecs_clusters) + len(eks_clusters)
        if total == 0:
            console.print(
                "[red]No clusters found to scan[/red]"
            )
            sys.exit(1)

        if not quiet:
            console.print(
                f"[green]Scanning {len(ecs_clusters)} ECS "
                f"+ {len(eks_clusters)} EKS cluster(s)..."
                f"[/green]\n"
            )

        # Perform scan
        results = scanner.scan_all_clusters(
            ecs_clusters=ecs_clusters,
            eks_clusters=eks_clusters,
        )

        if not results:
            console.print("[red]No results generated[/red]")
            sys.exit(1)

        # Generate reports
        report_files = scanner.generate_reports(
            results, output_format
        )

        if not quiet:
            if compliance_only:
                _print_compliance_detail(results)
            else:
                scanner.print_summary(results)

            console.print(
                "\n[bold green]Reports Generated:"
                "[/bold green]"
            )
            for report_type, file_path in report_files.items():
                console.print(
                    f"  {report_type.upper()}: {file_path}"
                )

        console.print(
            "\n[bold green]Security scan completed "
            "successfully![/bold green]"
        )
        console.print(
            f"[dim]Reports saved to: {output_dir}[/dim]"
        )

        # Exit code based on finding severity
        # (exit 2 = CRITICAL findings, exit 3 = HIGH findings)
        has_critical = any(
            any(
                i.get("severity") == "CRITICAL"
                for i in r.get("issues", [])
            )
            for r in results
            if not r.get("scan_error", False)
        )
        has_high = any(
            any(
                i.get("severity") == "HIGH"
                for i in r.get("issues", [])
            )
            for r in results
            if not r.get("scan_error", False)
        )
        if has_critical:
            sys.exit(2)
        elif has_high:
            sys.exit(3)

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Scan interrupted by user[/yellow]"
        )
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/red]")
        if debug:
            console.print(
                f"[red]{traceback.format_exc()}[/red]"
            )
        sys.exit(1)


def _print_compliance_detail(results):
    """Print detailed compliance information."""
    from rich.table import Table

    frameworks = [
        "AWS-FSBP", "CIS-EKS-v2.0", "EKS-Hardening",
        "PCI-DSS-v4.0.1", "HIPAA", "SOC2",
        "ISO27001", "ISO27017", "ISO27018",
        "GDPR", "NIST-800-53",
    ]

    valid = [
        r for r in results
        if not r.get("scan_error", False)
    ]

    for fw in frameworks:
        # Collect failed controls across all clusters
        all_failed = {}
        for r in valid:
            fw_status = r.get(
                "compliance_status", {}
            ).get(fw, {})
            for ctrl in fw_status.get("failed", []):
                ctrl_id = ctrl["control_id"]
                if ctrl_id not in all_failed:
                    all_failed[ctrl_id] = {
                        "description": ctrl["description"],
                        "severity": ctrl.get(
                            "severity", "MEDIUM"
                        ),
                        "clusters": [],
                    }
                all_failed[ctrl_id]["clusters"].append(
                    r.get("cluster_name", "")
                )

        if all_failed:
            table = Table(
                title=f"{fw} - Failed Controls"
            )
            table.add_column(
                "Control", style="cyan", width=15
            )
            table.add_column("Description", width=40)
            table.add_column("Severity", width=10)
            table.add_column(
                "Affected", justify="right", width=10
            )

            for ctrl_id, info in sorted(
                all_failed.items()
            ):
                table.add_row(
                    ctrl_id,
                    info["description"],
                    info["severity"],
                    str(len(info["clusters"])),
                )

            console.print(table)


# For backward compatibility with entry point
main = cli


if __name__ == "__main__":
    cli()
