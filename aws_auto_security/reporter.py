import sys
import json
import datetime
from collections import OrderedDict
from colorama import Fore, Style, init as _colorama_init
from botocore.exceptions import NoCredentialsError

# initialize colorama once
_colorama_init(autoreset=True)

# severity → (symbol, color)
SEVERITY_MAP = {
    'CRITICAL': ('✗', Fore.RED),
    'HIGH':     ('✗', Fore.RED),
    'MEDIUM':   ('⚠', Fore.YELLOW),
    'LOW':      ('✓', Fore.GREEN),
}

def report_grouped(findings, metadata, out=sys.stdout):
    """
    Print an ASCII-boxed, category-grouped list of findings,
    each prepended with the severity symbol in its color.
    """
    groups = OrderedDict()
    for check_id, resource, desc in findings:
        meta = metadata.get(check_id, {})
        cat = meta.get('category', 'Other')
        sev = meta.get('severity', meta.get('color', 'LOW')).upper()
        symbol, color = SEVERITY_MAP.get(sev, ('?', Fore.WHITE))
        groups.setdefault(cat, []).append((symbol, color, resource, desc))

    for cat, items in groups.items():
        title = f" {cat.upper()} ISSUES ({len(items)}) "
        max_line = max(len(f"{sym} {res}: {desc}") for sym, _, res, desc in items)
        width = max(len(title), max_line) + 2

        print("┌" + "─" * width + "┐", file=out)
        print("│" + title.center(width) + "│", file=out)
        print("├" + "─" * width + "┤", file=out)
        for sym, color, res, desc in items:
            text = f"{sym} {res}: {desc}"
            pad = width - len(text)
            print("│ " + color + text + Style.RESET_ALL + " " * pad + "│", file=out)
        print("└" + "─" * width + "┘\n", file=out)

def dump_json(findings, metadata, output_file, profiles, regions, runtime_seconds):
    """
    Write a JSON report alongside the text report.
    """
    scan_meta = {
        "scanner_name":    "aws-sec-scan",
        "scanner_version": "1.0.0",
        "timestamp":       datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "aws_profiles":    profiles,
        "aws_regions":     regions,
        "runtime_seconds": runtime_seconds
    }

    findings_list = []
    for check_id, resource, desc in findings:
        meta = metadata.get(check_id, {})
        findings_list.append({
            "check_id":    check_id,
            "title":       meta.get("name"),
            "severity":    meta.get("severity", meta.get("color")),
            "service":     meta.get("category"),
            "resource_id": resource,
            "description": desc,
        })

    payload = {
        "scan_metadata": scan_meta,
        "findings":      findings_list,
        "summary": {
            "total_checks":    len(metadata),
            "total_findings":  len(findings),
        }
    }

    with open(output_file, 'w') as f:
        json.dump(payload, f, indent=2)

    print(f"JSON report written to {output_file}", file=sys.stderr)

def dump_asff(findings, metadata, output_file, profiles, regions, runtime_seconds, session):
    """
    Write findings in AWS Security Finding Format (ASFF) for ingestion into Security Hub.
    """
    try:
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
    except NoCredentialsError:
        account_id = "UNKNOWN"
    timestamp = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    asff_payload = []
    for check_id, resource, desc in findings:
        meta = metadata.get(check_id, {})
        finding = {
            "SchemaVersion":   "2018-10-08",
            "Id":              f"{check_id}/{resource}",
            "ProductArn":      f"arn:aws:securityhub:{regions}:{account_id}:product/{account_id}/default",
            "GeneratorId":     "aws-sec-scan",
            "AwsAccountId":    account_id,
            "Types":           ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": timestamp,
            "LastObservedAt":  timestamp,
            "CreatedAt":       timestamp,
            "UpdatedAt":       timestamp,
            "Severity": {
                "Label": meta.get("severity", meta.get("color", "LOW")).upper()
            },
            "Title":       meta.get("name"),
            "Description": desc,
            "Resources": [
                {"Type": meta.get("service", "Other"), "Id": resource}
            ],
            "Compliance":  {"Status": "FAILED"},
            "Workflow":    {"Status": "NEW"}
        }
        asff_payload.append({"AwsSecurityFinding": finding})

    with open(output_file, 'w') as f:
        json.dump(asff_payload, f, indent=2)

    print(f"ASFF report written to {output_file}", file=sys.stderr)
