# File: aws_auto_security/cli.py

#!/usr/bin/env python3
import sys
import os
# Ensure project root is on PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import Fore, Style, init as _colorama_init

from aws_auto_security.config import DEFAULT_PROFILE, DEFAULT_REGION
from aws_auto_security.utils import init_colors
from aws_auto_security.core.runner import Runner
from aws_auto_security.reporter import report_grouped, dump_json, dump_asff, SEVERITY_MAP

# Initialize colorama so our legend colors actually work
_colorama_init(autoreset=True)

def main():
    init_colors()

    parser = argparse.ArgumentParser(
        description="AWS Auto Security - Plugin-based scanner and advice tool"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # SCAN command
    scan_p = sub.add_parser("scan", help="Run security checks")
    scan_p.add_argument(
        "-p", "--profile",
        help=f"Comma-separated AWS CLI profiles (default: {DEFAULT_PROFILE})"
    )
    scan_p.add_argument(
        "-r", "--region",
        help=f"Comma-separated AWS regions (default: {DEFAULT_REGION})"
    )
    scan_p.add_argument(
        "-l", "--list",
        action="store_true",
        help="List all available check IDs"
    )
    scan_p.add_argument(
        "-o", "--only",
        nargs="+", metavar="CHECK_ID",
        help="Run only these check IDs"
    )
    scan_p.add_argument(
        "-f", "--output-format",
        choices=["text", "json", "asff"],
        default="text",
        help="Output format: text (fancy grouped), json, or asff"
    )
    scan_p.add_argument(
        "-O", "--output-file",
        help="Write output to this file (.log/.txt for text, .json for JSON/ASFF)"
    )

    # ADVISE command (unchanged)
    adv_p = sub.add_parser("advise", help="Generate remediation advice")
    adv_p.add_argument(
        "-i", "--input-file", required=True,
        help="Scanner output file"
    )
    adv_p.add_argument(
        "-o", "--output-file", required=True,
        help="Advice output file"
    )
    adv_p.add_argument(
        "-k", "--api-key", required=True,
        help="OpenAI API key"
    )

    args = parser.parse_args()

    if args.command == "scan":
        # Parse multiple profiles and regions
        profiles = [
            p.strip()
            for p in (args.profile or DEFAULT_PROFILE).split(',')
            if p.strip()
        ]
        regions = [
            r.strip()
            for r in (args.region or DEFAULT_REGION).split(',')
            if r.strip()
        ]

        # If user just wants the list of checks, do that and exit
        if args.list:
            Runner(profiles[0], regions[0]).list_plugins()
            return

        # Instantiate one Runner to grab the plugin list and metadata
        first_runner = Runner(profiles[0], regions[0])
        plugins = first_runner.plugins    # list of all available check metas
        metadata = first_runner.metadata
        all_findings = []

        # Create a single progress bar for the 90 checks
        bar = tqdm(
            plugins,
            desc="Running checks",
            unit="check",
            file=sys.stdout
        )
        start = time.time()

        try:
            for meta in bar:
                pid = meta['id']
                # Run this plugin across all profiles×regions in parallel
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = {
                        executor.submit(Runner(prf, reg).run_plugin, meta): (prf, reg)
                        for prf in profiles
                        for reg in regions
                    }
                    for fut in as_completed(futures):
                        prf, reg = futures[fut]
                        try:
                            results = fut.result()
                        except Exception as e:
                            bar.write(f"❌ {pid}@{prf}/{reg} failed: {e}")
                            continue
                        for resource_id, desc in results or []:
                            all_findings.append((pid, resource_id, desc))

        except KeyboardInterrupt:
            print("\n🛑 Scan aborted; compiling partial results...", file=sys.stderr)
        finally:
            elapsed = round(time.time() - start, 2)
            bar.close()

        # Print legend to stderr so it doesn't clash with stdout report
        legend = "  ".join(
            f"{color}{symbol}{Style.RESET_ALL} = {sev.title()}"
            for sev, (symbol, color) in SEVERITY_MAP.items()
        )
        print(legend, file=sys.stderr)
        print("", file=sys.stderr)

        # Output grouped text report
        report_grouped(all_findings, metadata)

        # Determine base filename
        base = args.output_file or f"cloudwaller-{','.join(profiles)}-{int(start)}"

        # Handle JSON export
        if args.output_format == "json" and all_findings:
            dump_json(
                all_findings,
                metadata,
                base + ".json",
                ','.join(profiles),
                ','.join(regions),
                elapsed
            )

        # Handle ASFF export
        elif args.output_format == "asff" and all_findings:
            dump_asff(
                all_findings,
                metadata,
                base + ".json",
                ','.join(profiles),
                ','.join(regions),
                elapsed,
                first_runner.session
            )

        # Or write the same grouped text into a file if the user requested it
        elif args.output_file and all_findings:
            with open(args.output_file, "w") as f:
                print(legend, file=f)
                report_grouped(all_findings, metadata, out=f)

    else:  # advise
        from aws_auto_security.advise import run_advise
        run_advise(args)


if __name__ == "__main__":
    main()
