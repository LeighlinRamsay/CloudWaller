#!/usr/bin/env python3
import sys
import os
# ensure project root is on PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import argparse
import importlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import Fore, Style, init as _colorama_init

from aws_auto_security.config import DEFAULT_PROFILE, DEFAULT_REGION
from aws_auto_security.utils import init_colors
from aws_auto_security.core.runner import Runner
from aws_auto_security.reporter import report_grouped, dump_json, dump_asff, SEVERITY_MAP

# make colorama auto-reset
_colorama_init(autoreset=True)

def _run_one_plugin(runner, meta):
    """
    Import and run a single plugin (unpacked from its metadata).
    Returns list of (resource_id, description).
    """
    pid = meta['id']
    try:
        mod = importlib.import_module(meta['module'])
        plugin = mod.Plugin(runner.session)
        return plugin.run() or []
    except Exception as e:
        print(f"❌ Error in plugin {pid} @ {runner.session.region_name}: {e}", file=sys.stderr)
        return []

def main():
    init_colors()

    p = argparse.ArgumentParser(
        description="AWS Auto Security - Plugin-based scanner and advice tool"
    )
    sub = p.add_subparsers(dest="command", required=True)

    # SCAN subcommand
    scan = sub.add_parser("scan", help="Run security checks")
    scan.add_argument("-p","--profile",
        help=f"Comma-separated AWS CLI profiles (default: {DEFAULT_PROFILE})"
    )
    scan.add_argument("-r","--region",
        help=f"Comma-separated AWS regions (default: {DEFAULT_REGION})"
    )
    scan.add_argument("-l","--list",
        action="store_true",
        help="List all available check IDs"
    )
    scan.add_argument("-o","--only",
        nargs="+", metavar="CHECK_ID",
        help="Run only these check IDs"
    )
    scan.add_argument("-f","--output-format",
        choices=["text","json","asff"], default="text",
        help="Output format: text, json, or asff"
    )
    scan.add_argument("-O","--output-file",
        help="Write output to this file"
    )
    scan.add_argument("--no-output",
        action="store_true",
        help="Suppress console output (still writes files)"
    )
    scan.add_argument("--list-services",
        action="store_true",
        help="List all AWS services that have at least one check"
    )
    scan.add_argument("--services",
        help="Comma-separated AWS service(s) to run checks for"
    )
    scan.add_argument("--skip-services",
        help="Comma-separated AWS service(s) to skip in this scan"
    )

    # ADVISE subcommand
    advise = sub.add_parser("advise", help="Generate remediation advice")
    advise.add_argument("-i","--input-file", required=True, help="Scanner output file")
    advise.add_argument("-o","--output-file",required=True, help="Advice output file")
    advise.add_argument("-k","--api-key",     required=True, help="OpenAI API key")

    args = p.parse_args()

    if args.command == "scan":
        # 1) discover metadata once
        disc = Runner(None, None)
        plugins = disc.plugins

        # 2) skip-services filter
        skip = {s.strip() for s in (args.skip_services or "").split(",") if s.strip()}
        if skip:
            plugins = [m for m in plugins if m.get("service") not in skip]

        # 3) list-services and exit
        if args.list_services:
            services = sorted({m.get("service","<unknown>") for m in plugins})
            print("Available services with checks:")
            for svc in services:
                print("  -", svc)
            return

        # 4) services filter
        inc = {s.strip() for s in (args.services or "").split(",") if s.strip()}
        if inc:
            plugins = [m for m in plugins if m.get("service") in inc]

        # 5) only-IDs filter
        if args.only:
            only_set = set(args.only)
            plugins = [m for m in plugins if m["id"] in only_set]

        # 6) list-checks and exit
        if args.list:
            Runner(None, None).list_plugins()
            return

        # 7) parse profiles & regions
        profiles = [x.strip() for x in (args.profile or DEFAULT_PROFILE).split(",") if x.strip()]
        regions  = [x.strip() for x in (args.region  or DEFAULT_REGION).split(",") if x.strip()]

        # 8) run each plugin in parallel across profiles×regions,
        #    but show a single progress bar over *plugins*
        all_findings = []
        metadata     = {m["id"]:m for m in plugins}
        t0 = time.time()

        bar = tqdm(
            plugins,
            desc="Running checks",
            unit="check",
            file=sys.stderr,
            dynamic_ncols=True
        )

        for meta in bar:
            pid = meta["id"]
            # spawn a small thread‐pool for this one check across all combos
            with ThreadPoolExecutor(max_workers=len(profiles)*len(regions)) as ex:
                futures = []
                for prf in profiles:
                    for reg in regions:
                        runner = Runner(prf, reg)
                        futures.append(ex.submit(_run_one_plugin, runner, meta))

                for fut in as_completed(futures):
                    results = fut.result()
                    for resource, desc in results:
                        all_findings.append((pid, resource, desc))

        bar.close()
        elapsed = round(time.time() - t0, 2)

        # 9) console output
        if not args.no_output:
            # legend
            legend = "  ".join(
                f"{c}{sym}{Style.RESET_ALL} = {sev.title()}"
                for sev,(sym,c) in SEVERITY_MAP.items()
            )
            print(legend, file=sys.stderr)
            print("",    file=sys.stderr)

            # scoring
            WEIGHTS = {"CRITICAL":5,"HIGH":3,"MEDIUM":2,"LOW":1}
            counts = {sev:0 for sev in WEIGHTS}
            for cid,_,_ in all_findings:
                sev = metadata[cid].get("severity","LOW").upper()
                if sev in counts:
                    counts[sev] += 1
            weighted = sum(counts[s]*WEIGHTS[s] for s in counts)
            max_w    = len(metadata)*WEIGHTS["CRITICAL"]
            score    = max(0, min(100, 100 - int((weighted/max_w)*100)))
            grade    = ("A" if score>=90 else
                        "B" if score>=80 else
                        "C" if score>=70 else
                        "D" if score>=60 else "F")

            # grouped report + score
            report_grouped(all_findings, metadata)
            print(
                Fore.MAGENTA +
                f"\nAWS Security Score: {score}/100  (Grade: {grade})\n" +
                Style.RESET_ALL,
                file=sys.stderr
            )

        # 10) file‐based exports
        base = args.output_file or f"cloudwaller-{','.join(profiles)}-{int(t0)}"
        if args.output_format == "json" and all_findings:
            dump_json(
                all_findings, metadata, base+".json",
                ",".join(profiles), ",".join(regions), elapsed
            )
        elif args.output_format == "asff" and all_findings:
            dump_asff(
                all_findings, metadata, base+".json",
                ",".join(profiles), ",".join(regions), elapsed,
                Runner(profiles[0],regions[0]).session
            )
        elif args.output_file and all_findings:
            with open(args.output_file, "w") as f:
                print(legend, file=f)
                report_grouped(all_findings, metadata, out=f)

    else:
        # ADVISE
        from aws_auto_security.advise import run_advise
        run_advise(args)

if __name__ == "__main__":
    main()
