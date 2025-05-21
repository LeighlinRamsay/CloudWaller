# File: aws_auto_security/utils.py

import boto3
from colorama import Fore, Style

def init_colors():
    """
    Placeholder for any color initialization if needed.
    """
    pass

def get_session(profile=None, region=None):
    """
    Create and return a boto3 Session using the given profile and region.
    """
    session_kwargs = {}
    if profile:
        session_kwargs['profile_name'] = profile
    if region:
        session_kwargs['region_name'] = region
    return boto3.Session(**session_kwargs)

def report_findings(findings, metadata):
    """

    NOT USED ANYMORE!!!!

    Print out security findings in the terminal.
    Each finding tuple may be either:
      (check_id, resource_id, description)
    or:
      (region, check_id, resource_id, description)
    We unpack both forms and ignore the region for single-region output.
    
    if not findings:
        print(Fore.GREEN + '✅ No security issues found!' + Style.RESET_ALL)
        return

    print(Fore.RED + '\n⚠️ Security Findings:\n' + Style.RESET_ALL)

    for item in findings:
        # unpack based on tuple length
        if len(item) == 4:
            _region, check_id, resource_id, desc = item
        elif len(item) == 3:
            check_id, resource_id, desc = item
        else:
            # unexpected format; skip
            continue

        # print the finding
        print(Fore.YELLOW + f'• Resource: {resource_id}' + Style.RESET_ALL)
        print(Fore.CYAN + f'  Issue: {desc}' + Style.RESET_ALL)

        # fetch advice from metadata (fallback if missing)
        advice = metadata.get(check_id, {}).get(
            'advice',
            'Refer to AWS best practices for remediation.'
        )
        print(Fore.GREEN + f'  Advice: {advice}' + Style.RESET_ALL)

        # separator
        print(Style.DIM + '-' * 50 + Style.RESET_ALL)"""
