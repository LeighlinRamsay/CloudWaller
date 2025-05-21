# File: aws_auto_security/advise.py

import os
import json
from openai import OpenAI
from tqdm import tqdm
from aws_auto_security.utils import Fore

# Discover metadata directory if needed (not strictly required for advice generation)
# PLUGIN_CHECKS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'checks'))

def run_advise(args):
    """
    Read security issues from a text file, call OpenAI's ChatCompletion API
    to generate step-by-step remediation advice, and either print it or write
    to a file, depending on length and output-file flag.
    """
    # 1) Read the issues file
    with open(args.input_file, 'r') as f:
        issues_text = f.read()

    # 2) Configure the OpenAI client
    client = OpenAI(api_key=args.api_key)

    # 3) Build the prompt
    system_prompt = {
        "role": "system",
        "content": (
            "You are an expert AWS security engineer. "
            "For each reported finding, provide clear, step-by-step remediation instructions."
        )
    }
    user_prompt = {
        "role": "user",
        "content": (
            "The following AWS security issues were detected:\n\n"
            f"{issues_text}\n\n"
            "Please respond with actionable, concise, numbered steps for each issue."
        )
    }

    # 4) Call the API with a progress bar
    with tqdm(total=1, desc="Calling OpenAI API"):
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[system_prompt, user_prompt],
            max_tokens=2048,
            temperature=0.2
        )

    # 5) Extract the advice text
    advice = resp.choices[0].message.content.strip()

    # 6) Decide whether to print inline or write to file
    threshold = 500  # characters threshold for inline display
    if len(advice) <= threshold:
        print(Fore.CYAN + advice)
    else:
        with open(args.output_file, 'w') as f:
            f.write(advice)
        # per user request, only notify when advice is large
        print(Fore.GREEN + f"✅ Advice written to {args.output_file}")
