# AWS Auto Security

**Plugin-based AWS security scanner and advice tool**

AWS Auto Security is an extensible Python CLI that automates 90+ AWS security best-practice checks across one or more AWS CLI profiles and regions.

## Features

- **Plugin Architecture**: Drop new checks into `checks/<service>/<check_id>/` with a `metadata.json` and `Plugin.run()` implementation.  
- **Parallel Scanning**: Executes all checks concurrently for maximum speed with a unified tqdm progress bar.  
- **Multi-Profile & Region**: Supply comma-separated profiles (`-p`) and regions (`-r`) in a single command.  
- **Flexible Output**:  
  - **Text**: Grouped, colored ASCII boxes.  
  - **JSON**: Structured report for automation.  
  - **ASFF**: AWS Security Finding Format for Security Hub ingestion.  
- **Built-in Coverage**: IAM, VPC, EC2, S3, RDS, CloudTrail, Config, Inspector, Security Hub, and more.  
- **Graceful Interrupt**: Ctrl+C safely aborts and compiles partial results.

## Installation

```bash
git clone https://github.com/your-org/aws-auto-security.git
cd aws-auto-security
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan on default profile/region

aws configure --profile CloudWaller

python cli.py scan -p CloudWaller -r us-east-1

# Scan multiple profiles/regions and get JSON
python cli.py scan -p dev,prod -r us-east-1,us-west-2 -f json -O report.json

# ASFF for Security Hub
python cli.py scan -p CloudWaller -r us-east-1 -f asff -O findings-asff.json

# List available checks
python cli.py scan --list
```

## Advise

After running a scan, use the advise command to feed your output into AI for step-by-step remediation instructions:

```bash
python cli.py advise -i scan-output.json -o remediation.txt -k YOUR_OPENAI_API_KEY
```
