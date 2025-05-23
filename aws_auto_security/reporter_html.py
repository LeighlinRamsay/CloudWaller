import os
import datetime
from types import SimpleNamespace
from collections import defaultdict
from jinja2 import Environment, FileSystemLoader

# Directory containing your Jinja2 templates
TEMPLATES_DIR = os.path.join(
    os.path.dirname(__file__),
    'reports', 'templates'
)
# Directory where HTML reports will be written
OUTPUT_DIR = os.path.join(
    os.path.dirname(__file__),
    'reports', 'output'
)

# Initialize Jinja2 environment
env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=True,
)

def generate_html_report(scan_meta, findings, metadata):
    """
    Renders an HTML report from scan results.
    
    scan_meta: dict with keys 'timestamp', 'aws_profiles', 'aws_regions',
               and optionally 'score', 'grade', 'score_color'
    findings:  list of tuples (check_id, resource_id, description)
    metadata:  dict mapping check_id -> plugin metadata
    """
    # 1) Severity counts
    severity_counts = {sev: 0 for sev in ('CRITICAL','HIGH','MEDIUM','LOW')}
    for cid, _, _ in findings:
        sev = metadata[cid].get('severity', 'LOW').upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # 2) Group findings by category
    grouped = defaultdict(list)
    for cid, res, desc in findings:
        cat = metadata[cid].get('category', 'Other')
        grouped[cat].append(
            SimpleNamespace(
                resource=res,
                desc=desc,
                severity=metadata[cid].get('severity','LOW').upper()
            )
        )

    # 3) Map categories → bootstrap colors
    category_color = {
        cat: ('primary' if cat == 'Other' else 'info')
        for cat in grouped.keys()
    }

    # 4) Service distribution counts
    svc_counts = defaultdict(int)
    for cid, _, _ in findings:
        svc = metadata[cid].get('service', '<unknown>')
        svc_counts[svc] += 1

    # 5) Load and render template
    template = env.get_template('scan_report.html')
    rendered = template.render(
        scan_id          = scan_meta['timestamp'].replace(':','').replace('-',''),
        timestamp        = scan_meta['timestamp'],
        profiles         = scan_meta['aws_profiles'],
        regions          = scan_meta['aws_regions'],

        score            = scan_meta.get('score', 0),
        grade            = scan_meta.get('grade', 'F'),
        score_color      = scan_meta.get('score_color', 'dark'),

        severity_labels  = list(severity_counts.keys()),
        severity_counts  = list(severity_counts.values()),

        service_labels   = list(svc_counts.keys()),
        service_counts   = list(svc_counts.values()),

        grouped_findings = grouped,
        category_color   = category_color,
        severity_color   = {
            'CRITICAL': 'danger',
            'HIGH':     'danger',
            'MEDIUM':   'warning',
            'LOW':      'success'
        }
    )

    # 6) Write out to file
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"scan_{scan_meta['timestamp'].replace(':','').replace('-','')}.html"
    out_path = os.path.join(OUTPUT_DIR, filename)
    with open(out_path, 'w') as f:
        f.write(rendered)

    return out_path
