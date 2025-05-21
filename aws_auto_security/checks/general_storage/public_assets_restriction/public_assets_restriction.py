# File: checks/storage/public_assets_restrictions/public_assets_restrictions.py
#!/usr/bin/env python3
"""
Plugin ID: storage_public_assets_restrictions
Description: Flag public-facing buckets or endpoints hosting web assets lacking origin/referer restrictions.
"""

from botocore.exceptions import ClientError

class Plugin:
    def __init__(self, session):
        self.cloudfront = session.client('cloudfront')
        self.s3 = session.client('s3')

    def run(self):
        findings = []
        # CloudFront distributions
        dists = self.cloudfront.list_distributions().get('DistributionList',{}).get('Items',[])
        for d in dists:
            domain = d['DomainName']
            cfg = d['DistributionConfig']
            for origin in cfg.get('Origins',{}).get('Items',[]):
                b = origin['DomainName']
                # check CORS or referer in behaviors
                restricted = False
                for bvr in cfg.get('DefaultCacheBehavior',{}), *cfg.get('CacheBehaviors',{}).get('Items',[]):
                    fr = bvr.get('ViewerProtocolPolicy')
                    # origin/referer restriction check (simplified)
                    if 'Whitelist' in bvr.get('AllowedOrigins',{}):
                        restricted = True
                if not restricted:
                    findings.append((domain, "No origin/referer restrictions on distribution"))
        return findings
