# File: aws_auto_security/core/runner.py

import os
import json
import importlib
import sys
import concurrent.futures
from botocore.config import Config

from aws_auto_security.utils import get_session

class Runner:
    """
    Discover and execute all check plugins under checks/<service>/<check>/,
    using each check's metadata.json for ID, name, category, advice, and color.
    Applies per-call timeouts automatically to all boto3 clients, wraps each
    plugin.run in a thread with a timeout, and handles Ctrl-C gracefully.
    """
    # seconds to allow each plugin.run before giving up
    PLUGIN_TIMEOUT = 5

    def __init__(self, profile=None, region=None):
        # Create a Config with timeouts and retries
        self.client_config = Config(
            connect_timeout=6,
            read_timeout=10,
            retries={'max_attempts': 0}
        )

        # Initialize boto3 Session
        self.session = get_session(profile, region)

        # Monkey-patch session.client so every client gets our timeout Config
        original_client = self.session.client
        def client_with_config(service_name, **kwargs):
            if 'config' not in kwargs:
                kwargs['config'] = self.client_config
            return original_client(service_name, **kwargs)
        self.session.client = client_with_config

        # Discover plugins
        self.plugins = []
        checks_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), '..', 'checks')
        )
        for service in os.listdir(checks_root):
            svc_path = os.path.join(checks_root, service)
            if not os.path.isdir(svc_path):
                continue
            for check in os.listdir(svc_path):
                chk_path = os.path.join(svc_path, check)
                meta_file = os.path.join(chk_path, 'metadata.json')
                if not os.path.isfile(meta_file):
                    continue
                try:
                    with open(meta_file, 'r') as f:
                        meta = json.load(f)
                except json.JSONDecodeError as e:
                    print(f"⚠️ Skipping invalid JSON in {meta_file}: {e}")
                    continue
                meta['module'] = f"aws_auto_security.checks.{service}.{check}.{check}"
                self.plugins.append(meta)

        # Map plugin_id -> metadata
        self.metadata = {p['id']: p for p in self.plugins}

    def list_plugins(self):
        """Print available plugin IDs and names"""
        print("Available checks:")
        for p in self.plugins:
            print(f"  {p['id']}: {p.get('name','<no name>')}")

    def run_all(self, only=None):
        """
        Execute all plugins sequentially without an internal progress bar.
        Returns a list of (check_id, resource_id, description).
        """
        findings = []
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)

        for meta in self.plugins:
            pid = meta['id']
            if only and pid not in only:
                continue

            module_path = meta['module']
            try:
                mod = importlib.import_module(module_path)
            except KeyboardInterrupt:
                executor.shutdown(wait=False)
                raise
            except Exception as e:
                print(f"❌ Failed to load plugin {pid}: {e}")
                continue

            if not hasattr(mod, 'Plugin'):
                print(f"❌ Plugin module {module_path} has no class 'Plugin'")
                continue

            try:
                plugin_obj = mod.Plugin(self.session)
            except Exception as e:
                print(f"❌ Error initializing plugin {pid}: {e}")
                continue

            future = executor.submit(plugin_obj.run)
            try:
                results = future.result(timeout=self.PLUGIN_TIMEOUT)
            except concurrent.futures.TimeoutError:
                future.cancel()
                continue
            except KeyboardInterrupt:
                executor.shutdown(wait=False)
                raise
            except Exception as e:
                errmsg = str(e).lower()
                if 'timeout' in errmsg:
                    continue
                print(f"❌ Error running plugin {pid}: {e}")
                continue

            for item in results or []:
                if not (isinstance(item, (list, tuple)) and len(item) == 2):
                    print(f"❌ Plugin {pid} returned invalid result: {item!r}")
                    continue
                findings.append((pid, item[0], item[1]))

        executor.shutdown(wait=False)
        return findings

    def run_plugin(self, meta):
        """
        Run exactly one plugin (meta dict) under this session,
        applying the same timeout logic. Returns a list of (resource_id, description).
        """
        pid = meta['id']
        try:
            mod = importlib.import_module(meta['module'])
        except Exception as e:
            raise RuntimeError(f"load failed: {e}")

        if not hasattr(mod, 'Plugin'):
            raise RuntimeError("missing Plugin class")

        try:
            plugin = mod.Plugin(self.session)
        except Exception as e:
            raise RuntimeError(f"init failed: {e}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(plugin.run)
            try:
                results = fut.result(timeout=self.PLUGIN_TIMEOUT)
            except concurrent.futures.TimeoutError:
                fut.cancel()
                return []
            except Exception as e:
                raise RuntimeError(f"run failed: {e}")

        valid = []
        for item in results or []:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                valid.append((item[0], item[1]))
        return valid
