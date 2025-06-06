"""
EDR Windows Agent - Process Monitor (FIXED)
"""

import os
import time
import psutil
import logging
import threading
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Callable, Optional
import win32api
import win32con
import win32process
import win32security

class ProcessMonitor:
    """Monitors process activities on Windows system"""
    
    def __init__(self, config, event_callback: Callable):
        self.config = config
        self.event_callback = event_callback
        self.logger = logging.getLogger(__name__)
        
        # Monitoring state
        self.running = False
        self.monitor_thread = None
        
        # Process tracking
        self.known_processes = {}  # PID -> ProcessInfo
        self.suspicious_processes = set(config.get('process_monitoring', 'suspicious_processes', []))
        
        # Configuration
        self.monitor_interval = config.get('monitoring', 'interval', 5)
        self.monitor_creation = config.get('process_monitoring', 'monitor_creation', True)
        self.monitor_termination = config.get('process_monitoring', 'monitor_termination', True)
        self.monitor_injection = config.get('process_monitoring', 'monitor_injection', True)
        
        # FIXED: Add process tracking cache
        self.process_cache = {}
        self.cache_timeout = 300  # 5 minutes
        
        self.logger.info("✅ Process monitor initialized")
    
    def start(self):
        """Start process monitoring"""
        try:
            if self.running:
                return
                
            self.running = True
            
            # Initialize known processes
            self._initialize_process_list()
            
            # Start monitoring thread
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            
            self.logger.info("🔍 Process monitoring started")
            
        except Exception as e:
            self.logger.error(f"Failed to start process monitor: {e}")
            raise
    
    def stop(self):
        """Stop process monitoring"""
        try:
            self.running = False
            
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=5)
            
            self.logger.info("🛑 Process monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping process monitor: {e}")
    
    def is_running(self) -> bool:
        """Check if monitor is running"""
        return self.running and (self.monitor_thread and self.monitor_thread.is_alive())
    
    def _initialize_process_list(self):
        """Initialize list of current processes"""
        try:
            current_processes = {}
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
                try:
                    pinfo = proc.info
                    if pinfo['pid'] == 0:  # Skip system idle process
                        continue
                        
                    current_processes[pinfo['pid']] = {
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'exe': pinfo['exe'],
                        'cmdline': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else '',
                        'create_time': pinfo['create_time'],
                        'first_seen': datetime.utcnow()
                    }
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            self.known_processes = current_processes
            self.logger.info(f"📊 Initialized with {len(current_processes)} existing processes")
            
        except Exception as e:
            self.logger.error(f"Error initializing process list: {e}")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._check_process_changes()
                
                # FIXED: Clean cache periodically
                self._cleanup_cache()
                
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                self.logger.error(f"Error in process monitor loop: {e}")
                time.sleep(5)
    
    def _check_process_changes(self):
        """Check for process creation and termination"""
        try:
            current_processes = {}
            
            # Get current process list
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
                try:
                    pinfo = proc.info
                    if pinfo['pid'] == 0:
                        continue
                    
                    # FIXED: Better error handling for process information
                    try:
                        parent_pid = proc.ppid()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        parent_pid = None
                    
                    try:
                        username = self._get_process_user(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        username = None
                    
                    try:
                        cpu_percent = proc.cpu_percent()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        cpu_percent = 0.0
                    
                    try:
                        memory_info = proc.memory_info()._asdict()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        memory_info = {'rss': 0, 'vms': 0}
                        
                    current_processes[pinfo['pid']] = {
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'exe': pinfo['exe'],
                        'cmdline': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else '',
                        'create_time': pinfo['create_time'],
                        'parent_pid': parent_pid,
                        'username': username,
                        'cpu_percent': cpu_percent,
                        'memory_info': memory_info,
                        'hash': self._get_file_hash_cached(pinfo['exe']) if pinfo['exe'] else None
                    }
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Check for new processes (creation)
            if self.monitor_creation:
                new_pids = set(current_processes.keys()) - set(self.known_processes.keys())
                for pid in new_pids:
                    self._handle_process_creation(current_processes[pid])
            
            # Check for terminated processes
            if self.monitor_termination:
                terminated_pids = set(self.known_processes.keys()) - set(current_processes.keys())
                for pid in terminated_pids:
                    self._handle_process_termination(self.known_processes[pid])
            
            # Update known processes
            self.known_processes = current_processes
            
        except Exception as e:
            self.logger.error(f"Error checking process changes: {e}")
    
    def _handle_process_creation(self, process_info: Dict[str, Any]):
        """Handle process creation event"""
        try:
            # FIXED: Better suspicious process detection
            is_suspicious, detection_reasons = self._analyze_process_suspicious(process_info)
            
            event_data = {
                'event_type': 'process_created',
                'process_id': process_info['pid'],
                'parent_process_id': process_info.get('parent_pid'),
                'process_name': process_info['name'],
                'command_line': process_info['cmdline'],
                'executable_path': process_info['exe'],
                'username': process_info.get('username'),
                'cpu_usage': process_info.get('cpu_percent', 0),
                'memory_usage': process_info.get('memory_info', {}).get('rss', 0),
                'hash': process_info.get('hash'),
                'create_time': process_info['create_time'],
                'is_suspicious': is_suspicious,
                'detection_reasons': detection_reasons
            }
            
            # Send event to agent
            self.event_callback(event_data)
            
            # Log suspicious processes
            if is_suspicious:
                self.logger.warning(f"🚨 Suspicious process created: {process_info['name']} (PID: {process_info['pid']}) - {', '.join(detection_reasons)}")
            else:
                self.logger.debug(f"➕ Process created: {process_info['name']} (PID: {process_info['pid']})")
                
        except Exception as e:
            self.logger.error(f"Error handling process creation: {e}")
    
    def _handle_process_termination(self, process_info: Dict[str, Any]):
        """Handle process termination event"""
        try:
            event_data = {
                'event_type': 'process_terminated',
                'process_id': process_info['pid'],
                'process_name': process_info['name'],
                'executable_path': process_info['exe'],
                'first_seen': process_info.get('first_seen', datetime.utcnow()).isoformat()
            }
            
            # Send event to agent
            self.event_callback(event_data)
            
            self.logger.debug(f"➖ Process terminated: {process_info['name']} (PID: {process_info['pid']})")
            
        except Exception as e:
            self.logger.error(f"Error handling process termination: {e}")
    
    def _analyze_process_suspicious(self, process_info: Dict[str, Any]) -> tuple[bool, List[str]]:
        """Analyze if process is suspicious and return reasons"""
        detection_reasons = []
        
        try:
            process_name = process_info['name'].lower()
            cmdline = process_info['cmdline'].lower()
            exe_path = process_info['exe']
            
            # Check against suspicious process names
            if process_name in [p.lower() for p in self.suspicious_processes]:
                detection_reasons.append("suspicious_process_name")
            
            # Check for suspicious command line patterns
            suspicious_patterns = [
                ('powershell -enc', 'encoded_powershell'),
                ('powershell -e ', 'encoded_powershell'),
                ('powershell.exe -w hidden', 'hidden_powershell'),
                ('cmd /c echo', 'suspicious_cmd'),
                ('wmic process', 'wmi_process_access'),
                ('net user', 'user_enumeration'),
                ('net localgroup', 'group_enumeration'),
                ('reg add', 'registry_modification'),
                ('schtasks /create', 'scheduled_task_creation'),
                ('whoami', 'user_discovery'),
                ('systeminfo', 'system_discovery'),
                ('tasklist', 'process_discovery'),
                ('netstat', 'network_discovery'),
                ('ipconfig', 'network_discovery')
            ]
            
            for pattern, reason in suspicious_patterns:
                if pattern in cmdline:
                    detection_reasons.append(reason)
            
            # Check for execution from suspicious locations
            if exe_path:
                suspicious_paths = [
                    ('temp', 'temp_directory'),
                    ('appdata\\local\\temp', 'temp_directory'),
                    ('downloads', 'downloads_directory'),
                    ('public', 'public_directory'),
                    ('programdata', 'programdata_directory'),
                    ('\\users\\public', 'public_directory'),
                    ('recycle.bin', 'recycle_bin'),
                    ('$recycle.bin', 'recycle_bin')
                ]
                
                exe_path_lower = exe_path.lower()
                for path, reason in suspicious_paths:
                    if path in exe_path_lower:
                        detection_reasons.append(reason)
            
            # Check for unsigned executables in system locations
            if exe_path and ('system32' in exe_path.lower() or 'syswow64' in exe_path.lower()):
                if not self._is_file_signed(exe_path):
                    detection_reasons.append("unsigned_system_binary")
            
            # Check for process hollowing indicators
            if process_info.get('parent_pid'):
                try:
                    parent_proc = psutil.Process(process_info['parent_pid'])
                    parent_name = parent_proc.name().lower()
                    
                    # Suspicious parent-child relationships
                    suspicious_parents = {
                        'svchost.exe': ['cmd.exe', 'powershell.exe', 'wmic.exe'],
                        'winlogon.exe': ['cmd.exe', 'powershell.exe'],
                        'lsass.exe': ['cmd.exe', 'powershell.exe'],
                        'csrss.exe': ['cmd.exe', 'powershell.exe']
                    }
                    
                    if parent_name in suspicious_parents:
                        if process_name in suspicious_parents[parent_name]:
                            detection_reasons.append("suspicious_parent_child")
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Check for common malware names
            malware_indicators = [
                'backdoor', 'trojan', 'keylog', 'rootkit', 'botnet',
                'stealer', 'miner', 'ransomware', 'crypter', 'loader'
            ]
            
            for indicator in malware_indicators:
                if indicator in process_name or indicator in cmdline:
                    detection_reasons.append("malware_indicator")
                    break
            
            # Check for living-off-the-land binaries (LOLBins) abuse
            lolbins_abuse = {
                'regsvr32.exe': ['scrobj.dll', '/s', '/u', '/i:http'],
                'rundll32.exe': ['javascript:', 'vbscript:', '/c'],
                'mshta.exe': ['http', 'javascript:', 'vbscript:'],
                'certutil.exe': ['-urlcache', '-split', '-f', 'http'],
                'bitsadmin.exe': ['/transfer', '/download'],
                'wmic.exe': ['process', 'call', 'create']
            }
            
            for binary, indicators in lolbins_abuse.items():
                if binary in process_name:
                    if any(indicator in cmdline for indicator in indicators):
                        detection_reasons.append("lolbins_abuse")
                        break
            
            return len(detection_reasons) > 0, detection_reasons
            
        except Exception as e:
            self.logger.error(f"Error analyzing suspicious process: {e}")
            return False, []
    
    def _get_process_user(self, proc: psutil.Process) -> Optional[str]:
        """Get process owner username"""
        try:
            return proc.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return None
    
    def _get_file_hash_cached(self, file_path: str) -> Optional[str]:
        """Calculate SHA256 hash of file with caching"""
        try:
            if not file_path or not os.path.exists(file_path):
                return None
            
            # Check cache first
            file_stat = os.stat(file_path)
            cache_key = f"{file_path}_{file_stat.st_mtime}_{file_stat.st_size}"
            
            if cache_key in self.process_cache:
                return self.process_cache[cache_key]['hash']
            
            # Calculate hash
            file_hash = self._get_file_hash(file_path)
            
            # Store in cache
            self.process_cache[cache_key] = {
                'hash': file_hash,
                'timestamp': time.time()
            }
            
            return file_hash
            
        except Exception as e:
            self.logger.debug(f"Error getting cached hash for {file_path}: {e}")
            return None
    
    def _get_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate SHA256 hash of file"""
        try:
            if not file_path or not os.path.exists(file_path):
                return None
            
            # FIXED: Check file size before hashing
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:  # Skip files larger than 50MB
                return f"large_file_{file_size}"
            
            # FIXED: Handle locked/permission denied files
            try:
                hash_sha256 = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_sha256.update(chunk)
                
                return hash_sha256.hexdigest()
                
            except (OSError, PermissionError, IOError) as e:
                self.logger.debug(f"Cannot hash file {file_path}: {e}")
                return f"error_{str(e)[:20]}"
            
        except Exception as e:
            self.logger.error(f"Unexpected error hashing {file_path}: {e}")
            return None
    
    def _is_file_signed(self, file_path: str) -> bool:
        """Check if file is digitally signed"""
        try:
            # FIXED: Implement basic signature check
            if not os.path.exists(file_path):
                return False
            
            # Use PowerShell to check signature (simplified)
            import subprocess
            
            ps_command = f'Get-AuthenticodeSignature "{file_path}" | Select-Object Status'
            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return 'Valid' in result.stdout
            
            return False
            
        except Exception:
            return False
    
    def _cleanup_cache(self):
        """Clean up old cache entries"""
        try:
            current_time = time.time()
            expired_keys = [
                key for key, value in self.process_cache.items()
                if current_time - value['timestamp'] > self.cache_timeout
            ]
            
            for key in expired_keys:
                del self.process_cache[key]
                
            if expired_keys:
                self.logger.debug(f"🧹 Cleaned up {len(expired_keys)} cache entries")
                
        except Exception as e:
            self.logger.error(f"Error cleaning cache: {e}")
    
    def get_process_list(self) -> List[Dict[str, Any]]:
        """Get current process list"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
                try:
                    pinfo = proc.info
                    if pinfo['pid'] == 0:
                        continue
                    
                    # FIXED: Better error handling
                    try:
                        parent_pid = proc.ppid()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        parent_pid = None
                    
                    try:
                        username = self._get_process_user(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        username = None
                    
                    try:
                        cpu_percent = proc.cpu_percent()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        cpu_percent = 0.0
                    
                    try:
                        memory_mb = proc.memory_info().rss / 1024 / 1024
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        memory_mb = 0.0
                    
                    try:
                        status = proc.status()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        status = 'unknown'
                        
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'exe': pinfo['exe'],
                        'cmdline': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else '',
                        'create_time': pinfo['create_time'],
                        'parent_pid': parent_pid,
                        'username': username,
                        'cpu_percent': cpu_percent,
                        'memory_mb': memory_mb,
                        'status': status
                    })
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            return processes
            
        except Exception as e:
            self.logger.error(f"Error getting process list: {e}")
            return []
    
    def get_process_info(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get detailed info for specific process"""
        try:
            proc = psutil.Process(pid)
            
            # FIXED: Better error handling for each field
            result = {'pid': proc.pid}
            
            try:
                result['name'] = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result['name'] = 'unknown'
            
            try:
                result['exe'] = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result['exe'] = None
            
            try:
                result['cmdline'] = ' '.join(proc.cmdline())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result['cmdline'] = ''
            
            try:
                result['create_time'] = proc.create_time()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result['create_time'] = 0
            
            try:
                result['parent_pid'] = proc.ppid()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result['parent_pid'] = None
            
            try:
                result['username'] = self._get_process_user(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result['username'] = None
            
            try:
                result['cpu_percent'] = proc.cpu_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result['cpu_percent'] = 0.0
            
            try:
                result['memory_info'] = proc.memory_info()._asdict()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result['memory_info'] = {'rss': 0, 'vms': 0}
            
            try:
                result['status'] = proc.status()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result['status'] = 'unknown'
            
            try:
                result['num_threads'] = proc.num_threads()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result['num_threads'] = 0
            
            try:
                result['connections'] = [conn._asdict() for conn in proc.connections()]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result['connections'] = []
            
            try:
                result['open_files'] = [f.path for f in proc.open_files()]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result['open_files'] = []
            
            try:
                result['hash'] = self._get_file_hash(result['exe']) if result['exe'] else None
            except Exception:
                result['hash'] = None
            
            return result
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as e:
            self.logger.error(f"Error getting process info for PID {pid}: {e}")
            return None
    
    def terminate_process(self, pid: int, force: bool = False) -> bool:
        """Terminate a process"""
        try:
            proc = psutil.Process(pid)
            process_name = proc.name()
            
            if force:
                proc.kill()
                self.logger.info(f"💀 Force killed process: {process_name} (PID: {pid})")
            else:
                proc.terminate()
                self.logger.info(f"🛑 Terminated process: {process_name} (PID: {pid})")
            
            return True
            
        except psutil.NoSuchProcess:
            self.logger.warning(f"Process {pid} not found")
            return False
        except psutil.AccessDenied:
            self.logger.error(f"Access denied terminating process {pid}")
            return False
        except Exception as e:
            self.logger.error(f"Error terminating process {pid}: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get monitor statistics"""
        try:
            suspicious_count = 0
            for process_info in self.known_processes.values():
                is_suspicious, _ = self._analyze_process_suspicious(process_info)
                if is_suspicious:
                    suspicious_count += 1
            
            return {
                'running': self.running,
                'known_processes': len(self.known_processes),
                'suspicious_processes': suspicious_count,
                'monitor_interval': self.monitor_interval,
                'monitor_creation': self.monitor_creation,
                'monitor_termination': self.monitor_termination,
                'cache_size': len(self.process_cache)
            }
        except Exception as e:
            self.logger.error(f"Error getting process monitor stats: {e}")
            return {'error': str(e)}