"""
EDR Windows Agent - Process Monitor
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
                        
                    current_processes[pinfo['pid']] = {
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'exe': pinfo['exe'],
                        'cmdline': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else '',
                        'create_time': pinfo['create_time'],
                        'parent_pid': proc.ppid(),
                        'username': self._get_process_user(proc),
                        'cpu_percent': proc.cpu_percent(),
                        'memory_info': proc.memory_info()._asdict(),
                        'hash': self._get_file_hash(pinfo['exe']) if pinfo['exe'] else None
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
                'is_suspicious': self._is_suspicious_process(process_info)
            }
            
            # Send event to agent
            self.event_callback(event_data)
            
            # Log suspicious processes
            if event_data['is_suspicious']:
                self.logger.warning(f"🚨 Suspicious process created: {process_info['name']} (PID: {process_info['pid']})")
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
    
    def _is_suspicious_process(self, process_info: Dict[str, Any]) -> bool:
        """Check if process is suspicious"""
        try:
            # Check against suspicious process names
            if process_info['name'].lower() in [p.lower() for p in self.suspicious_processes]:
                return True
            
            # Check for suspicious command line patterns
            cmdline = process_info['cmdline'].lower()
            suspicious_patterns = [
                'powershell -enc',
                'powershell -e ',
                'powershell.exe -w hidden',
                'cmd /c echo',
                'wmic process',
                'net user',
                'net localgroup',
                'reg add',
                'schtasks /create'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in cmdline:
                    return True
            
            # Check for execution from suspicious locations
            exe_path = process_info['exe']
            if exe_path:
                suspicious_paths = [
                    'temp',
                    'appdata\\local\\temp',
                    'downloads',
                    'public',
                    'programdata'
                ]
                
                exe_path_lower = exe_path.lower()
                for path in suspicious_paths:
                    if path in exe_path_lower:
                        return True
            
            # Check for unsigned executables in system locations
            if exe_path and ('system32' in exe_path.lower() or 'syswow64' in exe_path.lower()):
                if not self._is_file_signed(exe_path):
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking suspicious process: {e}")
            return False
    
    def _get_process_user(self, proc: psutil.Process) -> Optional[str]:
        """Get process owner username"""
        try:
            return proc.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return None
    
    def _get_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate SHA256 hash of file"""
        try:
            if not file_path or not os.path.exists(file_path):
                return None
                
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            
            return hash_sha256.hexdigest()
            
        except Exception:
            return None
    
    def _is_file_signed(self, file_path: str) -> bool:
        """Check if file is digitally signed"""
        try:
            # This is a simplified check - in production you'd use WinVerifyTrust
            return os.path.exists(file_path)
        except Exception:
            return False
    
    def get_process_list(self) -> List[Dict[str, Any]]:
        """Get current process list"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
                try:
                    pinfo = proc.info
                    if pinfo['pid'] == 0:
                        continue
                        
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'exe': pinfo['exe'],
                        'cmdline': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else '',
                        'create_time': pinfo['create_time'],
                        'parent_pid': proc.ppid(),
                        'username': self._get_process_user(proc),
                        'cpu_percent': proc.cpu_percent(),
                        'memory_mb': proc.memory_info().rss / 1024 / 1024,
                        'status': proc.status()
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
            
            return {
                'pid': proc.pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': ' '.join(proc.cmdline()),
                'create_time': proc.create_time(),
                'parent_pid': proc.ppid(),
                'username': self._get_process_user(proc),
                'cpu_percent': proc.cpu_percent(),
                'memory_info': proc.memory_info()._asdict(),
                'status': proc.status(),
                'num_threads': proc.num_threads(),
                'connections': [conn._asdict() for conn in proc.connections()],
                'open_files': [f.path for f in proc.open_files()],
                'hash': self._get_file_hash(proc.exe())
            }
            
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
            return {
                'running': self.running,
                'known_processes': len(self.known_processes),
                'suspicious_processes': len([p for p in self.known_processes.values() 
                                           if self._is_suspicious_process(p)]),
                'monitor_interval': self.monitor_interval,
                'monitor_creation': self.monitor_creation,
                'monitor_termination': self.monitor_termination
            }
        except Exception as e:
            self.logger.error(f"Error getting process monitor stats: {e}")
            return {'error': str(e)}