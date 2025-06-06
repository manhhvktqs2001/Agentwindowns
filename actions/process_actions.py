"""
EDR Windows Agent - Process Response Actions
"""

import os
import time
import psutil
import logging
import subprocess
from typing import Dict, List, Any, Optional, Union
import win32api
import win32con
import win32process
import win32security

class ProcessActions:
    """Handles process-related response actions"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.allow_termination = config.get('actions', 'allow_process_termination', True)
        self.response_timeout = config.get('actions', 'response_timeout', 10)
        
        # Protected processes that should not be terminated
        self.protected_processes = {
            'system', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
            'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe',
            'dwm.exe', 'conhost.exe'
        }
        
        # Quarantine directory
        self.quarantine_dir = os.path.join(os.getcwd(), 'data', 'quarantine')
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        self.logger.info("✅ Process actions initialized")
    
    def terminate_process(self, process_id: Optional[int] = None, process_name: Optional[str] = None, 
                         force: bool = False) -> bool:
        """Terminate a process by PID or name"""
        try:
            if not self.allow_termination:
                self.logger.warning("❌ Process termination is disabled in configuration")
                return False
            
            # Find process
            target_processes = []
            
            if process_id:
                try:
                    proc = psutil.Process(process_id)
                    target_processes.append(proc)
                except psutil.NoSuchProcess:
                    self.logger.error(f"Process with PID {process_id} not found")
                    return False
            
            elif process_name:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if proc.info['name'].lower() == process_name.lower():
                            target_processes.append(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                if not target_processes:
                    self.logger.error(f"No processes found with name: {process_name}")
                    return False
            
            else:
                self.logger.error("Either process_id or process_name must be provided")
                return False
            
            # Terminate processes
            terminated_count = 0
            for proc in target_processes:
                try:
                    proc_name = proc.name()
                    proc_pid = proc.pid
                    
                    # Check if process is protected
                    if self._is_protected_process(proc_name):
                        self.logger.warning(f"⚠️ Refusing to terminate protected process: {proc_name}")
                        continue
                    
                    # Get process info before termination
                    proc_info = self._get_process_info_for_logging(proc)
                    
                    # Terminate process
                    if force:
                        proc.kill()
                        self.logger.info(f"💀 Force killed process: {proc_name} (PID: {proc_pid})")
                    else:
                        proc.terminate()
                        # Wait for process to terminate gracefully
                        try:
                            proc.wait(timeout=self.response_timeout)
                            self.logger.info(f"🛑 Terminated process: {proc_name} (PID: {proc_pid})")
                        except psutil.TimeoutExpired:
                            # Force kill if graceful termination failed
                            proc.kill()
                            self.logger.info(f"💀 Force killed process after timeout: {proc_name} (PID: {proc_pid})")
                    
                    terminated_count += 1
                    
                    # Log the action
                    self._log_process_action('terminate', proc_info)
                    
                except psutil.NoSuchProcess:
                    self.logger.info(f"Process {proc_name} (PID: {proc_pid}) already terminated")
                    terminated_count += 1
                except psutil.AccessDenied:
                    self.logger.error(f"❌ Access denied terminating process: {proc_name} (PID: {proc_pid})")
                except Exception as e:
                    self.logger.error(f"❌ Error terminating process {proc_name} (PID: {proc_pid}): {e}")
            
            return terminated_count > 0
            
        except Exception as e:
            self.logger.error(f"Error in terminate_process: {e}")
            return False
    
    def suspend_process(self, process_id: int) -> bool:
        """Suspend a process"""
        try:
            proc = psutil.Process(process_id)
            proc_name = proc.name()
            
            # Check if process is protected
            if self._is_protected_process(proc_name):
                self.logger.warning(f"⚠️ Refusing to suspend protected process: {proc_name}")
                return False
            
            proc.suspend()
            
            proc_info = self._get_process_info_for_logging(proc)
            self._log_process_action('suspend', proc_info)
            
            self.logger.info(f"⏸️ Suspended process: {proc_name} (PID: {process_id})")
            return True
            
        except psutil.NoSuchProcess:
            self.logger.error(f"Process with PID {process_id} not found")
            return False
        except psutil.AccessDenied:
            self.logger.error(f"❌ Access denied suspending process PID {process_id}")
            return False
        except Exception as e:
            self.logger.error(f"Error suspending process {process_id}: {e}")
            return False
    
    def resume_process(self, process_id: int) -> bool:
        """Resume a suspended process"""
        try:
            proc = psutil.Process(process_id)
            proc_name = proc.name()
            
            proc.resume()
            
            proc_info = self._get_process_info_for_logging(proc)
            self._log_process_action('resume', proc_info)
            
            self.logger.info(f"▶️ Resumed process: {proc_name} (PID: {process_id})")
            return True
            
        except psutil.NoSuchProcess:
            self.logger.error(f"Process with PID {process_id} not found")
            return False
        except psutil.AccessDenied:
            self.logger.error(f"❌ Access denied resuming process PID {process_id}")
            return False
        except Exception as e:
            self.logger.error(f"Error resuming process {process_id}: {e}")
            return False
    
    def quarantine_process_executable(self, process_id: int) -> bool:
        """Move process executable to quarantine"""
        try:
            proc = psutil.Process(process_id)
            exe_path = proc.exe()
            proc_name = proc.name()
            
            if not exe_path or not os.path.exists(exe_path):
                self.logger.error(f"Executable path not found for process {proc_name}")
                return False
            
            # Check if process is protected
            if self._is_protected_process(proc_name):
                self.logger.warning(f"⚠️ Refusing to quarantine protected process: {proc_name}")
                return False
            
            # Terminate process first
            if not self.terminate_process(process_id=process_id):
                self.logger.error(f"Failed to terminate process before quarantine: {proc_name}")
                return False
            
            # Wait a moment for process to fully terminate
            time.sleep(1)
            
            # Move executable to quarantine
            quarantine_path = os.path.join(
                self.quarantine_dir,
                f"{proc_name}_{process_id}_{int(time.time())}.quarantine"
            )
            
            try:
                import shutil
                shutil.move(exe_path, quarantine_path)
                
                self.logger.info(f"🔒 Quarantined executable: {exe_path} -> {quarantine_path}")
                
                # Log the action
                self._log_process_action('quarantine', {
                    'pid': process_id,
                    'name': proc_name,
                    'original_path': exe_path,
                    'quarantine_path': quarantine_path
                })
                
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to move file to quarantine: {e}")
                return False
                
        except psutil.NoSuchProcess:
            self.logger.error(f"Process with PID {process_id} not found")
            return False
        except Exception as e:
            self.logger.error(f"Error quarantining process {process_id}: {e}")
            return False
    
    def block_process_network(self, process_id: int) -> bool:
        """Block network access for a process using Windows Firewall"""
        try:
            proc = psutil.Process(process_id)
            exe_path = proc.exe()
            proc_name = proc.name()
            
            if not exe_path:
                self.logger.error(f"Executable path not found for process {proc_name}")
                return False
            
            # Create firewall rule to block the executable
            rule_name = f"EDR_Block_{proc_name}_{process_id}"
            
            # Use netsh to create firewall rule
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=out',
                'action=block',
                f'program={exe_path}',
                'enable=yes'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"🚫 Blocked network access for: {proc_name} (PID: {process_id})")
                
                # Log the action
                self._log_process_action('block_network', {
                    'pid': process_id,
                    'name': proc_name,
                    'exe_path': exe_path,
                    'firewall_rule': rule_name
                })
                
                return True
            else:
                self.logger.error(f"Failed to create firewall rule: {result.stderr}")
                return False
                
        except psutil.NoSuchProcess:
            self.logger.error(f"Process with PID {process_id} not found")
            return False
        except Exception as e:
            self.logger.error(f"Error blocking network for process {process_id}: {e}")
            return False
    
    def get_process_handles(self, process_id: int) -> List[Dict[str, Any]]:
        """Get handles opened by a process"""
        try:
            # This is a simplified implementation
            # In practice, you'd use Windows APIs to enumerate handles
            proc = psutil.Process(process_id)
            
            handles = []
            
            # Get open files
            try:
                for f in proc.open_files():
                    handles.append({
                        'type': 'file',
                        'path': f.path,
                        'fd': f.fd if hasattr(f, 'fd') else None
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Get network connections
            try:
                for conn in proc.connections():
                    handles.append({
                        'type': 'network',
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            return handles
            
        except psutil.NoSuchProcess:
            self.logger.error(f"Process with PID {process_id} not found")
            return []
        except Exception as e:
            self.logger.error(f"Error getting handles for process {process_id}: {e}")
            return []
    
    def inject_dll(self, process_id: int, dll_path: str) -> bool:
        """Inject DLL into target process (for monitoring/analysis)"""
        try:
            # This is for legitimate EDR monitoring purposes only
            if not os.path.exists(dll_path):
                self.logger.error(f"DLL not found: {dll_path}")
                return False
            
            proc = psutil.Process(process_id)
            proc_name = proc.name()
            
            # Check if process is protected
            if self._is_protected_process(proc_name):
                self.logger.warning(f"⚠️ Refusing to inject into protected process: {proc_name}")
                return False
            
            # This would implement DLL injection using Windows APIs
            # Implementation omitted for security reasons
            
            self.logger.info(f"💉 DLL injection simulated for: {proc_name} (PID: {process_id})")
            return True
            
        except psutil.NoSuchProcess:
            self.logger.error(f"Process with PID {process_id} not found")
            return False
        except Exception as e:
            self.logger.error(f"Error injecting DLL into process {process_id}: {e}")
            return False
    
    def _is_protected_process(self, process_name: str) -> bool:
        """Check if process is protected and should not be terminated"""
        return process_name.lower() in self.protected_processes
    
    def _get_process_info_for_logging(self, proc: psutil.Process) -> Dict[str, Any]:
        """Get process information for logging purposes"""
        try:
            return {
                'pid': proc.pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': ' '.join(proc.cmdline()),
                'username': proc.username(),
                'create_time': proc.create_time(),
                'cpu_percent': proc.cpu_percent(),
                'memory_mb': proc.memory_info().rss / 1024 / 1024
            }
        except Exception as e:
            return {
                'pid': proc.pid,
                'error': str(e)
            }
    
    def _log_process_action(self, action: str, proc_info: Dict[str, Any]):
        """Log process action for audit trail"""
        try:
            log_entry = {
                'timestamp': time.time(),
                'action': action,
                'process_info': proc_info,
                'agent_hostname': self.config.get_system_info().get('hostname')
            }
            
            # This would typically send to the server as well
            self.logger.info(f"📝 Process action logged: {action} on {proc_info.get('name', 'unknown')}")
            
        except Exception as e:
            self.logger.error(f"Error logging process action: {e}")
    
    def get_quarantined_files(self) -> List[Dict[str, Any]]:
        """Get list of quarantined files"""
        try:
            quarantined = []
            
            if os.path.exists(self.quarantine_dir):
                for filename in os.listdir(self.quarantine_dir):
                    if filename.endswith('.quarantine'):
                        file_path = os.path.join(self.quarantine_dir, filename)
                        stat = os.stat(file_path)
                        
                        quarantined.append({
                            'filename': filename,
                            'path': file_path,
                            'size': stat.st_size,
                            'quarantined_time': stat.st_ctime,
                            'modified_time': stat.st_mtime
                        })
            
            return quarantined
            
        except Exception as e:
            self.logger.error(f"Error getting quarantined files: {e}")
            return []
    
    def restore_quarantined_file(self, quarantine_filename: str, restore_path: str) -> bool:
        """Restore a file from quarantine"""
        try:
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            if not os.path.exists(quarantine_path):
                self.logger.error(f"Quarantined file not found: {quarantine_filename}")
                return False
            
            import shutil
            shutil.move(quarantine_path, restore_path)
            
            self.logger.info(f"♻️ Restored file from quarantine: {quarantine_filename} -> {restore_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error restoring quarantined file: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get process action statistics"""
        try:
            return {
                'allow_termination': self.allow_termination,
                'response_timeout': self.response_timeout,
                'protected_processes': len(self.protected_processes),
                'quarantine_dir': self.quarantine_dir,
                'quarantined_files': len(self.get_quarantined_files())
            }
        except Exception as e:
            self.logger.error(f"Error getting process action stats: {e}")
            return {'error': str(e)}