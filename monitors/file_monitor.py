"""
EDR Windows Agent - File System Monitor (FIXED)
"""

import os
import time
import hashlib
import logging
import threading
import glob
from datetime import datetime
from typing import Dict, List, Any, Callable, Optional, Set
from pathlib import Path
import psutil

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

class EDRFileEventHandler(FileSystemEventHandler):
    """Custom file system event handler for EDR"""
    
    def __init__(self, file_monitor):
        self.file_monitor = file_monitor
        self.logger = logging.getLogger(__name__)
        super().__init__()
    
    def on_created(self, event: FileSystemEvent):
        """Handle file creation"""
        if not event.is_directory:
            self.file_monitor._handle_file_event('created', event.src_path)
    
    def on_modified(self, event: FileSystemEvent):
        """Handle file modification"""
        if not event.is_directory:
            self.file_monitor._handle_file_event('modified', event.src_path)
    
    def on_deleted(self, event: FileSystemEvent):
        """Handle file deletion"""
        if not event.is_directory:
            self.file_monitor._handle_file_event('deleted', event.src_path)
    
    def on_moved(self, event: FileSystemEvent):
        """Handle file move/rename"""
        if not event.is_directory and hasattr(event, 'dest_path'):
            self.file_monitor._handle_file_event('moved', event.src_path, event.dest_path)

class FileMonitor:
    """Monitors file system activities on Windows"""
    
    def __init__(self, config, event_callback: Callable):
        self.config = config
        self.event_callback = event_callback
        self.logger = logging.getLogger(__name__)
        
        # Monitoring state
        self.running = False
        self.observers = []
        
        # Configuration
        self.watch_paths = config.get('file_monitoring', 'watch_paths', [])
        self.exclude_paths = set(config.get('file_monitoring', 'exclude_paths', []))
        self.monitored_extensions = set(config.get('file_monitoring', 'file_extensions', []))
        
        # Event filtering
        self.event_cache = {}  # To prevent duplicate events
        self.cache_timeout = 5  # seconds
        self.last_cleanup = time.time()
        
        # FIXED: Add rate limiting for high-frequency events
        self.event_rate_limit = {}  # path -> last_event_time
        self.rate_limit_interval = 1  # 1 second minimum between same file events
        
        # File tracking for mass operations detection
        self.recent_operations = {}  # directory -> list of recent events
        self.mass_operation_threshold = 10  # files
        self.mass_operation_window = 30  # seconds
        
        # File tracking
        self.suspicious_patterns = [
            '.encrypt', '.encrypted', '.locked', '.crypto', '.crypt',
            'ransom', 'readme', 'decrypt', 'restore', 'recovery',
            '.vault', '.secured', '.coded', '.enc'
        ]
        
        # FIXED: Add more comprehensive exclusions
        self.system_exclude_patterns = [
            'thumbs.db', 'desktop.ini', '.ds_store',
            '*.tmp', '*.temp', '*.swp', '*.bak',
            '*.log', '*.lock', '*.cache',
            'hiberfil.sys', 'pagefile.sys', 'swapfile.sys'
        ]
        
        self.logger.info("✅ File monitor initialized")
    
    def start(self):
        """Start file system monitoring"""
        try:
            if self.running:
                return
                
            self.running = True
            
            # Start observers for each watch path
            for watch_path in self.watch_paths:
                self._start_path_observer(watch_path)
            
            self.logger.info(f"🔍 File monitoring started for {len(self.observers)} paths")
            
        except Exception as e:
            self.logger.error(f"Failed to start file monitor: {e}")
            raise
    
    def stop(self):
        """Stop file system monitoring"""
        try:
            self.running = False
            
            # Stop all observers
            for observer in self.observers:
                try:
                    observer.stop()
                    observer.join(timeout=5)
                except Exception as e:
                    self.logger.error(f"Error stopping observer: {e}")
            
            self.observers.clear()
            self.logger.info("🛑 File monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping file monitor: {e}")
    
    def is_running(self) -> bool:
        """Check if monitor is running"""
        return self.running and any(obs.is_alive() for obs in self.observers)
    
    def _start_path_observer(self, watch_path: str):
        """Start observer for specific path"""
        try:
            # Expand environment variables and wildcards
            expanded_path = os.path.expandvars(watch_path)
            
            if '*' in expanded_path:
                # Handle wildcard paths
                self._handle_wildcard_path(expanded_path)
            else:
                # Regular path
                if os.path.exists(expanded_path):
                    observer = Observer()
                    event_handler = EDRFileEventHandler(self)
                    observer.schedule(event_handler, expanded_path, recursive=True)
                    observer.start()
                    self.observers.append(observer)
                    
                    self.logger.info(f"👁️ Watching: {expanded_path}")
                else:
                    self.logger.warning(f"⚠️ Watch path does not exist: {expanded_path}")
                
        except Exception as e:
            self.logger.error(f"Error starting observer for {watch_path}: {e}")
    
    def _handle_wildcard_path(self, wildcard_path: str):
        """Handle wildcard paths like C:\\Users\\*\\Desktop"""
        try:
            # FIXED: Use glob for better wildcard handling
            expanded_paths = glob.glob(wildcard_path, recursive=True)
            
            for path in expanded_paths:
                if os.path.isdir(path):
                    try:
                        observer = Observer()
                        event_handler = EDRFileEventHandler(self)
                        observer.schedule(event_handler, path, recursive=True)
                        observer.start()
                        self.observers.append(observer)
                        self.logger.info(f"👁️ Watching wildcard path: {path}")
                    except Exception as e:
                        self.logger.error(f"Failed to watch {path}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error handling wildcard path {wildcard_path}: {e}")
    
    def _handle_file_event(self, event_type: str, file_path: str, dest_path: str = None):
        """Handle file system event"""
        try:
            # FIXED: Rate limiting for same file
            if self._is_rate_limited(file_path):
                return
            
            # Check if path should be excluded
            if self._should_exclude_path(file_path):
                return
            
            # Check if extension should be monitored
            if not self._should_monitor_file(file_path):
                return
            
            # Prevent duplicate events
            if self._is_duplicate_event(event_type, file_path):
                return
            
            # Get file information
            file_info = self._get_file_info(file_path, event_type)
            if not file_info:
                return
            
            # Detect suspicious activity
            is_suspicious, detection_reasons = self._analyze_suspicious_activity(file_info, event_type, file_path)
            
            # Track mass operations
            self._track_mass_operations(file_path, event_type)
            
            # Get process information
            process_info = self._get_current_process_info()
            
            # Create event data
            event_data = {
                'event_type': f'file_{event_type}',
                'file_name': os.path.basename(file_path),
                'file_path': file_path,
                'file_size': file_info.get('size'),
                'file_hash': file_info.get('hash'),
                'file_extension': Path(file_path).suffix.lower(),
                'process_id': process_info.get('pid'),
                'process_name': process_info.get('name'),
                'process_path': process_info.get('exe'),
                'is_suspicious': is_suspicious,
                'detection_reasons': detection_reasons,
                'mass_operation': self._check_mass_operation(os.path.dirname(file_path))
            }
            
            if dest_path:
                event_data['destination_path'] = dest_path
                event_data['destination_name'] = os.path.basename(dest_path)
            
            # Send event to agent
            self.event_callback(event_data)
            
            # Log suspicious activity
            if is_suspicious:
                self.logger.warning(f"🚨 Suspicious file activity: {event_type} - {file_path} - Reasons: {', '.join(detection_reasons)}")
            else:
                self.logger.debug(f"📁 File {event_type}: {file_path}")
                
            # Cleanup old cache entries periodically
            self._cleanup_caches()
            
        except Exception as e:
            self.logger.error(f"Error handling file event: {e}")
    
    def _is_rate_limited(self, file_path: str) -> bool:
        """Check if file is rate limited"""
        try:
            current_time = time.time()
            
            if file_path in self.event_rate_limit:
                last_time = self.event_rate_limit[file_path]
                if current_time - last_time < self.rate_limit_interval:
                    return True
            
            self.event_rate_limit[file_path] = current_time
            return False
            
        except Exception:
            return False
    
    def _should_exclude_path(self, file_path: str) -> bool:
        """Check if path should be excluded from monitoring"""
        try:
            file_path_lower = file_path.lower()
            file_name_lower = os.path.basename(file_path).lower()
            
            # Check configured exclude paths
            for exclude_path in self.exclude_paths:
                exclude_path_lower = exclude_path.lower()
                if exclude_path_lower in file_path_lower:
                    return True
            
            # FIXED: Check system exclude patterns
            for pattern in self.system_exclude_patterns:
                if pattern.startswith('*'):
                    if file_name_lower.endswith(pattern[1:]):
                        return True
                elif pattern.endswith('*'):
                    if file_name_lower.startswith(pattern[:-1]):
                        return True
                elif pattern in file_name_lower:
                    return True
            
            # Exclude browser cache and temp directories
            exclude_keywords = [
                'cache', 'temp', 'tmp', 'logs', 'cookies',
                'sessionstore', 'recovery', 'crashreports'
            ]
            
            for keyword in exclude_keywords:
                if keyword in file_path_lower:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _should_monitor_file(self, file_path: str) -> bool:
        """Check if file extension should be monitored"""
        try:
            if not self.monitored_extensions:
                return True  # Monitor all files if no extensions specified
            
            file_ext = Path(file_path).suffix.lower()
            return file_ext in self.monitored_extensions
            
        except Exception:
            return False
    
    def _is_duplicate_event(self, event_type: str, file_path: str) -> bool:
        """Check if this is a duplicate event"""
        try:
            event_key = f"{event_type}:{file_path}"
            current_time = time.time()
            
            if event_key in self.event_cache:
                last_time = self.event_cache[event_key]
                if current_time - last_time < self.cache_timeout:
                    return True
            
            self.event_cache[event_key] = current_time
            return False
            
        except Exception:
            return False
    
    def _track_mass_operations(self, file_path: str, event_type: str):
        """Track mass file operations for ransomware detection"""
        try:
            directory = os.path.dirname(file_path)
            current_time = time.time()
            
            if directory not in self.recent_operations:
                self.recent_operations[directory] = []
            
            # Add current operation
            self.recent_operations[directory].append({
                'event_type': event_type,
                'timestamp': current_time,
                'file_path': file_path
            })
            
            # Remove old operations outside the window
            self.recent_operations[directory] = [
                op for op in self.recent_operations[directory]
                if current_time - op['timestamp'] <= self.mass_operation_window
            ]
            
        except Exception as e:
            self.logger.error(f"Error tracking mass operations: {e}")
    
    def _check_mass_operation(self, directory: str) -> bool:
        """Check if directory has mass file operations"""
        try:
            if directory not in self.recent_operations:
                return False
            
            recent_count = len(self.recent_operations[directory])
            return recent_count >= self.mass_operation_threshold
            
        except Exception:
            return False
    
    def _cleanup_caches(self):
        """Clean up old cache entries"""
        try:
            current_time = time.time()
            
            # Clean event cache
            if current_time - self.last_cleanup > 60:  # Cleanup every minute
                expired_keys = [
                    key for key, timestamp in self.event_cache.items()
                    if current_time - timestamp > self.cache_timeout * 10
                ]
                
                for key in expired_keys:
                    del self.event_cache[key]
                
                # Clean rate limit cache
                expired_rate_keys = [
                    path for path, timestamp in self.event_rate_limit.items()
                    if current_time - timestamp > 300  # 5 minutes
                ]
                
                for key in expired_rate_keys:
                    del self.event_rate_limit[key]
                
                self.last_cleanup = current_time
                
                if expired_keys or expired_rate_keys:
                    self.logger.debug(f"🧹 Cleaned {len(expired_keys)} event cache, {len(expired_rate_keys)} rate limit entries")
                
        except Exception as e:
            self.logger.error(f"Error cleaning caches: {e}")
    
    def _get_file_info(self, file_path: str, event_type: str) -> Optional[Dict[str, Any]]:
        """Get file information"""
        try:
            file_info = {
                'path': file_path,
                'exists': os.path.exists(file_path)
            }
            
            if file_info['exists'] and event_type != 'deleted':
                try:
                    stat = os.stat(file_path)
                    file_info.update({
                        'size': stat.st_size,
                        'modified_time': stat.st_mtime,
                        'created_time': stat.st_ctime,
                        'accessed_time': stat.st_atime
                    })
                    
                    # FIXED: Only hash small files and certain types
                    if stat.st_size < 10 * 1024 * 1024:  # Only hash files < 10MB
                        file_ext = Path(file_path).suffix.lower()
                        hashable_extensions = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.zip'}
                        if file_ext in hashable_extensions:
                            file_info['hash'] = self._calculate_file_hash(file_path)
                    
                except OSError as e:
                    self.logger.debug(f"Could not get file info for {file_path}: {e}")
            
            return file_info
            
        except Exception as e:
            self.logger.error(f"Error getting file info for {file_path}: {e}")
            return None
    
    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate SHA256 hash of file"""
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
    
    def _analyze_suspicious_activity(self, file_info: Dict[str, Any], event_type: str, file_path: str) -> tuple[bool, List[str]]:
        """Analyze file activity for suspicious patterns"""
        detection_reasons = []
        
        try:
            file_name = os.path.basename(file_path).lower()
            file_ext = Path(file_path).suffix.lower()
            directory = os.path.dirname(file_path).lower()
            
            # Check for ransomware-like patterns in filename
            for pattern in self.suspicious_patterns:
                if pattern in file_name:
                    detection_reasons.append(f"suspicious_filename:{pattern}")
            
            # Check for mass file operations (potential ransomware)
            if event_type in ['created', 'modified']:
                if self._check_mass_operation(os.path.dirname(file_path)):
                    detection_reasons.append("mass_file_operation")
            
            # Check for execution of files from suspicious locations
            if event_type == 'created' and file_ext == '.exe':
                suspicious_locations = ['temp', 'downloads', 'appdata', 'public', 'programdata']
                if any(loc in directory for loc in suspicious_locations):
                    detection_reasons.append("executable_in_suspicious_location")
            
            # Check for suspicious file extensions
            suspicious_extensions = [
                '.encrypt', '.encrypted', '.locked', '.crypto', '.crypt',
                '.vault', '.secured', '.coded', '.enc', '.ransomware'
            ]
            if file_ext in suspicious_extensions:
                detection_reasons.append("suspicious_extension")
            
            # Check for double extensions (common malware trick)
            if file_name.count('.') > 1:
                # Look for patterns like .pdf.exe, .doc.scr, etc.
                parts = file_name.split('.')
                if len(parts) >= 3:
                    second_ext = f".{parts[-2]}"
                    if second_ext in ['.pdf', '.doc', '.txt', '.jpg', '.png'] and file_ext in ['.exe', '.scr', '.bat', '.cmd']:
                        detection_reasons.append("double_extension")
            
            # Check for script files in unusual locations
            script_extensions = {'.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.wsh'}
            if file_ext in script_extensions:
                if any(suspicious in directory for suspicious in ['downloads', 'temp', 'public']):
                    detection_reasons.append("script_in_suspicious_location")
            
            # Check for hidden files with suspicious extensions
            if file_name.startswith('.') and file_ext in {'.exe', '.bat', '.cmd', '.ps1'}:
                detection_reasons.append("hidden_executable")
            
            # Check for very long filenames (sometimes used by malware)
            if len(file_name) > 100:
                detection_reasons.append("unusually_long_filename")
            
            # Check for files with no extension but executable content
            if not file_ext and event_type == 'created':
                if file_info.get('size', 0) > 1024:  # Larger than 1KB
                    detection_reasons.append("no_extension_executable_size")
            
            # Check for rapid file modifications (potential encryption)
            if event_type == 'modified':
                recent_ops = self.recent_operations.get(os.path.dirname(file_path), [])
                modification_count = sum(1 for op in recent_ops if op['event_type'] == 'modified')
                if modification_count > 5:  # More than 5 modifications in the window
                    detection_reasons.append("rapid_file_modifications")
            
            # Check for system file tampering
            system_paths = ['system32', 'syswow64', 'windows\\system']
            if any(sys_path in directory for sys_path in system_paths):
                if event_type in ['created', 'modified'] and not self._is_system_process():
                    detection_reasons.append("system_file_tampering")
            
            # Check for startup folder modifications
            startup_paths = ['startup', 'start menu\\programs\\startup']
            if any(startup in directory for startup in startup_paths):
                detection_reasons.append("startup_folder_modification")
            
            return len(detection_reasons) > 0, detection_reasons
            
        except Exception as e:
            self.logger.error(f"Error analyzing suspicious activity: {e}")
            return False, []
    
    def _get_current_process_info(self) -> Dict[str, Any]:
        """Get information about the current process that might be accessing files"""
        try:
            # This is simplified - in practice you'd use ETW or ProcessMonitor-like techniques
            current_proc = psutil.Process()
            return {
                'pid': current_proc.pid,
                'name': current_proc.name(),
                'exe': current_proc.exe(),
                'cmdline': ' '.join(current_proc.cmdline())
            }
        except Exception:
            return {
                'pid': os.getpid(),
                'name': 'unknown',
                'exe': None,
                'cmdline': ''
            }
    
    def _is_system_process(self) -> bool:
        """Check if current process is a system process"""
        try:
            current_proc = psutil.Process()
            process_name = current_proc.name().lower()
            
            system_processes = {
                'system', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
                'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe'
            }
            
            return process_name in system_processes
            
        except Exception:
            return False
    
    def get_monitored_paths(self) -> List[str]:
        """Get list of monitored paths"""
        return self.watch_paths.copy()
    
    def add_watch_path(self, path: str) -> bool:
        """Add new path to monitor"""
        try:
            if path not in self.watch_paths:
                self.watch_paths.append(path)
                if self.running:
                    self._start_path_observer(path)
                self.logger.info(f"✅ Added watch path: {path}")
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Error adding watch path {path}: {e}")
            return False
    
    def remove_watch_path(self, path: str) -> bool:
        """Remove path from monitoring"""
        try:
            if path in self.watch_paths:
                self.watch_paths.remove(path)
                # FIXED: Stop specific observer for this path
                self._stop_path_observer(path)
                self.logger.info(f"✅ Removed watch path: {path}")
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Error removing watch path {path}: {e}")
            return False
    
    def _stop_path_observer(self, path: str):
        """Stop observer for specific path"""
        try:
            # This is simplified - you'd need to track which observer handles which path
            # For now, we'll restart all observers
            if self.running:
                self.stop()
                self.start()
        except Exception as e:
            self.logger.error(f"Error stopping observer for {path}: {e}")
    
    def get_recent_suspicious_files(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recently detected suspicious files"""
        try:
            cutoff_time = time.time() - (hours * 3600)
            suspicious_files = []
            
            # This would typically be stored in a database or persistent storage
            # For now, we'll return recent operations that were flagged as suspicious
            for directory, operations in self.recent_operations.items():
                for op in operations:
                    if op['timestamp'] >= cutoff_time:
                        file_path = op['file_path']
                        file_info = self._get_file_info(file_path, op['event_type'])
                        if file_info:
                            is_suspicious, reasons = self._analyze_suspicious_activity(
                                file_info, op['event_type'], file_path
                            )
                            if is_suspicious:
                                suspicious_files.append({
                                    'file_path': file_path,
                                    'event_type': op['event_type'],
                                    'timestamp': op['timestamp'],
                                    'detection_reasons': reasons
                                })
            
            return suspicious_files
            
        except Exception as e:
            self.logger.error(f"Error getting recent suspicious files: {e}")
            return []
    
    def get_mass_operations_summary(self) -> Dict[str, Any]:
        """Get summary of mass file operations by directory"""
        try:
            summary = {}
            
            for directory, operations in self.recent_operations.items():
                if len(operations) >= self.mass_operation_threshold:
                    summary[directory] = {
                        'operation_count': len(operations),
                        'event_types': list(set(op['event_type'] for op in operations)),
                        'time_span': max(op['timestamp'] for op in operations) - min(op['timestamp'] for op in operations),
                        'first_event': min(op['timestamp'] for op in operations),
                        'last_event': max(op['timestamp'] for op in operations)
                    }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error getting mass operations summary: {e}")
            return {}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get monitor statistics"""
        try:
            active_observers = len([obs for obs in self.observers if obs.is_alive()])
            
            return {
                'running': self.running,
                'active_observers': active_observers,
                'total_observers': len(self.observers),
                'watched_paths': len(self.watch_paths),
                'monitored_extensions': len(self.monitored_extensions),
                'event_cache_size': len(self.event_cache),
                'rate_limit_cache_size': len(self.event_rate_limit),
                'exclude_paths': len(self.exclude_paths),
                'recent_operations_dirs': len(self.recent_operations),
                'mass_operations_detected': len([
                    d for d, ops in self.recent_operations.items() 
                    if len(ops) >= self.mass_operation_threshold
                ])
            }
        except Exception as e:
            self.logger.error(f"Error getting file monitor stats: {e}")
            return {'error': str(e)}