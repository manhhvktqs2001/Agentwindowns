"""
EDR Windows Agent - File System Monitor
"""

import os
import time
import hashlib
import logging
import threading
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
        
        # File tracking
        self.suspicious_patterns = [
            '.encrypt',
            '.locked',
            '.crypto',
            '.crypt',
            'ransom',
            'readme',
            'decrypt',
            'restore'
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
                if os.path.exists(watch_path):
                    self._start_path_observer(watch_path)
                else:
                    self.logger.warning(f"⚠️ Watch path does not exist: {watch_path}")
            
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
                observer.stop()
                observer.join(timeout=5)
            
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
                observer = Observer()
                event_handler = EDRFileEventHandler(self)
                observer.schedule(event_handler, expanded_path, recursive=True)
                observer.start()
                self.observers.append(observer)
                
                self.logger.info(f"👁️ Watching: {expanded_path}")
                
        except Exception as e:
            self.logger.error(f"Error starting observer for {watch_path}: {e}")
    
    def _handle_wildcard_path(self, wildcard_path: str):
        """Handle wildcard paths like C:\\Users\\*\\Desktop"""
        try:
            # Split path to find wildcard part
            parts = Path(wildcard_path).parts
            
            if '*' in parts:
                wildcard_index = parts.index('*')
                base_path = Path(*parts[:wildcard_index])
                remaining_path = Path(*parts[wildcard_index + 1:]) if wildcard_index + 1 < len(parts) else None
                
                # Find matching directories
                if base_path.exists():
                    for item in base_path.iterdir():
                        if item.is_dir():
                            if remaining_path:
                                full_path = item / remaining_path
                                if full_path.exists():
                                    self._start_path_observer(str(full_path))
                            else:
                                self._start_path_observer(str(item))
                                
        except Exception as e:
            self.logger.error(f"Error handling wildcard path {wildcard_path}: {e}")
    
    def _handle_file_event(self, event_type: str, file_path: str, dest_path: str = None):
        """Handle file system event"""
        try:
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
            is_suspicious = self._is_suspicious_file_activity(file_info, event_type)
            
            # Create event data
            event_data = {
                'event_type': f'file_{event_type}',
                'file_name': os.path.basename(file_path),
                'file_path': file_path,
                'file_size': file_info.get('size'),
                'file_hash': file_info.get('hash'),
                'process_id': self._get_current_process_id(),
                'process_name': self._get_current_process_name(),
                'is_suspicious': is_suspicious,
                'detection_reason': file_info.get('detection_reason')
            }
            
            if dest_path:
                event_data['destination_path'] = dest_path
            
            # Send event to agent
            self.event_callback(event_data)
            
            # Log suspicious activity
            if is_suspicious:
                self.logger.warning(f"🚨 Suspicious file activity: {event_type} - {file_path}")
            else:
                self.logger.debug(f"📁 File {event_type}: {file_path}")
                
            # Cleanup old cache entries
            self._cleanup_event_cache()
            
        except Exception as e:
            self.logger.error(f"Error handling file event: {e}")
    
    def _should_exclude_path(self, file_path: str) -> bool:
        """Check if path should be excluded from monitoring"""
        try:
            file_path_lower = file_path.lower()
            
            for exclude_path in self.exclude_paths:
                exclude_path_lower = exclude_path.lower()
                if exclude_path_lower in file_path_lower:
                    return True
            
            # Exclude temporary files
            temp_patterns = [
                '.tmp',
                '.temp',
                '~$',
                '.swp',
                '.log'
            ]
            
            for pattern in temp_patterns:
                if file_path_lower.endswith(pattern):
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
    
    def _cleanup_event_cache(self):
        """Clean up old event cache entries"""
        try:
            current_time = time.time()
            
            if current_time - self.last_cleanup > 60:  # Cleanup every minute
                expired_keys = [
                    key for key, timestamp in self.event_cache.items()
                    if current_time - timestamp > self.cache_timeout * 10
                ]
                
                for key in expired_keys:
                    del self.event_cache[key]
                
                self.last_cleanup = current_time
                
        except Exception as e:
            self.logger.error(f"Error cleaning event cache: {e}")
    
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
                        'hash': self._calculate_file_hash(file_path) if stat.st_size < 10 * 1024 * 1024 else None  # Only hash files < 10MB
                    })
                except OSError:
                    pass
            
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
            
        except Exception:
            return None
    
    def _is_suspicious_file_activity(self, file_info: Dict[str, Any], event_type: str) -> bool:
        """Detect suspicious file activity"""
        try:
            file_path = file_info['path']
            file_name = os.path.basename(file_path).lower()
            
            detection_reasons = []
            
            # Check for ransomware-like patterns
            for pattern in self.suspicious_patterns:
                if pattern in file_name:
                    detection_reasons.append(f"suspicious_filename:{pattern}")
            
            # Check for mass file creation/modification (potential ransomware)
            if event_type in ['created', 'modified']:
                recent_events = self._count_recent_events_in_directory(os.path.dirname(file_path))
                if recent_events > 10:  # More than 10 files in same directory in short time
                    detection_reasons.append("mass_file_operation")
            
            # Check for execution of files from suspicious locations
            if event_type == 'created' and file_path.lower().endswith('.exe'):
                suspicious_locations = ['temp', 'downloads', 'appdata']
                if any(loc in file_path.lower() for loc in suspicious_locations):
                    detection_reasons.append("executable_in_suspicious_location")
            
            # Check for file extension changes (potential ransomware)
            if event_type == 'modified' and '.' in file_name:
                ext = Path(file_path).suffix.lower()
                suspicious_extensions = ['.encrypt', '.locked', '.crypto', '.crypt']
                if ext in suspicious_extensions:
                    detection_reasons.append("suspicious_extension")
            
            # Store detection reasons
            if detection_reasons:
                file_info['detection_reason'] = ', '.join(detection_reasons)
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error detecting suspicious activity: {e}")
            return False
    
    def _count_recent_events_in_directory(self, directory: str) -> int:
        """Count recent events in the same directory"""
        try:
            current_time = time.time()
            count = 0
            
            for key, timestamp in self.event_cache.items():
                if current_time - timestamp < 30:  # Events in last 30 seconds
                    event_path = key.split(':', 1)[1]
                    if os.path.dirname(event_path) == directory:
                        count += 1
            
            return count
            
        except Exception:
            return 0
    
    def _get_current_process_id(self) -> Optional[int]:
        """Get current process ID that might be accessing the file"""
        try:
            # This is simplified - in practice you'd use ETW or similar
            return os.getpid()
        except Exception:
            return None
    
    def _get_current_process_name(self) -> Optional[str]:
        """Get current process name"""
        try:
            current_proc = psutil.Process()
            return current_proc.name()
        except Exception:
            return None
    
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
                # Note: In practice, you'd need to stop the specific observer
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Error removing watch path {path}: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get monitor statistics"""
        try:
            return {
                'running': self.running,
                'active_observers': len([obs for obs in self.observers if obs.is_alive()]),
                'watched_paths': len(self.watch_paths),
                'monitored_extensions': len(self.monitored_extensions),
                'event_cache_size': len(self.event_cache),
                'exclude_paths': len(self.exclude_paths)
            }
        except Exception as e:
            self.logger.error(f"Error getting file monitor stats: {e}")
            return {'error': str(e)}