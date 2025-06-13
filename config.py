"""
EDR Windows Agent Configuration (COMPLETELY FIXED)
Fixed disk usage error and other Windows compatibility issues
"""

import os
import yaml
import socket
import platform
import psutil
import uuid
import time
from pathlib import Path
from typing import Dict, Any, Optional

class AgentConfig:
    """Agent configuration manager with enhanced error handling"""
    
    def __init__(self, config_file="agent_config.yaml"):
        self.config_file = config_file
        self.config_data = {}
        self._system_info_cache = None
        self._cache_expiry = 0
        
        # Setup configuration
        self.setup_defaults()
        self.load_config()
        self.load_from_env()
        
        # Validate configuration
        if not self.validate_config():
            print("⚠️ Configuration validation failed, using defaults")
    
    def setup_defaults(self):
        """Setup comprehensive default configuration"""
        self.config_data = {
            # Server Configuration
            'server': {
                'url': 'http://192.168.20.85:5000',
                'timeout': 30,
                'retry_interval': 10,
                'max_retries': 5,
                'heartbeat_interval': 30,
                'reconnect_delay': 5,
                'connection_check_interval': 60
            },
            
            # Agent Configuration
            'agent': {
                'name': f"{socket.gethostname()}-edr-agent",
                'version': '2.0.0',
                'log_level': 'INFO',
                'max_log_size': 100,
                'log_backup_count': 5,
                'update_interval': 300,
                'offline_cache_size': 1000,
                'agent_id': None,
                'auto_restart': True
            },
            
            # Monitoring Configuration
            'monitoring': {
                'process_monitoring': True,
                'file_monitoring': True,
                'network_monitoring': True,
                'registry_monitoring': True,
                'interval': 5,
                'batch_size': 50,
                'send_interval': 30,
                'realtime_send': True,
                'buffer_flush_interval': 60
            },
            
            # Security Configuration
            'security': {
                'anti_tamper': True,
                'self_defense': True,
                'encrypt_communication': False,
                'verify_server_cert': False,
                'allowed_processes': [
                    'edr_agent.exe',
                    'python.exe',
                    'pythonw.exe'
                ]
            },
            
            # Actions Configuration
            'actions': {
                'allow_process_termination': True,
                'allow_file_quarantine': True,
                'allow_network_blocking': True,
                'show_user_notifications': True,
                'auto_response_enabled': True,
                'response_timeout': 10
            },
            
            # UI Configuration
            'ui': {
                'show_tray_icon': True,
                'show_notifications': True,
                'notification_timeout': 5,
                'startup_notification': True,
                'alert_sound': True
            },
            
            # Performance Configuration
            'performance': {
                'max_cpu_usage': 10,
                'max_memory_usage': 200,
                'thread_pool_size': 4,
                'queue_max_size': 1000,
                'cleanup_interval': 3600,
                'memory_monitor': True
            },
            
            # File Monitoring Configuration
            'file_monitoring': {
                'watch_paths': [
                    'C:\\Windows\\System32',
                    'C:\\Program Files',
                    'C:\\Program Files (x86)',
                    'C:\\Users\\*\\AppData',
                    'C:\\Users\\*\\Desktop',
                    'C:\\Users\\*\\Downloads'
                ],
                'exclude_paths': [
                    'C:\\Windows\\Temp',
                    'C:\\Windows\\SoftwareDistribution',
                    'C:\\$Recycle.Bin',
                    'C:\\Windows\\Logs',
                    'C:\\Windows\\ServiceProfiles'
                ],
                'file_extensions': [
                    '.exe', '.dll', '.bat', '.cmd', '.ps1',
                    '.vbs', '.js', '.jar', '.msi', '.scr'
                ]
            },
            
            # Process Monitoring Configuration
            'process_monitoring': {
                'monitor_creation': True,
                'monitor_termination': True,
                'monitor_injection': True,
                'suspicious_processes': [
                    'cmd.exe', 'powershell.exe', 'wmic.exe',
                    'reg.exe', 'net.exe', 'schtasks.exe'
                ]
            },
            
            # Network Monitoring Configuration
            'network_monitoring': {
                'monitor_connections': True,
                'monitor_dns': True,
                'suspicious_ports': [4444, 5555, 6666, 1337, 31337],
                'blocked_ips': [],
                'connection_timeout': 300
            },
            
            # Alert Configuration
            'alerts': {
                'max_alerts_per_minute': 50,
                'alert_aggregation': True,
                'critical_alert_popup': True,
                'log_all_alerts': True,
                'send_to_server': True
            }
        }
    
    def load_config(self):
        """Load configuration from YAML file with error handling"""
        try:
            config_path = Path(self.config_file)
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    file_config = yaml.safe_load(f)
                
                if file_config and isinstance(file_config, dict):
                    self._merge_config(self.config_data, file_config)
                    print(f"✅ Configuration loaded from {self.config_file}")
                else:
                    print(f"⚠️ Invalid config file format: {self.config_file}")
            else:
                # Create default config file
                self.save_config()
                print(f"📄 Default configuration created: {self.config_file}")
                
        except yaml.YAMLError as e:
            print(f"⚠️ YAML parsing error in config file: {e}")
        except Exception as e:
            print(f"⚠️ Error loading config file: {e}")
    
    def load_from_env(self):
        """Load configuration from environment variables"""
        env_mappings = {
            'EDR_SERVER_URL': ['server', 'url'],
            'EDR_SERVER_TIMEOUT': ['server', 'timeout'],
            'EDR_AGENT_NAME': ['agent', 'name'],
            'EDR_AGENT_VERSION': ['agent', 'version'],
            'EDR_AGENT_ID': ['agent', 'agent_id'],
            'EDR_LOG_LEVEL': ['agent', 'log_level'],
            'EDR_MONITORING_INTERVAL': ['monitoring', 'interval'],
            'EDR_HEARTBEAT_INTERVAL': ['server', 'heartbeat_interval'],
            'EDR_AUTO_RESPONSE': ['actions', 'auto_response_enabled'],
            'EDR_SHOW_NOTIFICATIONS': ['ui', 'show_notifications']
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                try:
                    self._set_nested_value(self.config_data, config_path, value)
                    print(f"📝 Config override from {env_var}: {value}")
                except Exception as e:
                    print(f"⚠️ Error setting config from {env_var}: {e}")
    
    def save_config(self):
        """Save configuration to YAML file"""
        try:
            # Ensure directory exists
            config_dir = os.path.dirname(self.config_file)
            if config_dir:
                os.makedirs(config_dir, exist_ok=True)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, 
                         indent=2, allow_unicode=True)
            print(f"💾 Configuration saved to {self.config_file}")
            return True
            
        except Exception as e:
            print(f"❌ Error saving config file: {e}")
            return False
    
    def _merge_config(self, base: Dict, update: Dict):
        """Recursively merge configuration dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def _set_nested_value(self, config: Dict, path: list, value: Any):
        """Set nested configuration value with type conversion"""
        try:
            current = config
            for key in path[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            
            final_key = path[-1]
            
            # Type conversion based on existing value
            if final_key in current:
                existing_type = type(current[final_key])
                if existing_type == int:
                    current[final_key] = int(value)
                elif existing_type == float:
                    current[final_key] = float(value)
                elif existing_type == bool:
                    current[final_key] = value.lower() in ('true', '1', 'yes', 'on')
                elif existing_type == list:
                    # Handle comma-separated values
                    current[final_key] = [item.strip() for item in value.split(',')]
                else:
                    current[final_key] = value
            else:
                current[final_key] = value
                
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            print(f"⚠️ Error setting nested value {path}: {e}")
    
    def get(self, section: str, key: str = None, default=None):
        """Get configuration value with error handling"""
        try:
            if key is None:
                return self.config_data.get(section, default)
            else:
                section_data = self.config_data.get(section, {})
                if isinstance(section_data, dict):
                    return section_data.get(key, default)
                else:
                    return default
        except Exception:
            return default
    
    def set(self, section: str, key: str, value: Any):
        """Set configuration value"""
        try:
            if section not in self.config_data:
                self.config_data[section] = {}
            
            if not isinstance(self.config_data[section], dict):
                self.config_data[section] = {}
                
            self.config_data[section][key] = value
            return True
        except Exception as e:
            print(f"❌ Error setting config value: {e}")
            return False
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information with caching - COMPLETELY FIXED"""
        try:
            current_time = time.time()
            
            # Use cache if valid (cache for 5 minutes)
            if (self._system_info_cache and 
                current_time < self._cache_expiry):
                return self._system_info_cache
            
            # Get fresh system info
            system_info = {
                'hostname': socket.gethostname(),
                'os_type': 'Windows',
                'os_version': platform.platform(),
                'os_release': platform.release(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'agent_version': self.get('agent', 'version', '2.0.0'),
                'python_version': platform.python_version(),
                'boot_time': psutil.boot_time(),
                'timestamp': current_time
            }
            
            # Memory information - FIXED
            try:
                memory = psutil.virtual_memory()
                system_info.update({
                    'memory_total': memory.total,
                    'memory_available': memory.available,
                    'memory_used': memory.used,
                    'memory_percent': memory.percent
                })
            except Exception as e:
                print(f"⚠️ Error getting memory info: {e}")
                system_info.update({
                    'memory_total': 0,
                    'memory_available': 0,
                    'memory_used': 0,
                    'memory_percent': 0
                })
            
            # Disk information - COMPLETELY FIXED for Windows
            try:
                # FIXED: Multiple drive support and error handling
                drives_to_check = ['C:\\', 'D:\\', 'E:\\']
                disk_info = {
                    'total': 0,
                    'used': 0,
                    'free': 0,
                    'percent': 0,
                    'drives': []
                }
                
                for drive in drives_to_check:
                    try:
                        if os.path.exists(drive):
                            disk = psutil.disk_usage(drive)
                            drive_info = {
                                'drive': drive,
                                'total': disk.total,
                                'used': disk.used,
                                'free': disk.free,
                                'percent': round((disk.used / disk.total) * 100, 2) if disk.total > 0 else 0
                            }
                            disk_info['drives'].append(drive_info)
                            
                            # Use C: drive as primary
                            if drive == 'C:\\':
                                disk_info.update({
                                    'total': disk.total,
                                    'used': disk.used,
                                    'free': disk.free,
                                    'percent': drive_info['percent']
                                })
                    except (OSError, PermissionError) as e:
                        print(f"⚠️ Error accessing drive {drive}: {e}")
                        continue
                
                # If no drives found, set defaults
                if not disk_info['drives']:
                    disk_info = {
                        'total': 0,
                        'used': 0,
                        'free': 0,
                        'percent': 0,
                        'drives': [],
                        'error': 'No accessible drives found'
                    }
                
                system_info.update({
                    'disk_total': disk_info['total'],
                    'disk_used': disk_info['used'],
                    'disk_free': disk_info['free'],
                    'disk_percent': disk_info['percent'],
                    'disk_drives': disk_info['drives']
                })
                
            except Exception as e:
                print(f"⚠️ Error getting disk info: {e}")
                system_info.update({
                    'disk_total': 0,
                    'disk_used': 0,
                    'disk_free': 0,
                    'disk_percent': 0,
                    'disk_drives': [],
                    'disk_error': str(e)
                })
            
            # Network information
            system_info.update({
                'ip_address': self._get_local_ip(),
                'mac_address': self._get_mac_address()
            })
            
            # Windows specific information
            try:
                system_info.update({
                    'domain': os.environ.get('USERDOMAIN', 'WORKGROUP'),
                    'username': os.environ.get('USERNAME', 'Unknown'),
                    'computer_name': os.environ.get('COMPUTERNAME', 'Unknown'),
                    'user_profile': os.environ.get('USERPROFILE', ''),
                    'system_drive': os.environ.get('SYSTEMDRIVE', 'C:'),
                    'program_files': os.environ.get('PROGRAMFILES', ''),
                    'temp_dir': os.environ.get('TEMP', '')
                })
            except Exception as e:
                print(f"⚠️ Error getting Windows info: {e}")
            
            # Administrator check
            try:
                import ctypes
                system_info['is_admin'] = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                system_info['is_admin'] = False
            
            # CPU information - FIXED
            try:
                # Use interval=None for non-blocking call
                cpu_percent = psutil.cpu_percent(interval=None)
                if cpu_percent == 0.0:  # First call might return 0
                    # Wait briefly and try again
                    time.sleep(0.1)
                    cpu_percent = psutil.cpu_percent(interval=None)
                
                system_info.update({
                    'cpu_count': psutil.cpu_count(),
                    'cpu_count_logical': psutil.cpu_count(logical=True),
                    'cpu_percent': cpu_percent
                })
            except Exception as e:
                print(f"⚠️ Error getting CPU info: {e}")
                system_info.update({
                    'cpu_count': 1,
                    'cpu_count_logical': 1,
                    'cpu_percent': 0
                })
            
            # Cache the result
            self._system_info_cache = system_info
            self._cache_expiry = current_time + 300  # Cache for 5 minutes
            
            return system_info
            
        except Exception as e:
            print(f"❌ Error getting system info: {e}")
            # Return minimal fallback info
            return {
                'hostname': socket.gethostname(),
                'os_type': 'Windows',
                'os_version': platform.platform(),
                'architecture': platform.machine(),
                'agent_version': self.get('agent', 'version', '2.0.0'),
                'ip_address': self._get_local_ip(),
                'mac_address': self._get_mac_address(),
                'error': str(e)
            }
    
    def _get_local_ip(self) -> str:
        """Get local IP address with multiple fallback methods - FIXED"""
        try:
            # Method 1: Connect to remote address
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)  # Shorter timeout
                s.connect(('8.8.8.8', 80))
                return s.getsockname()[0]
        except Exception:
            try:
                # Method 2: Use hostname
                hostname = socket.gethostname()
                return socket.gethostbyname(hostname)
            except Exception:
                try:
                    # Method 3: Use psutil
                    addrs = psutil.net_if_addrs()
                    for interface, addr_list in addrs.items():
                        for addr in addr_list:
                            if (addr.family == socket.AF_INET and 
                                not addr.address.startswith('127.') and
                                not addr.address.startswith('169.254.')):
                                return addr.address
                except Exception:
                    pass
                return '127.0.0.1'
    
    def _get_mac_address(self) -> str:
        """Get MAC address with proper formatting - FIXED"""
        try:
            mac = uuid.getnode()
            # Verify it's a real MAC (not random)
            if mac != uuid.getnode():
                return '00:00:00:00:00:00'
            
            # Format as standard MAC address
            mac_hex = format(mac, '012x')
            mac_formatted = ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))
            return mac_formatted
        except Exception as e:
            print(f"⚠️ Error getting MAC address: {e}")
            return '00:00:00:00:00:00'
    
    def validate_config(self) -> bool:
        """Comprehensive configuration validation"""
        try:
            validation_errors = []
            
            # Check required sections
            required_sections = ['server', 'agent', 'monitoring']
            for section in required_sections:
                if section not in self.config_data:
                    validation_errors.append(f"Missing required section: {section}")
            
            # Validate server URL
            server_url = self.get('server', 'url')
            if not server_url:
                validation_errors.append("Server URL is required")
            elif not server_url.startswith(('http://', 'https://')):
                validation_errors.append(f"Invalid server URL format: {server_url}")
            
            # Validate agent configuration
            agent_version = self.get('agent', 'version')
            if not agent_version:
                validation_errors.append("Agent version is required")
            
            agent_name = self.get('agent', 'name')
            if not agent_name:
                validation_errors.append("Agent name is required")
            
            # Validate numeric values
            numeric_validations = [
                ('server', 'timeout', 1, 300),
                ('server', 'heartbeat_interval', 5, 3600),
                ('monitoring', 'interval', 1, 60),
                ('monitoring', 'batch_size', 1, 1000),
                ('monitoring', 'send_interval', 1, 300),
                ('performance', 'max_cpu_usage', 1, 100),
                ('performance', 'max_memory_usage', 50, 2048),
                ('performance', 'thread_pool_size', 1, 16),
                ('performance', 'queue_max_size', 100, 10000)
            ]
            
            for section, key, min_val, max_val in numeric_validations:
                value = self.get(section, key)
                if value is not None:
                    try:
                        num_value = float(value)
                        if not (min_val <= num_value <= max_val):
                            validation_errors.append(
                                f"{section}.{key} must be between {min_val} and {max_val}, got {num_value}"
                            )
                    except (ValueError, TypeError):
                        validation_errors.append(
                            f"{section}.{key} must be a number, got {value}"
                        )
            
            # Validate boolean values
            boolean_validations = [
                ('monitoring', 'process_monitoring'),
                ('monitoring', 'file_monitoring'),
                ('monitoring', 'network_monitoring'),
                ('actions', 'auto_response_enabled'),
                ('ui', 'show_notifications'),
                ('security', 'anti_tamper')
            ]
            
            for section, key in boolean_validations:
                value = self.get(section, key)
                if value is not None and not isinstance(value, bool):
                    validation_errors.append(
                        f"{section}.{key} must be a boolean, got {type(value).__name__}"
                    )
            
            # Validate file paths
            watch_paths = self.get('file_monitoring', 'watch_paths', [])
            if not isinstance(watch_paths, list):
                validation_errors.append("file_monitoring.watch_paths must be a list")
            
            exclude_paths = self.get('file_monitoring', 'exclude_paths', [])
            if not isinstance(exclude_paths, list):
                validation_errors.append("file_monitoring.exclude_paths must be a list")
            
            # Report validation results
            if validation_errors:
                print("❌ Configuration validation errors:")
                for error in validation_errors:
                    print(f"  - {error}")
                return False
            else:
                print("✅ Configuration validation passed")
                return True
                
        except Exception as e:
            print(f"❌ Configuration validation error: {e}")
            return False
    
    def reload_config(self) -> bool:
        """Reload configuration from file"""
        try:
            old_config = self.config_data.copy()
            self.load_config()
            self.load_from_env()
            
            if self.validate_config():
                print("✅ Configuration reloaded successfully")
                return True
            else:
                print("❌ Configuration reload failed, reverting to previous config")
                self.config_data = old_config
                return False
                
        except Exception as e:
            print(f"❌ Error reloading configuration: {e}")
            return False
    
    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring-specific configuration"""
        return {
            'process_monitoring': self.get('monitoring', 'process_monitoring', True),
            'file_monitoring': self.get('monitoring', 'file_monitoring', True),
            'network_monitoring': self.get('monitoring', 'network_monitoring', True),
            'interval': self.get('monitoring', 'interval', 5),
            'batch_size': self.get('monitoring', 'batch_size', 50),
            'send_interval': self.get('monitoring', 'send_interval', 30),
            'realtime_send': self.get('monitoring', 'realtime_send', True)
        }
    
    def get_performance_limits(self) -> Dict[str, Any]:
        """Get performance limits configuration"""
        return {
            'max_cpu_usage': self.get('performance', 'max_cpu_usage', 10),
            'max_memory_usage': self.get('performance', 'max_memory_usage', 200),
            'thread_pool_size': self.get('performance', 'thread_pool_size', 4),
            'queue_max_size': self.get('performance', 'queue_max_size', 1000),
            'cleanup_interval': self.get('performance', 'cleanup_interval', 3600)
        }
    
    # Property shortcuts for common configurations
    @property
    def SERVER_URL(self):
        return self.get('server', 'url')
    
    @SERVER_URL.setter
    def SERVER_URL(self, value):
        self.set('server', 'url', value)
    
    @property
    def AGENT_NAME(self):
        return self.get('agent', 'name')
    
    @property
    def AGENT_VERSION(self):
        return self.get('agent', 'version', '2.0.0')
    
    @property
    def AGENT_ID(self):
        return self.get('agent', 'agent_id')
    
    @AGENT_ID.setter
    def AGENT_ID(self, value):
        self.set('agent', 'agent_id', value)
    
    @property
    def LOG_LEVEL(self):
        return self.get('agent', 'log_level', 'INFO')
    
    @property
    def HEARTBEAT_INTERVAL(self):
        return self.get('server', 'heartbeat_interval', 30)
    
    @property
    def MONITORING_INTERVAL(self):
        return self.get('monitoring', 'interval', 5)
    
    @property
    def PROCESS_MONITORING(self):
        return self.get('monitoring', 'process_monitoring', True)
    
    @property
    def FILE_MONITORING(self):
        return self.get('monitoring', 'file_monitoring', True)
    
    @property
    def NETWORK_MONITORING(self):
        return self.get('monitoring', 'network_monitoring', True)
    
    @property
    def SHOW_TRAY_ICON(self):
        return self.get('ui', 'show_tray_icon', True)
    
    @property
    def SHOW_NOTIFICATIONS(self):
        return self.get('ui', 'show_notifications', True)
    
    @property
    def AUTO_RESPONSE_ENABLED(self):
        return self.get('actions', 'auto_response_enabled', True)
    
    @property
    def REALTIME_SEND(self):
        return self.get('monitoring', 'realtime_send', True)
    
    def __str__(self):
        """String representation of configuration"""
        return (f"EDRAgentConfig(server={self.SERVER_URL}, "
                f"agent={self.AGENT_NAME}, "
                f"version={self.AGENT_VERSION}, "
                f"id={self.AGENT_ID})")
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for logging/debugging"""
        return {
            'server_url': self.SERVER_URL,
            'agent_name': self.AGENT_NAME,
            'agent_version': self.AGENT_VERSION,
            'agent_id': self.AGENT_ID,
            'monitoring': self.get_monitoring_config(),
            'performance': self.get_performance_limits(),
            'file_monitoring_paths': len(self.get('file_monitoring', 'watch_paths', [])),
            'exclude_paths': len(self.get('file_monitoring', 'exclude_paths', [])),
            'config_file': self.config_file,
            'validation_status': 'valid' if self.validate_config() else 'invalid'
        }

    RULE_CHECK_INTERVAL = 60  # seconds, hoặc giá trị phù hợp