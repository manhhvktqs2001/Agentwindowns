"""
EDR Windows Agent Configuration
"""

import os
import yaml
import socket
import platform
from pathlib import Path
from typing import Dict, Any

class AgentConfig:
    """Agent configuration manager"""
    
    def __init__(self, config_file="agent_config.yaml"):
        self.config_file = config_file
        self.config_data = {}
        
        # Default configuration
        self.setup_defaults()
        
        # Load from file if exists
        self.load_config()
        
        # Override with environment variables
        self.load_from_env()
    
    def setup_defaults(self):
        """Setup default configuration"""
        self.config_data = {
            # Server Configuration
            'server': {
                'url': 'http://192.168.20.85:5000',
                'timeout': 30,
                'retry_interval': 10,
                'max_retries': 5,
                'heartbeat_interval': 30,
                'reconnect_delay': 5
            },
            
            # Agent Configuration
            'agent': {
                'name': f"{socket.gethostname()}-edr-agent",
                'version': '2.0.0',
                'log_level': 'INFO',
                'max_log_size': 100,  # MB
                'log_backup_count': 5,
                'update_interval': 300,  # 5 minutes
                'offline_cache_size': 1000
            },
            
            # Monitoring Configuration
            'monitoring': {
                'process_monitoring': True,
                'file_monitoring': True,
                'network_monitoring': True,
                'registry_monitoring': True,
                'interval': 5,  # seconds
                'batch_size': 50,
                'send_interval': 30  # seconds
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
                'response_timeout': 10  # seconds
            },
            
            # UI Configuration
            'ui': {
                'show_tray_icon': True,
                'show_notifications': True,
                'notification_timeout': 5,  # seconds
                'startup_notification': True,
                'alert_sound': True
            },
            
            # Performance Configuration
            'performance': {
                'max_cpu_usage': 10,  # percentage
                'max_memory_usage': 200,  # MB
                'thread_pool_size': 4,
                'queue_max_size': 1000,
                'cleanup_interval': 3600  # 1 hour
            }
        }
    
    def load_config(self):
        """Load configuration from YAML file"""
        try:
            config_path = Path(self.config_file)
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    file_config = yaml.safe_load(f)
                
                if file_config:
                    self._merge_config(self.config_data, file_config)
                    print(f"✅ Configuration loaded from {self.config_file}")
            else:
                # Create default config file
                self.save_config()
                print(f"📄 Default configuration created: {self.config_file}")
                
        except Exception as e:
            print(f"⚠️ Error loading config file: {e}")
    
    def load_from_env(self):
        """Load configuration from environment variables"""
        env_mappings = {
            'EDR_SERVER_URL': ['server', 'url'],
            'EDR_SERVER_TIMEOUT': ['server', 'timeout'],
            'EDR_AGENT_NAME': ['agent', 'name'],
            'EDR_LOG_LEVEL': ['agent', 'log_level'],
            'EDR_MONITORING_INTERVAL': ['monitoring', 'interval'],
            'EDR_HEARTBEAT_INTERVAL': ['server', 'heartbeat_interval']
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                self._set_nested_value(self.config_data, config_path, value)
                print(f"📝 Config override from {env_var}: {value}")
    
    def save_config(self):
        """Save configuration to YAML file"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
            print(f"💾 Configuration saved to {self.config_file}")
            
        except Exception as e:
            print(f"❌ Error saving config file: {e}")
    
    def _merge_config(self, base: Dict, update: Dict):
        """Recursively merge configuration dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def _set_nested_value(self, config: Dict, path: list, value: Any):
        """Set nested configuration value"""
        try:
            current = config
            for key in path[:-1]:
                current = current[key]
            
            # Try to convert to appropriate type
            if isinstance(current[path[-1]], int):
                current[path[-1]] = int(value)
            elif isinstance(current[path[-1]], float):
                current[path[-1]] = float(value)
            elif isinstance(current[path[-1]], bool):
                current[path[-1]] = value.lower() in ('true', '1', 'yes', 'on')
            else:
                current[path[-1]] = value
                
        except (KeyError, ValueError, TypeError):
            pass
    
    def get(self, section: str, key: str = None, default=None):
        """Get configuration value"""
        try:
            if key is None:
                return self.config_data.get(section, default)
            else:
                return self.config_data.get(section, {}).get(key, default)
        except:
            return default
    
    def set(self, section: str, key: str, value: Any):
        """Set configuration value"""
        if section not in self.config_data:
            self.config_data[section] = {}
        self.config_data[section][key] = value
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        try:
            import psutil
            
            system_info = {
                'hostname': socket.gethostname(),
                'os_type': 'Windows',
                'os_version': platform.platform(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'memory_total': psutil.virtual_memory().total,
                'disk_total': psutil.disk_usage('C:').total,
                'ip_address': self._get_local_ip(),
                'mac_address': self._get_mac_address(),
                'domain': os.environ.get('USERDOMAIN', 'WORKGROUP'),
                'username': os.environ.get('USERNAME', 'Unknown')
            }
            
            return system_info
            
        except Exception as e:
            print(f"Error getting system info: {e}")
            return {
                'hostname': socket.gethostname(),
                'os_type': 'Windows',
                'os_version': platform.platform(),
                'architecture': platform.architecture()[0]
            }
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                return s.getsockname()[0]
        except:
            return '127.0.0.1'
    
    def _get_mac_address(self) -> str:
        """Get MAC address"""
        try:
            import uuid
            mac = uuid.getnode()
            return ':'.join(['{:02x}'.format((mac >> elements) & 0xff) 
                           for elements in range(0, 2*6, 2)][::-1])
        except:
            return '00:00:00:00:00:00'
    
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
    def LOG_LEVEL(self):
        return self.get('agent', 'log_level')
    
    @property
    def HEARTBEAT_INTERVAL(self):
        return self.get('server', 'heartbeat_interval')
    
    @property
    def MONITORING_INTERVAL(self):
        return self.get('monitoring', 'interval')
    
    @property
    def PROCESS_MONITORING(self):
        return self.get('monitoring', 'process_monitoring')
    
    @property
    def FILE_MONITORING(self):
        return self.get('monitoring', 'file_monitoring')
    
    @property
    def NETWORK_MONITORING(self):
        return self.get('monitoring', 'network_monitoring')
    
    @property
    def SHOW_TRAY_ICON(self):
        return self.get('ui', 'show_tray_icon')
    
    @property
    def SHOW_NOTIFICATIONS(self):
        return self.get('ui', 'show_notifications')
    
    @property
    def AUTO_RESPONSE_ENABLED(self):
        return self.get('actions', 'auto_response_enabled')
    
    def validate_config(self) -> bool:
        """Validate configuration"""
        try:
            # Check required sections
            required_sections = ['server', 'agent', 'monitoring']
            for section in required_sections:
                if section not in self.config_data:
                    print(f"❌ Missing required config section: {section}")
                    return False
            
            # Validate server URL
            server_url = self.SERVER_URL
            if not server_url or not server_url.startswith(('http://', 'https://')):
                print(f"❌ Invalid server URL: {server_url}")
                return False
            
            # Validate numeric values
            numeric_checks = [
                (self.get('server', 'timeout'), 'server timeout'),
                (self.get('monitoring', 'interval'), 'monitoring interval'),
                (self.get('server', 'heartbeat_interval'), 'heartbeat interval')
            ]
            
            for value, name in numeric_checks:
                if not isinstance(value, (int, float)) or value <= 0:
                    print(f"❌ Invalid {name}: {value}")
                    return False
            
            print("✅ Configuration validation passed")
            return True
            
        except Exception as e:
            print(f"❌ Configuration validation error: {e}")
            return False
    
    def __str__(self):
        """String representation of configuration"""
        return f"EDRAgentConfig(server={self.SERVER_URL}, agent={self.AGENT_NAME})"