"""
EDR Windows Agent - Server Connection Manager (FIXED)
"""

import json
import time
import logging
import threading
import requests
import socketio
from typing import Dict, Any, Optional, Callable
from datetime import datetime

class ServerConnection:
    """Handles communication with EDR Server"""
    
    def __init__(self, config, agent_instance):
        self.config = config
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)
        
        # Connection state
        self.connected = False
        self.agent_id = None  # FIXED: Store agent ID from server
        self.last_heartbeat = None
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = self.config.get('server', 'max_retries', 5)
        self.reconnect_delay = self.config.get('server', 'reconnect_delay', 5)
        
        # Socket.IO client
        self.sio = socketio.Client(
            reconnection=True,
            reconnection_attempts=self.max_reconnect_attempts,
            reconnection_delay=self.reconnect_delay,
            logger=False,
            engineio_logger=False
        )
        
        # Setup event handlers
        self._setup_event_handlers()
        
        # Threading
        self.connection_lock = threading.Lock()
        
        # FIXED: Load agent ID if exists
        self.agent_id = self.config.get('agent', 'agent_id')
        
        self.logger.info("✅ Server connection initialized")
    
    def _setup_event_handlers(self):
        """Setup Socket.IO event handlers"""
        
        @self.sio.event
        def connect():
            """Handle successful connection"""
            with self.connection_lock:
                self.connected = True
                self.reconnect_attempts = 0
                
            self.logger.info("🔗 Connected to EDR Server")
            
            # Send agent info immediately after connection
            self._send_agent_info()
            
            # FIXED: Join agent room for targeted messaging
            if self.agent_id:
                self.sio.emit('join_agent_room', {'agent_id': self.agent_id})
        
        @self.sio.event
        def disconnect():
            """Handle disconnection"""
            with self.connection_lock:
                self.connected = False
                
            self.logger.warning("⚠️ Disconnected from EDR Server")
        
        @self.sio.event
        def connect_error(data):
            """Handle connection errors"""
            self.logger.error(f"❌ Connection error: {data}")
            with self.connection_lock:
                self.connected = False
                self.reconnect_attempts += 1
        
        @self.sio.event
        def command(data):
            """Handle commands from server"""
            try:
                self.logger.info(f"📨 Received command: {data.get('type', 'unknown')}")
                if self.agent:
                    self.agent.handle_server_command(data)
            except Exception as e:
                self.logger.error(f"Error handling command: {e}")
        
        @self.sio.event
        def alert(data):
            """Handle alerts from server"""
            try:
                self.logger.warning(f"🚨 Received alert: {data.get('title', 'Security Alert')}")
                if self.agent:
                    self.agent.handle_server_command({
                        'type': 'alert',
                        'params': data
                    })
            except Exception as e:
                self.logger.error(f"Error handling alert: {e}")
        
        @self.sio.event
        def rule_update(data):
            """Handle rule updates from server"""
            try:
                self.logger.info("📋 Received rule update")
                # FIXED: Better rule update handling
                if self.agent and hasattr(self.agent, 'update_rules'):
                    self.agent.update_rules(data.get('rules', []))
            except Exception as e:
                self.logger.error(f"Error handling rule update: {e}")
        
        @self.sio.event
        def heartbeat_response(data):
            """Handle heartbeat response"""
            self.last_heartbeat = datetime.utcnow()
            self.logger.debug("💓 Heartbeat acknowledged")
            
        @self.sio.event
        def registration_complete(data):
            """Handle registration completion"""
            try:
                self.agent_id = data.get('agent_id')
                if self.agent_id:
                    self.config.set('agent', 'agent_id', self.agent_id)
                    self.config.save_config()
                    self.logger.info(f"✅ Agent registered with ID: {self.agent_id}")
            except Exception as e:
                self.logger.error(f"Error handling registration: {e}")
    
    def start(self) -> bool:
        """Start connection to server"""
        try:
            server_url = self.config.SERVER_URL
            self.logger.info(f"🚀 Connecting to EDR Server: {server_url}")
            
            # Test HTTP connectivity first
            if not self._test_http_connection():
                return False
            
            # Connect Socket.IO
            self.sio.connect(
                server_url,
                headers={
                    'User-Agent': f'EDR-Agent/{self.config.get("agent", "version")}',
                    'X-Agent-Hostname': self.config.get_system_info().get('hostname', 'unknown'),
                    'X-Agent-ID': self.agent_id or 'new'  # FIXED: Send agent ID if exists
                },
                timeout=self.config.get('server', 'timeout', 30)
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to connect to server: {e}")
            return False
    
    def stop(self):
        """Stop connection to server"""
        try:
            if self.sio.connected:
                # FIXED: Send disconnect notification
                self.sio.emit('agent_disconnect', {
                    'agent_id': self.agent_id,
                    'hostname': self.config.get_system_info().get('hostname'),
                    'timestamp': datetime.utcnow().isoformat()
                })
                self.sio.disconnect()
            
            with self.connection_lock:
                self.connected = False
                
            self.logger.info("🛑 Server connection stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping connection: {e}")
    
    def reconnect(self) -> bool:
        """Attempt to reconnect to server"""
        try:
            if self.connected:
                return True
            
            self.logger.info("🔄 Attempting to reconnect...")
            
            # Wait before reconnection attempt
            time.sleep(self.reconnect_delay)
            
            return self.start()
            
        except Exception as e:
            self.logger.error(f"Reconnection failed: {e}")
            return False
    
    def _test_http_connection(self) -> bool:
        """Test basic HTTP connectivity to server"""
        try:
            base_url = self.config.SERVER_URL.replace('/socket.io', '')
            test_url = f"{base_url}/api/health"
            
            response = requests.get(
                test_url,
                timeout=self.config.get('server', 'timeout', 30),
                headers={'User-Agent': f'EDR-Agent/{self.config.get("agent", "version")}'}
            )
            
            if response.status_code == 200:
                self.logger.debug("✅ HTTP connectivity test passed")
                return True
            else:
                self.logger.warning(f"⚠️ HTTP test failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ HTTP connectivity test failed: {e}")
            return False
    
    def _send_agent_info(self):
        """Send agent information to server"""
        try:
            if not self.connected:
                return False
            
            system_info = self.config.get_system_info()
            agent_info = {
                'agent_id': self.agent_id,  # FIXED: Include agent ID
                'hostname': system_info.get('hostname'),
                'os_type': system_info.get('os_type'),
                'os_version': system_info.get('os_version'),
                'architecture': system_info.get('architecture'),
                'ip_address': system_info.get('ip_address'),
                'mac_address': system_info.get('mac_address'),
                'agent_version': self.config.get('agent', 'version'),
                'timestamp': datetime.utcnow().isoformat(),
                'capabilities': {  # FIXED: Send agent capabilities
                    'process_monitoring': self.config.get('monitoring', 'process_monitoring', True),
                    'file_monitoring': self.config.get('monitoring', 'file_monitoring', True),
                    'network_monitoring': self.config.get('monitoring', 'network_monitoring', True),
                    'response_actions': self.config.get('actions', 'auto_response_enabled', True)
                }
            }
            
            self.sio.emit('agent_info', agent_info)
            self.logger.debug("📤 Agent info sent to server")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending agent info: {e}")
            return False
    
    def register_agent(self, registration_data: Dict[str, Any]) -> bool:
        """Register agent with EDR server"""
        try:
            base_url = self.config.SERVER_URL.replace('/socket.io', '')
            register_url = f"{base_url}/api/agents/register"
            
            # FIXED: Include more system information
            enhanced_data = {
                **registration_data,
                'agent_id': self.agent_id,  # Send existing agent ID if any
                'first_seen': datetime.utcnow().isoformat(),
                'capabilities': {
                    'process_monitoring': True,
                    'file_monitoring': True,
                    'network_monitoring': True,
                    'response_actions': True,
                    'quarantine': True,
                    'network_blocking': True
                }
            }
            
            response = requests.post(
                register_url,
                json=enhanced_data,
                timeout=self.config.get('server', 'timeout', 30),
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': f'EDR-Agent/{self.config.get("agent", "version")}'
                }
            )
            
            if response.status_code in [200, 201]:
                # FIXED: Handle server response properly
                try:
                    response_data = response.json()
                    if 'agent_id' in response_data:
                        self.agent_id = response_data['agent_id']
                        self.config.set('agent', 'agent_id', self.agent_id)
                        self.config.save_config()
                    
                    if 'rules' in response_data:
                        # Store initial rules
                        self.config.set('agent', 'rules', response_data['rules'])
                        
                except Exception as json_error:
                    self.logger.warning(f"Could not parse registration response: {json_error}")
                
                self.logger.info("✅ Agent registered successfully")
                return True
            else:
                self.logger.error(f"❌ Registration failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Registration error: {e}")
            return False
    
    def send_heartbeat(self) -> bool:
        """Send heartbeat to server"""
        try:
            if not self.connected:
                return False
            
            # FIXED: Include more status information
            heartbeat_data = {
                'agent_id': self.agent_id,
                'hostname': self.config.get_system_info().get('hostname'),
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'Online',
                'agent_version': self.config.get('agent', 'version'),
                'cpu_usage': self._get_cpu_usage(),
                'memory_usage': self._get_memory_usage(),
                'disk_usage': self._get_disk_usage()
            }
            
            self.sio.emit('heartbeat', heartbeat_data)
            self.logger.debug("💓 Heartbeat sent")
            return True
            
        except Exception as e:
            self.logger.error(f"Heartbeat error: {e}")
            return False
    
    def send_logs(self, log_data: Dict[str, Any]) -> bool:
        """Send log data to server"""
        try:
            if not self.connected:
                return False
            
            # FIXED: Add agent identification
            enhanced_log_data = {
                **log_data,
                'agent_id': self.agent_id,
                'hostname': self.config.get_system_info().get('hostname'),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.sio.emit('logs', enhanced_log_data)
            self.logger.debug(f"📤 Logs sent: {sum(len(v) if isinstance(v, list) else 1 for v in log_data.values())} events")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending logs: {e}")
            return False
    
    def send_http_logs(self, log_data: Dict[str, Any]) -> bool:
        """Send logs via HTTP as fallback"""
        try:
            base_url = self.config.SERVER_URL.replace('/socket.io', '')
            logs_url = f"{base_url}/api/logs"
            
            # FIXED: Add agent identification
            enhanced_log_data = {
                **log_data,
                'agent_id': self.agent_id,
                'hostname': self.config.get_system_info().get('hostname'),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            response = requests.post(
                logs_url,
                json=enhanced_log_data,
                timeout=self.config.get('server', 'timeout', 30),
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': f'EDR-Agent/{self.config.get("agent", "version")}',
                    'X-Agent-ID': self.agent_id or 'unknown'
                }
            )
            
            if response.status_code in [200, 201]:
                self.logger.debug("📤 HTTP logs sent successfully")
                return True
            else:
                self.logger.warning(f"⚠️ HTTP logs failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"HTTP logs error: {e}")
            return False
    
    def get_rules(self) -> Optional[List[Dict[str, Any]]]:
        """Get rules from server"""
        try:
            base_url = self.config.SERVER_URL.replace('/socket.io', '')
            rules_url = f"{base_url}/api/rules"
            
            hostname = self.config.get_system_info().get('hostname')
            
            response = requests.get(
                rules_url,
                params={
                    'hostname': hostname,
                    'agent_id': self.agent_id,  # FIXED: Include agent ID
                    'os_type': 'Windows'
                },
                timeout=self.config.get('server', 'timeout', 30),
                headers={'User-Agent': f'EDR-Agent/{self.config.get("agent", "version")}'}
            )
            
            if response.status_code == 200:
                rules = response.json().get('rules', [])
                self.logger.info(f"📋 Retrieved {len(rules)} rules from server")
                return rules
            else:
                self.logger.warning(f"⚠️ Failed to get rules: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting rules: {e}")
            return None
    
    def report_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Report alert to server"""
        try:
            # FIXED: Add agent identification
            enhanced_alert = {
                **alert_data,
                'agent_id': self.agent_id,
                'hostname': self.config.get_system_info().get('hostname'),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            if self.connected:
                # Try Socket.IO first
                self.sio.emit('agent_alert', enhanced_alert)
                return True
            else:
                # Fallback to HTTP
                base_url = self.config.SERVER_URL.replace('/socket.io', '')
                alert_url = f"{base_url}/api/alerts"
                
                response = requests.post(
                    alert_url,
                    json=enhanced_alert,
                    timeout=self.config.get('server', 'timeout', 30),
                    headers={
                        'Content-Type': 'application/json',
                        'User-Agent': f'EDR-Agent/{self.config.get("agent", "version")}',
                        'X-Agent-ID': self.agent_id or 'unknown'
                    }
                )
                
                return response.status_code in [200, 201]
                
        except Exception as e:
            self.logger.error(f"Error reporting alert: {e}")
            return False
    
    def _get_cpu_usage(self) -> float:
        """Get current CPU usage"""
        try:
            import psutil
            return psutil.cpu_percent(interval=1)
        except Exception:
            return 0.0
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage percentage"""
        try:
            import psutil
            return psutil.virtual_memory().percent
        except Exception:
            return 0.0
    
    def _get_disk_usage(self) -> float:
        """Get current disk usage percentage"""
        try:
            import psutil
            return psutil.disk_usage('C:').percent
        except Exception:
            return 0.0
    
    def is_connected(self) -> bool:
        """Check if connected to server"""
        return self.connected and self.sio.connected
    
    def get_connection_status(self) -> Dict[str, Any]:
        """Get detailed connection status"""
        return {
            'connected': self.connected,
            'socket_connected': self.sio.connected,
            'agent_id': self.agent_id,
            'server_url': self.config.SERVER_URL,
            'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            'reconnect_attempts': self.reconnect_attempts,
            'max_reconnect_attempts': self.max_reconnect_attempts
        }