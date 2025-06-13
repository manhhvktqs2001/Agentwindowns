"""
EDR Windows Agent - Server Connection Manager (FIXED)
Fixed urllib3 compatibility issue
"""

import json
import time
import logging
import threading
import requests
import socketio
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime
import os
import platform
import socket
import queue
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings for development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class ServerConnection:
    """Handles robust communication with EDR Server"""
    
    def __init__(self, config, agent_instance):
        self.config = config
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)
        self.server_url = config.SERVER_URL
        
        # Connection configuration
        self.server_url = config.SERVER_URL
        self.base_url = self.server_url.replace('/socket.io', '') if '/socket.io' in self.server_url else self.server_url
        self.timeout = config.get('server', 'timeout', 30)
        self.heartbeat_interval = config.get('server', 'heartbeat_interval', 30)
        self.reconnect_delay = config.get('server', 'reconnect_delay', 5)
        self.max_reconnect_attempts = config.get('server', 'max_retries', 10)
        
        # Connection state
        self.connected = False
        self.authenticated = False
        self.agent_id = config.get('agent', 'agent_id')
        self.last_heartbeat = None
        self.last_successful_send = None
        self.reconnect_attempts = 0
        self.connection_start_time = None
        
        # Threading
        self.connection_lock = threading.Lock()
        self.running = False
        self.heartbeat_thread = None
        self.reconnect_thread = None
        self.connection_monitor_thread = None
        
        # Data queues for real-time sending
        self.data_queue = queue.Queue(maxsize=1000)
        self.priority_queue = queue.Queue(maxsize=500)  # For alerts and critical data
        self.failed_requests = queue.Queue(maxsize=200)
        
        # HTTP session with retry strategy - FIXED: Use allowed_methods instead of method_whitelist
        self.session = requests.Session()
        try:
            # Try new parameter name first
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
            )
        except TypeError:
            # Fallback to old parameter name for older urllib3 versions
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                method_whitelist=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
            )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Initialize Socket.IO client
        self.sio = None
        self._initialize_socketio()
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'successful_sends': 0,
            'failed_sends': 0,
            'reconnections': 0,
            'last_error': None,
            'uptime': 0,
            'data_sent_bytes': 0,
            'alerts_received': 0,
            'commands_received': 0
        }
        
        # Setup event handlers
        self._setup_event_handlers()
        self._setup_http_headers()
        
        self.logger.info("✅ Server connection manager initialized")
        
        self.hostname = None
        try:
            self.hostname = socket.gethostname()
        except Exception as e:
            self.hostname = None
            self.logger.error(f"Could not get system hostname: {e}")
    
    def _initialize_socketio(self):
        """Initialize Socket.IO client with enhanced configuration"""
        try:
            self.sio = socketio.Client(
                reconnection=True,
                reconnection_attempts=self.max_reconnect_attempts,
                reconnection_delay=self.reconnect_delay,
                reconnection_delay_max=60,
                randomization_factor=0.5,
                logger=False,
                engineio_logger=False
            )
            self.logger.info("✅ Socket.IO client initialized")
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Socket.IO client: {e}")
            self.sio = None
    
    def _setup_http_headers(self):
        """Setup HTTP session headers"""
        self.session.headers.update({
            'User-Agent': f'EDR-Agent/{self.config.get("agent", "version", "2.0.0")}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Agent-Version': self.config.get("agent", "version", "2.0.0"),
            'X-Agent-Platform': 'Windows'
        })
        
        if self.agent_id:
            self.session.headers['X-Agent-ID'] = self.agent_id
    
    def _setup_event_handlers(self):
        """Setup Socket.IO event handlers with comprehensive error handling"""
        if not self.sio:
            self.logger.error("❌ Cannot setup event handlers: Socket.IO client not initialized")
            return
            
        @self.sio.event
        def connect():
            """Handle successful Socket.IO connection"""
            with self.connection_lock:
                self.connected = True
                self.reconnect_attempts = 0
                self.connection_start_time = time.time()
                self.stats['total_connections'] += 1
                
            self.logger.info("🔗 Socket.IO connected to EDR Server")
            
            # Send agent registration immediately
            self._register_with_server()
            
            # Join agent room for targeted messaging
            if self.agent_id:
                self.sio.emit('join_agent_room', {'agent_id': self.agent_id})
            
            # Start data sending threads
            self._start_data_workers()
        
        @self.sio.event
        def disconnect():
            """Handle Socket.IO disconnection"""
            with self.connection_lock:
                self.connected = False
                self.authenticated = False
                
            self.logger.warning("⚠️ Socket.IO disconnected from EDR Server")
            
            # Schedule reconnection
            self._schedule_reconnection()
        
        @self.sio.event
        def connect_error(data):
            """Handle Socket.IO connection errors"""
            with self.connection_lock:
                self.connected = False
                self.reconnect_attempts += 1
                self.stats['last_error'] = f"Connection error: {data}"
                
            self.logger.error(f"❌ Socket.IO connection error: {data}")
            self._schedule_reconnection()
        
        @self.sio.event
        def agent_command(data):
            """Handle commands from server"""
            try:
                self.stats['commands_received'] += 1
                self.logger.info(f"📨 Received command: {data.get('type', 'unknown')}")
                
                if self.agent and hasattr(self.agent, 'handle_server_command'):
                    # Process command in separate thread to avoid blocking
                    command_thread = threading.Thread(
                        target=self.agent.handle_server_command,
                        args=(data,),
                        daemon=True
                    )
                    command_thread.start()
                else:
                    self.logger.warning("⚠️ Agent not available to handle command")
                    
            except Exception as e:
                self.logger.error(f"Error handling server command: {e}")
        
        @self.sio.event
        def agent_alert(data):
            """Handle alerts from server"""
            try:
                self.stats['alerts_received'] += 1
                self.logger.warning(f"🚨 Received alert: {data.get('title', 'Security Alert')}")
                
                if self.agent and hasattr(self.agent, 'handle_server_alert'):
                    self.agent.handle_server_alert(data)
                elif self.agent and hasattr(self.agent, 'notification_actions'):
                    # Show notification if agent has notification system
                    self.agent.notification_actions.show_alert(data)
                else:
                    self.logger.warning("⚠️ No alert handler available")
                    
            except Exception as e:
                self.logger.error(f"Error handling server alert: {e}")
        
        @self.sio.event
        def rule_update(data):
            """Handle rule updates from server"""
            try:
                self.logger.info("📋 Received rule update from server")
                
                rules = data.get('rules', [])
                if self.agent and hasattr(self.agent, 'update_rules'):
                    self.agent.update_rules(rules)
                    self.logger.info(f"✅ Updated {len(rules)} rules")
                else:
                    self.logger.warning("⚠️ Agent not available to update rules")
                    
            except Exception as e:
                self.logger.error(f"Error handling rule update: {e}")
        
        @self.sio.event
        def heartbeat_response(data):
            """Handle heartbeat response from server"""
            self.last_heartbeat = datetime.utcnow()
            self.logger.debug("💓 Heartbeat acknowledged by server")
            
        @self.sio.event
        def registration_complete(data):
            """Handle agent registration completion"""
            try:
                self.agent_id = data.get('agent_id')
                if self.agent_id:
                    # Update configuration
                    self.config.set('agent', 'agent_id', self.agent_id)
                    self.config.save_config()
                    
                    # Update HTTP headers
                    self.session.headers['X-Agent-ID'] = self.agent_id
                    
                    self.authenticated = True
                    self.logger.info(f"✅ Agent registered with ID: {self.agent_id}")
                    
                    # Request initial rules
                    self.sio.emit('request_rules', {'agent_id': self.agent_id})
                else:
                    self.logger.error("❌ Registration failed: No agent ID received")
                    
            except Exception as e:
                self.logger.error(f"Error handling registration completion: {e}")
        
        @self.sio.event
        def server_status(data):
            """Handle server status updates"""
            try:
                status = data.get('status', 'unknown')
                self.logger.info(f"📊 Server status: {status}")
                
                if status == 'maintenance':
                    self.logger.warning("⚠️ Server entering maintenance mode")
                elif status == 'overloaded':
                    self.logger.warning("⚠️ Server is overloaded, reducing send frequency")
                    # Implement backoff logic here
                    
            except Exception as e:
                self.logger.error(f"Error handling server status: {e}")
    
    def start(self) -> bool:
        """Start connection to server with comprehensive error handling"""
        try:
            if self.running:
                return True
            self.running = True
            self.logger.info(f"🚀 Starting connection to EDR Server: {self.server_url}")
            # Test basic HTTP connectivity first
            if not self._test_http_connectivity():
                self.logger.error("❌ Basic HTTP connectivity test failed")
                return False
            # Try to establish Socket.IO connection
            success = self._connect_socketio()
            if success:
                # Start background threads
                self._start_background_threads()
                self.logger.info("✅ Server connection started successfully")
                return True
            else:
                self.logger.error("❌ Failed to establish Socket.IO connection")
                # Continue in HTTP-only mode
                self._start_background_threads()
                return True  # Still return True for HTTP fallback
        except Exception as e:
            self.logger.error(f"❌ Failed to start server connection: {e}")
            self.stats['last_error'] = str(e)
            return False
    
    def stop(self):
        """Stop connection to server with proper cleanup"""
        try:
            self.logger.info("🛑 Stopping server connection...")
            self.running = False
            # Send disconnect notification if connected
            if self.connected and self.agent_id:
                try:
                    disconnect_data = {
                        'agent_id': self.agent_id,
                        'hostname': self.config.get_system_info().get('hostname'),
                        'timestamp': datetime.utcnow().isoformat(),
                        'reason': 'agent_shutdown'
                    }
                    if self.sio.connected:
                        self.sio.emit('agent_disconnect', disconnect_data)
                        time.sleep(1)  # Give time for message to send
                    else:
                        # Try HTTP if Socket.IO not available
                        self._send_http_request('POST', '/api/agents/disconnect', disconnect_data)
                except Exception as e:
                    self.logger.debug(f"Error sending disconnect notification: {e}")
            # Disconnect Socket.IO
            if self.sio.connected:
                self.sio.disconnect()
            # Wait for background threads to finish
            threads_to_wait = [
                self.heartbeat_thread,
                self.reconnect_thread,
                self.connection_monitor_thread
            ]
            for thread in threads_to_wait:
                if thread and thread.is_alive():
                    thread.join(timeout=5)
            with self.connection_lock:
                self.connected = False
                self.authenticated = False
            self.logger.info("✅ Server connection stopped")
        except Exception as e:
            self.logger.error(f"Error stopping connection: {e}")
    
    def _test_http_connectivity(self) -> bool:
        """Test basic HTTP connectivity to server"""
        try:
            # Try health endpoint first
            health_url = f"{self.base_url}/api/health"
            
            response = self.session.get(
                health_url,
                timeout=self.timeout,
                verify=False  # Disable SSL verification for development
            )
            
            if response.status_code == 200:
                self.logger.debug("✅ HTTP connectivity test passed")
                return True
            else:
                self.logger.warning(f"⚠️ HTTP test failed with status: {response.status_code}")
                # Try base URL as fallback
                response = self.session.get(f"{self.base_url}/", timeout=10, verify=False)
                return response.status_code < 500
                
        except requests.exceptions.ConnectTimeout:
            self.logger.error("❌ HTTP connectivity test: Connection timeout")
            return False
        except requests.exceptions.ConnectionError:
            self.logger.error("❌ HTTP connectivity test: Connection refused")
            return False
        except Exception as e:
            self.logger.error(f"❌ HTTP connectivity test failed: {e}")
            return False
    
    def _connect_socketio(self) -> bool:
        """Establish Socket.IO connection"""
        try:
            connect_headers = {
                'User-Agent': f'EDR-Agent/{self.config.get("agent", "version", "2.0.0")}',
                'X-Agent-Hostname': self.config.get_system_info().get('hostname', 'unknown'),
                'X-Agent-ID': self.agent_id or 'new',
                'X-Agent-Version': self.config.get("agent", "version", "2.0.0")
            }
            
            # Add authentication token if available
            auth_token = self.config.get('server', 'auth_token')
            if auth_token:
                connect_headers['Authorization'] = f'Bearer {auth_token}'
            
            self.sio.connect(
                self.server_url,
                headers=connect_headers,
                wait_timeout=self.timeout,
                transports=['websocket', 'polling']
            )
            
            return True
            
        except socketio.exceptions.ConnectionError as e:
            self.logger.error(f"❌ Socket.IO connection failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Unexpected Socket.IO error: {e}")
            return False
    
    def _start_background_threads(self):
        """Start all background threads"""
        try:
            # Heartbeat thread
            if not self.heartbeat_thread or not self.heartbeat_thread.is_alive():
                self.heartbeat_thread = threading.Thread(
                    target=self._heartbeat_worker,
                    daemon=True
                )
                self.heartbeat_thread.start()
            
            # Connection monitor thread
            if not self.connection_monitor_thread or not self.connection_monitor_thread.is_alive():
                self.connection_monitor_thread = threading.Thread(
                    target=self._connection_monitor,
                    daemon=True
                )
                self.connection_monitor_thread.start()
            
            self.logger.debug("✅ Background threads started")
            
        except Exception as e:
            self.logger.error(f"Error starting background threads: {e}")
    
    def _start_data_workers(self):
        """Start data sending worker threads"""
        try:
            # Priority data worker (for alerts and critical data)
            priority_worker = threading.Thread(
                target=self._priority_data_worker,
                daemon=True
            )
            priority_worker.start()
            
            # Regular data worker
            data_worker = threading.Thread(
                target=self._data_worker,
                daemon=True
            )
            data_worker.start()
            
            # Failed requests retry worker
            retry_worker = threading.Thread(
                target=self._retry_worker,
                daemon=True
            )
            retry_worker.start()
            
            self.logger.debug("✅ Data worker threads started")
            
        except Exception as e:
            self.logger.error(f"Error starting data workers: {e}")
    
    def _heartbeat_worker(self):
        """Background worker for sending heartbeats"""
        while self.running:
            try:
                if self.connected or self._test_http_connectivity():
                    success = self.send_heartbeat()
                    if success:
                        self.last_successful_send = time.time()
                    
                time.sleep(self.heartbeat_interval)
                
            except Exception as e:
                self.logger.error(f"Error in heartbeat worker: {e}")
                time.sleep(self.heartbeat_interval)
    
    def _connection_monitor(self):
        """Monitor connection health and trigger reconnection if needed"""
        while self.running:
            try:
                current_time = time.time()
                
                # Check if we've been disconnected for too long
                if not self.connected:
                    if (self.last_successful_send and 
                        current_time - self.last_successful_send > 300):  # 5 minutes
                        self.logger.warning("⚠️ Extended disconnection detected, forcing reconnection")
                        self._schedule_reconnection()
                
                # Check heartbeat health
                if (self.last_heartbeat and 
                    current_time - time.mktime(self.last_heartbeat.timetuple()) > self.heartbeat_interval * 3):
                    self.logger.warning("⚠️ Heartbeat timeout detected")
                    if self.connected:
                        self._schedule_reconnection()
                
                # Update uptime statistics
                if self.connection_start_time:
                    self.stats['uptime'] = current_time - self.connection_start_time
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in connection monitor: {e}")
                time.sleep(60)
    
    def _priority_data_worker(self):
        """Worker for sending priority data (alerts, commands responses)"""
        while self.running:
            try:
                # Get priority data with timeout
                try:
                    data = self.priority_queue.get(timeout=5)
                except queue.Empty:
                    continue
                
                success = self._send_data_internal(data, priority=True)
                if not success:
                    # Retry once for priority data
                    time.sleep(1)
                    success = self._send_data_internal(data, priority=True)
                    if not success:
                        self.failed_requests.put(data)
                
                self.priority_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Error in priority data worker: {e}")
                time.sleep(1)
    
    def _data_worker(self):
        """Worker for sending regular data"""
        while self.running:
            try:
                # Get regular data with timeout
                try:
                    data = self.data_queue.get(timeout=10)
                except queue.Empty:
                    continue
                
                success = self._send_data_internal(data, priority=False)
                if not success:
                    # Put failed requests in retry queue
                    if not self.failed_requests.full():
                        self.failed_requests.put(data)
                
                self.data_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Error in data worker: {e}")
                time.sleep(1)
    
    def _retry_worker(self):
        """Worker for retrying failed requests"""
        while self.running:
            try:
                # Get failed request with timeout
                try:
                    data = self.failed_requests.get(timeout=30)
                except queue.Empty:
                    continue
                
                # Wait before retry
                time.sleep(5)
                
                # Only retry if we're connected
                if self.connected or self._test_http_connectivity():
                    success = self._send_data_internal(data, priority=False)
                    if not success:
                        # Drop after retry failure to prevent infinite loops
                        self.logger.warning("⚠️ Dropping data after retry failure")
                        self.stats['failed_sends'] += 1
                
                self.failed_requests.task_done()
                
            except Exception as e:
                self.logger.error(f"Error in retry worker: {e}")
                time.sleep(30)
    
    def _schedule_reconnection(self):
        """Schedule reconnection attempt"""
        if not self.running:
            return
            
        # Start reconnection thread if not already running
        if not self.reconnect_thread or not self.reconnect_thread.is_alive():
            self.reconnect_thread = threading.Thread(
                target=self._reconnection_worker,
                daemon=True
            )
            self.reconnect_thread.start()
    
    def _reconnection_worker(self):
        """Worker for handling reconnection attempts"""
        while self.running and not self.connected:
            try:
                if self.reconnect_attempts >= self.max_reconnect_attempts:
                    self.logger.error(f"❌ Max reconnection attempts ({self.max_reconnect_attempts}) reached")
                    break
                self.reconnect_attempts += 1
                wait_time = min(self.reconnect_delay * (2 ** (self.reconnect_attempts - 1)), 300)  # Max 5 minutes
                self.logger.info(f"🔄 Reconnection attempt {self.reconnect_attempts}/{self.max_reconnect_attempts} in {wait_time}s")
                time.sleep(wait_time)
                if not self.running:
                    break
                # Try reconnection
                success = self._connect_socketio()
                if success:
                    self.stats['reconnections'] += 1
                    self.logger.info("✅ Reconnection successful")
                    break
                else:
                    self.logger.warning(f"⚠️ Reconnection attempt {self.reconnect_attempts} failed")
            except Exception as e:
                self.logger.error(f"Error in reconnection worker: {e}")
                time.sleep(self.reconnect_delay)
    
    def send_heartbeat(self) -> bool:
        """Send heartbeat to server via HTTP"""
        try:
            heartbeat_data = {
                'agent_id': self.agent_id,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'online',
                'metrics': self._get_agent_metrics()
            }
            # Try Socket.IO first, then HTTP fallback
            if self.connected:
                try:
                    self.sio.emit('agent_heartbeat', heartbeat_data)
                    self.logger.debug("💓 Heartbeat sent via Socket.IO")
                    return True
                except Exception as e:
                    self.logger.debug(f"Socket.IO heartbeat failed: {e}")
            # HTTP fallback
            response = self._send_http_request('POST', '/api/agents/heartbeat', heartbeat_data)
            if response and response.get('success'):
                self.logger.debug("💓 Heartbeat sent via HTTP")
                return True
            else:
                self.logger.warning("⚠️ Heartbeat failed")
                return False
        except Exception as e:
            self.logger.error(f"Error sending heartbeat: {e}")
            return False
    
    def send_logs(self, log_data: Dict[str, Any], priority: bool = False) -> bool:
        """Send log data to server with priority support"""
        try:
            if not log_data:
                return False
            # Enrich log data
            enriched_data = self._enrich_log_data(log_data)
            # Queue for sending
            target_queue = self.priority_queue if priority else self.data_queue
            try:
                if priority:
                    target_queue.put_nowait(enriched_data)
                else:
                    target_queue.put(enriched_data, timeout=1)
                return True
            except queue.Full:
                self.logger.warning("⚠️ Data queue full, dropping data")
                return False
        except Exception as e:
            self.logger.error(f"Error queuing log data: {e}")
            return False
    
    def report_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send alert to server with high priority"""
        try:
            enriched_alert = self._enrich_alert_data(alert_data)
            
            # Send with high priority
            return self.send_logs(enriched_alert, priority=True)
            
        except Exception as e:
            self.logger.error(f"Error sending alert: {e}")
            return False
    
    def register_agent(self, registration_data: Dict[str, Any] = None) -> bool:
        """Register agent with server (gửi đủ trường cho server)"""
        try:
            if not registration_data:
                registration_data = self._get_registration_data()

            # Chỉ lấy các trường cần thiết cho bảng Agents
            agent_data = {
                'hostname': registration_data.get('hostname'),
                'os_type': registration_data.get('os_type'),
                'os_version': registration_data.get('os_version'),
                'architecture': registration_data.get('architecture'),
                'ip_address': registration_data.get('ip_address'),
                'mac_address': registration_data.get('mac_address'),
                'agent_version': registration_data.get('agent_version'),
                'version': registration_data.get('agent_version'),  # Thêm trường version cho server
            }

            # Try Socket.IO first
            if self.connected:
                try:
                    self.sio.emit('agent_register', agent_data)
                    self.logger.info("📝 Registration sent via Socket.IO")
                    return True
                except Exception as e:
                    self.logger.debug(f"Socket.IO registration failed: {e}")

            # HTTP fallback
            response = self._send_http_request('POST', '/api/agents/register', agent_data)
            if response:
                self.agent_id = response.get('agent_id')
                if self.agent_id:
                    self.config.set('agent', 'agent_id', self.agent_id)
                    self.config.save_config()
                    self.session.headers['X-Agent-ID'] = self.agent_id
                    self.authenticated = True
                    self.logger.info(f"✅ Agent registered via HTTP with ID: {self.agent_id}")
                    return True

            self.logger.error("❌ Agent registration failed")
            return False
        except Exception as e:
            self.logger.error(f"Error registering agent: {e}")
            return False

    def _get_registration_data(self) -> Dict[str, Any]:
        """Get agent registration data (chỉ lấy các trường cần thiết cho bảng Agents)"""
        try:
            system_info = self.config.get_system_info()
            return {
                'hostname': system_info.get('hostname'),
                'os_type': system_info.get('os_type'),
                'os_version': system_info.get('os_version'),
                'architecture': system_info.get('architecture'),
                'ip_address': system_info.get('ip_address'),
                'mac_address': system_info.get('mac_address'),
                'agent_version': self.config.get('agent', 'version', '2.0.0'),
            }
        except Exception as e:
            self.logger.error(f"Error creating registration data: {e}")
            return {'error': str(e)}
    
    def _get_agent_metrics(self) -> Dict[str, Any]:
        """Get current agent metrics for heartbeat - FIXED"""
        try:
            import psutil
            
            # FIXED: Handle disk usage error on Windows
            try:
                disk_usage = psutil.disk_usage('C:').percent
            except Exception:
                disk_usage = 0.0
            
            # FIXED: Handle network connections error
            try:
                net_connections = len(psutil.net_connections())
            except Exception:
                net_connections = 0
            
            return {
                'cpu_usage': psutil.cpu_percent(interval=None),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': disk_usage,
                'process_count': len(psutil.pids()),
                'network_connections': net_connections,
                'queue_sizes': {
                    'data_queue': self.data_queue.qsize(),
                    'priority_queue': self.priority_queue.qsize(),
                    'failed_requests': self.failed_requests.qsize()
                },
                'stats': self.stats.copy()
            }
        except Exception as e:
            self.logger.error(f"Error getting agent metrics: {e}")
            return {
                'cpu_usage': 0.0,
                'memory_usage': 0.0,
                'disk_usage': 0.0,
                'process_count': 0,
                'network_connections': 0,
                'error': str(e)
            }
    
    def _enrich_log_data(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich log data with metadata"""
        try:
            system_info = self.config.get_system_info()
            
            enriched = log_data.copy()
            enriched.update({
                'agent_id': self.agent_id,
                'hostname': system_info.get('hostname'),
                'timestamp': datetime.utcnow().isoformat(),
                'agent_version': self.config.get('agent', 'version', '2.0.0'),
                'data_type': 'logs'
            })
            
            return enriched
        except Exception as e:
            self.logger.error(f"Error enriching log data: {e}")
            return log_data
    
    def _enrich_alert_data(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich alert data with metadata"""
        try:
            system_info = self.config.get_system_info()
            
            enriched = alert_data.copy()
            enriched.update({
                'agent_id': self.agent_id,
                'hostname': system_info.get('hostname'),
                'timestamp': datetime.utcnow().isoformat(),
                'agent_version': self.config.get('agent', 'version', '2.0.0'),
                'data_type': 'alert',
                'severity': alert_data.get('severity', 'Medium'),
                'source': 'edr_agent'
            })
            
            return enriched
        except Exception as e:
            self.logger.error(f"Error enriching alert data: {e}")
            return alert_data
    
    def _send_data_internal(self, data: Dict[str, Any], priority: bool = False) -> bool:
        """Internal method to send data via Socket.IO or HTTP"""
        try:
            data_size = len(json.dumps(data).encode('utf-8'))
            self.stats['data_sent_bytes'] += data_size
            # Try Socket.IO first
            if self.connected:
                try:
                    # Xác định loại log để gửi đúng event
                    log_type = data.get('type') or data.get('log_type')
                    if log_type == 'process':
                        event_name = 'process_logs'
                    elif log_type == 'file':
                        event_name = 'file_logs'
                    elif log_type == 'network':
                        event_name = 'network_logs'
                    else:
                        event_name = 'agent_data'  # fallback
                    self.sio.emit(event_name, data)
                    self.stats['successful_sends'] += 1
                    self.last_successful_send = time.time()
                    return True
                except Exception as e:
                    self.logger.debug(f"Socket.IO send failed: {e}")
            # HTTP fallback
            endpoint = '/api/alerts' if data.get('data_type') == 'alert' else '/api/logs'
            response = self._send_http_request('POST', endpoint, data)
            if response:
                self.stats['successful_sends'] += 1
                self.last_successful_send = time.time()
                return True
            else:
                self.stats['failed_sends'] += 1
                return False
        except Exception as e:
            self.logger.error(f"Error sending data: {e}")
            self.stats['failed_sends'] += 1
            return False
    
    def _send_http_request(self, method: str, endpoint: str, data: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Send HTTP request to server with error handling"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            if method.upper() == 'GET':
                response = self.session.get(url, timeout=self.timeout, verify=False)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, timeout=self.timeout, verify=False)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data, timeout=self.timeout, verify=False)
            else:
                self.logger.error(f"Unsupported HTTP method: {method}")
                return None
            
            if response.status_code in [200, 201]:
                try:
                    return response.json()
                except:
                    return {'success': True}
            else:
                self.logger.warning(f"HTTP {method} {endpoint} failed: {response.status_code}")
                return None
                
        except requests.exceptions.Timeout:
            self.logger.warning(f"HTTP {method} {endpoint} timeout")
            return None
        except requests.exceptions.ConnectionError:
            self.logger.warning(f"HTTP {method} {endpoint} connection error")
            return None
        except Exception as e:
            self.logger.error(f"HTTP {method} {endpoint} error: {e}")
            return None
    
    def get_rules(self) -> Optional[List[Dict[str, Any]]]:
        """Get rules from server"""
        try:
            # Try Socket.IO first
            if self.connected:
                # Request rules via Socket.IO
                self.sio.emit('request_rules', {'agent_id': self.agent_id})
                # Rules will be received via rule_update event
                return None
            
            # HTTP fallback
            params = {
                    'agent_id': self.agent_id,
                'hostname': self.config.get_system_info().get('hostname'),
                    'os_type': 'Windows'
            }
            
            response = self._send_http_request('GET', '/api/rules', params)
            if response and 'rules' in response:
                return response['rules']
            
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting rules: {e}")
            return None
    
    def is_connected(self) -> bool:
        """Check if connected to server"""
        return self.connected and (self.sio.connected or self._test_http_connectivity())
    
    def get_connection_status(self) -> Dict[str, Any]:
        """Get detailed connection status"""
        return {
            'connected': self.connected,
            'authenticated': self.authenticated,
            'socket_connected': self.sio.connected,
                'agent_id': self.agent_id,
            'server_url': self.server_url,
            'base_url': self.base_url,
            'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            'last_successful_send': self.last_successful_send,
            'reconnect_attempts': self.reconnect_attempts,
            'max_reconnect_attempts': self.max_reconnect_attempts,
            'connection_start_time': self.connection_start_time,
            'uptime': self.stats['uptime'],
            'queue_sizes': {
                'data_queue': self.data_queue.qsize(),
                'priority_queue': self.priority_queue.qsize(),
                'failed_requests': self.failed_requests.qsize()
            },
            'stats': self.stats.copy()
        }
    
    def clear_queues(self):
        """Clear all data queues"""
        try:
            # Clear all queues
            while not self.data_queue.empty():
                try:
                    self.data_queue.get_nowait()
                except queue.Empty:
                    break
            
            while not self.priority_queue.empty():
                try:
                    self.priority_queue.get_nowait()
                except queue.Empty:
                    break
            
            while not self.failed_requests.empty():
                try:
                    self.failed_requests.get_nowait()
                except queue.Empty:
                    break
            
            self.logger.info("🗑️ All data queues cleared")
                
        except Exception as e:
            self.logger.error(f"Error clearing queues: {e}")
    
    def force_reconnect(self) -> bool:
        """Force immediate reconnection"""
        try:
            self.logger.info("🔄 Forcing reconnection...")
            # Disconnect current connection
            if self.sio.connected:
                self.sio.disconnect()
            with self.connection_lock:
                self.connected = False
                self.authenticated = False
                self.reconnect_attempts = 0
            # Try immediate reconnection
            return self._connect_socketio()
        except Exception as e:
            self.logger.error(f"Error forcing reconnection: {e}")
            return False
    
    def send_command_response(self, command_id: str, response_data: Dict[str, Any]) -> bool:
        """Send response to server command"""
        try:
            response = {
                'command_id': command_id,
                'agent_id': self.agent_id,
                'timestamp': datetime.utcnow().isoformat(),
                'response': response_data
            }
            # Send with high priority
            return self.send_logs(response, priority=True)
        except Exception as e:
            self.logger.error(f"Error sending command response: {e}")
            return False
    
    def update_agent_status(self, status: str, details: Dict[str, Any] = None) -> bool:
        """Update agent status on server"""
        try:
            status_data = {
                'agent_id': self.agent_id,
                'status': status,
                'timestamp': datetime.utcnow().isoformat(),
                'details': details or {}
            }
            # Try Socket.IO first
            if self.connected:
                try:
                    self.sio.emit('agent_status_update', status_data)
                    return True
                except Exception as e:
                    self.logger.debug(f"Socket.IO status update failed: {e}")
            # HTTP fallback
            response = self._send_http_request('POST', '/api/agents/status', status_data)
            return response is not None
        except Exception as e:
            self.logger.error(f"Error updating agent status: {e}")
            return False
    
    def request_config_update(self) -> bool:
        """Request configuration update from server"""
        try:
            request_data = {
                'agent_id': self.agent_id,
                'timestamp': datetime.utcnow().isoformat(),
                'current_version': self.config.get('agent', 'version', '2.0.0')
            }
            # Try Socket.IO first
            if self.connected:
                try:
                    self.sio.emit('request_config_update', request_data)
                    return True
                except Exception as e:
                    self.logger.debug(f"Socket.IO config request failed: {e}")
            # HTTP fallback
            response = self._send_http_request('POST', '/api/agents/request-config', request_data)
            return response is not None
        except Exception as e:
            self.logger.error(f"Error requesting config update: {e}")
            return False
    
    def send_performance_metrics(self, metrics: Dict[str, Any]) -> bool:
        """Send performance metrics to server"""
        try:
            metrics_data = {
                'agent_id': self.agent_id,
                'timestamp': datetime.utcnow().isoformat(),
                'metrics': metrics,
                'data_type': 'performance_metrics'
            }
            
            return self.send_logs(metrics_data, priority=False)
                
        except Exception as e:
            self.logger.error(f"Error sending performance metrics: {e}")
            return False
    
    def test_connection(self) -> Dict[str, Any]:
        """Test connection and return detailed results"""
        try:
            results = {
                'timestamp': datetime.utcnow().isoformat(),
                'http_connectivity': False,
                'socketio_connectivity': False,
                'authentication': False,
                'latency': None,
                'errors': []
            }
            # Test HTTP connectivity
            start_time = time.time()
            try:
                if self._test_http_connectivity():
                    results['http_connectivity'] = True
                    results['latency'] = round((time.time() - start_time) * 1000, 2)  # ms
                else:
                    results['errors'].append('HTTP connectivity test failed')
            except Exception as e:
                results['errors'].append(f'HTTP test error: {str(e)}')
            # Test Socket.IO connectivity
            try:
                if self.sio.connected:
                    results['socketio_connectivity'] = True
                else:
                    # Try to connect for test
                    test_connected = self._connect_socketio()
                    if test_connected:
                        results['socketio_connectivity'] = True
                    else:
                        results['errors'].append('Socket.IO connection test failed')
            except Exception as e:
                results['errors'].append(f'Socket.IO test error: {str(e)}')
            # Test authentication
            if self.agent_id and self.authenticated:
                results['authentication'] = True
            else:
                results['errors'].append('Agent not authenticated')
            return results
        except Exception as e:
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e),
                'http_connectivity': False,
                'socketio_connectivity': False,
                'authentication': False
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive connection statistics"""
        try:
            current_time = time.time()
            return {
                'connection_info': {
                    'server_url': self.server_url,
                    'base_url': self.base_url,
                    'agent_id': self.agent_id,
                    'connected': self.connected,
                    'authenticated': self.authenticated,
                    'socket_connected': self.sio.connected,
                    'uptime': self.stats['uptime'],
                    'connection_start_time': self.connection_start_time
                },
                'performance': {
                    'successful_sends': self.stats['successful_sends'],
                    'failed_sends': self.stats['failed_sends'],
                    'total_connections': self.stats['total_connections'],
                    'reconnections': self.stats['reconnections'],
                    'data_sent_bytes': self.stats['data_sent_bytes'],
                    'alerts_received': self.stats['alerts_received'],
                    'commands_received': self.stats['commands_received'],
                    'success_rate': (
                        self.stats['successful_sends'] /
                        max(self.stats['successful_sends'] + self.stats['failed_sends'], 1) * 100
                    )
                },
                'queues': {
                    'data_queue_size': self.data_queue.qsize(),
                    'priority_queue_size': self.priority_queue.qsize(),
                    'failed_requests_size': self.failed_requests.qsize(),
                    'data_queue_maxsize': self.data_queue.maxsize,
                    'priority_queue_maxsize': self.priority_queue.maxsize,
                    'failed_requests_maxsize': self.failed_requests.maxsize
                },
                'timing': {
                    'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None,
                    'last_successful_send': self.last_successful_send,
                    'heartbeat_interval': self.heartbeat_interval,
                    'reconnect_delay': self.reconnect_delay,
                    'current_time': current_time
                },
                'errors': {
                    'last_error': self.stats['last_error'],
                    'reconnect_attempts': self.reconnect_attempts,
                    'max_reconnect_attempts': self.max_reconnect_attempts
                },
                'configuration': {
                    'timeout': self.timeout,
                    'max_reconnect_attempts': self.max_reconnect_attempts,
                    'reconnect_delay': self.reconnect_delay,
                    'heartbeat_interval': self.heartbeat_interval
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {'error': str(e)}

    def _register_with_server(self):
        """Register agent with server after successful connection"""
        try:
            # Get system information
            system_info = self.config.get_system_info()
            
            # Prepare registration data
            register_data = {
                'hostname': system_info.get('hostname'),
                'os_type': system_info.get('os_type'),
                'os_version': system_info.get('os_version'),
                'architecture': system_info.get('architecture'),
                'ip_address': system_info.get('ip_address'),
                'mac_address': system_info.get('mac_address'),
                'agent_version': self.config.AGENT_VERSION,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Send registration request
            self.sio.emit('register', register_data)
            self.logger.info("📝 Registration request sent to server")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to register with server: {e}")
            raise

    def send_schema_test(self, test_data):
        """Send schema test data to server (dummy implementation)"""
        try:
            # TODO: Gửi test_data lên server qua socketio hoặc HTTP
            self.logger.info(f"[send_schema_test] Schema test data: {test_data}")
            return True
        except Exception as e:
            self.logger.error(f"Error sending schema test: {e}")
            return False

    def send_performance_report(self, report):
        self.logger.info(f"[send_performance_report] {report}")
        return True

    def send_statistics_report(self, report):
        self.logger.info(f"[send_statistics_report] {report}")
        return True

    def send_system_info(self, info):
        self.logger.info(f"[send_system_info] {info}")
        return True

    def send_system_metrics(self, metrics: Dict[str, Any]) -> bool:
        """Send system metrics to server"""
        try:
            if not self.is_connected():
                return False

            # Add agent info
            metrics.update({
                'agent_id': self.config.AGENT_ID,
                'hostname': self.config.get_system_info().get('hostname'),
                'timestamp': datetime.utcnow().isoformat()
            })

            # Send via Socket.IO
            success = self.sio.emit('system_metrics', metrics)
            
            if success:
                print(f"[Agent] System metrics sent successfully")
            else:
                print(f"[Agent] Failed to send system metrics")
                
            return success

        except Exception as e:
            print(f"[Agent] Error sending system metrics: {e}")
            return False