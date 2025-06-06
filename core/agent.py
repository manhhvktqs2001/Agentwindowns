"""
EDR Windows Agent - Main Agent Class (FIXED)
"""

import os
import sys
import json
import time
import logging
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

from .connection import ServerConnection
from .scheduler import TaskScheduler
from ..monitors.process_monitor import ProcessMonitor
from ..monitors.file_monitor import FileMonitor  
from ..monitors.network_monitor import NetworkMonitor
from ..actions.process_actions import ProcessActions
from ..actions.notification_actions import NotificationActions
from ..utils.log_sender import LogSender

class EDRAgent:
    """Main EDR Agent class"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.system_info = {}
        
        # Core components
        self.connection = None
        self.scheduler = None
        self.log_sender = None
        
        # Monitors
        self.process_monitor = None
        self.file_monitor = None
        self.network_monitor = None
        
        # Actions
        self.process_actions = None
        self.notification_actions = None
        
        # Data buffers
        self.data_buffer = {
            'processes': [],
            'files': [],
            'networks': []
        }
        self.buffer_lock = threading.Lock()
        
        # FIXED: Add rules storage and management
        self.active_rules = []
        self.rules_lock = threading.Lock()
        
        # FIXED: Add statistics tracking
        self.stats = {
            'start_time': None,
            'events_processed': 0,
            'alerts_generated': 0,
            'rules_triggered': 0,
            'last_heartbeat': None
        }
        
        # Initialize components
        self._initialize_components()
        
        self.logger.info("✅ EDR Agent initialized")
    
    def _initialize_components(self):
        """Initialize all agent components"""
        try:
            # Get system information
            self.system_info = self.config.get_system_info()
            self.logger.info(f"System: {self.system_info.get('hostname')} - {self.system_info.get('os_version')}")
            
            # Initialize connection
            self.connection = ServerConnection(self.config, self)
            
            # Initialize scheduler
            self.scheduler = TaskScheduler()
            
            # Initialize log sender
            self.log_sender = LogSender(self.config, self.connection)
            
            # Initialize monitors
            if self.config.PROCESS_MONITORING:
                self.process_monitor = ProcessMonitor(self.config, self._on_process_event)
                
            if self.config.FILE_MONITORING:
                self.file_monitor = FileMonitor(self.config, self._on_file_event)
                
            if self.config.NETWORK_MONITORING:
                self.network_monitor = NetworkMonitor(self.config, self._on_network_event)
            
            # Initialize actions
            self.process_actions = ProcessActions(self.config)
            self.notification_actions = NotificationActions(self.config)
            
            # FIXED: Load initial rules
            self._load_initial_rules()
            
            self.logger.info("✅ All components initialized")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize components: {e}")
            raise
    
    def start(self) -> threading.Thread:
        """Start the EDR agent"""
        try:
            self.logger.info("🚀 Starting EDR Agent...")
            self.running = True
            self.stats['start_time'] = time.time()
            
            # Start connection to server
            self.connection.start()
            
            # Register agent with server
            self._register_agent()
            
            # Start log sender
            self.log_sender.start()
            
            # Start monitors
            self._start_monitors()
            
            # Start data sender
            self._start_data_sender()
            
            # Start heartbeat
            self._start_heartbeat()
            
            # FIXED: Start rule checking
            self._start_rule_checking()
            
            # Start main agent thread
            agent_thread = threading.Thread(target=self._main_loop, daemon=True)
            agent_thread.start()
            
            # Show startup notification
            if self.notification_actions:
                self.notification_actions.show_startup_notification()
            
            self.logger.info("✅ EDR Agent started successfully")
            return agent_thread
            
        except Exception as e:
            self.logger.error(f"❌ Failed to start agent: {e}")
            self.stop()
            raise
    
    def stop(self):
        """Stop the EDR agent"""
        try:
            self.logger.info("🛑 Stopping EDR Agent...")
            self.running = False
            
            # Stop monitors
            if self.process_monitor:
                self.process_monitor.stop()
            if self.file_monitor:
                self.file_monitor.stop()
            if self.network_monitor:
                self.network_monitor.stop()
            
            # Stop log sender
            if self.log_sender:
                self.log_sender.stop()
            
            # Stop connection
            if self.connection:
                self.connection.stop()
            
            # Stop scheduler
            if self.scheduler:
                self.scheduler.stop()
            
            # Stop notification actions
            if self.notification_actions:
                self.notification_actions.stop()
                
            self.logger.info("✅ EDR Agent stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping agent: {e}")
    
    def _register_agent(self):
        """Register agent with EDR server"""
        try:
            registration_data = {
                'hostname': self.system_info.get('hostname'),
                'os_type': self.system_info.get('os_type'),
                'os_version': self.system_info.get('os_version'),
                'architecture': self.system_info.get('architecture'),
                'ip_address': self.system_info.get('ip_address'),
                'mac_address': self.system_info.get('mac_address'),
                'agent_version': self.config.get('agent', 'version'),
                'status': 'Online'
            }
            
            success = self.connection.register_agent(registration_data)
            if success:
                self.logger.info("✅ Agent registered successfully")
                # FIXED: Get initial rules after registration
                self._fetch_rules_from_server()
            else:
                self.logger.warning("⚠️ Agent registration failed")
                
        except Exception as e:
            self.logger.error(f"Registration error: {e}")
    
    def _start_monitors(self):
        """Start all monitoring components"""
        try:
            if self.process_monitor:
                self.process_monitor.start()
                self.logger.info("✅ Process monitor started")
                
            if self.file_monitor:
                self.file_monitor.start()
                self.logger.info("✅ File monitor started")
                
            if self.network_monitor:
                self.network_monitor.start()
                self.logger.info("✅ Network monitor started")
                
        except Exception as e:
            self.logger.error(f"Error starting monitors: {e}")
    
    def _start_data_sender(self):
        """Start data sender task"""
        def send_data_task():
            while self.running:
                try:
                    self._send_buffered_data()
                    time.sleep(self.config.get('monitoring', 'send_interval', 30))
                except Exception as e:
                    self.logger.error(f"Error in data sender: {e}")
                    time.sleep(5)
        
        sender_thread = threading.Thread(target=send_data_task, daemon=True)
        sender_thread.start()
        self.logger.info("✅ Data sender started")
    
    def _start_heartbeat(self):
        """Start heartbeat task"""
        def heartbeat_task():
            while self.running:
                try:
                    success = self.connection.send_heartbeat()
                    if success:
                        self.stats['last_heartbeat'] = time.time()
                    time.sleep(self.config.HEARTBEAT_INTERVAL)
                except Exception as e:
                    self.logger.error(f"Heartbeat error: {e}")
                    time.sleep(10)
        
        heartbeat_thread = threading.Thread(target=heartbeat_task, daemon=True)
        heartbeat_thread.start()
        self.logger.info("✅ Heartbeat started")
    
    def _start_rule_checking(self):
        """Start rule checking task"""
        def rule_check_task():
            while self.running:
                try:
                    # Check for rule updates from server periodically
                    if time.time() % 300 == 0:  # Every 5 minutes
                        self._fetch_rules_from_server()
                    
                    time.sleep(60)  # Check every minute
                except Exception as e:
                    self.logger.error(f"Error in rule checking: {e}")
                    time.sleep(10)
        
        rule_thread = threading.Thread(target=rule_check_task, daemon=True)
        rule_thread.start()
        self.logger.info("✅ Rule checking started")
    
    def _main_loop(self):
        """Main agent loop"""
        while self.running:
            try:
                # Process any pending tasks
                if self.scheduler:
                    self.scheduler.process_tasks()
                
                # Check connection status
                if not self.connection.is_connected():
                    self.logger.warning("⚠️ Server connection lost, attempting reconnect...")
                    self.connection.reconnect()
                
                # FIXED: Periodic health check
                self._perform_health_check()
                
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Error in main loop: {e}")
                time.sleep(5)
    
    def _on_process_event(self, event_data: Dict[str, Any]):
        """Handle process monitoring events"""
        try:
            # FIXED: Add data validation
            if not isinstance(event_data, dict):
                self.logger.error("Invalid process event data format")
                return
            
            # Add required fields if missing
            if 'timestamp' not in event_data:
                event_data['timestamp'] = datetime.utcnow().isoformat()
            if 'hostname' not in event_data:
                event_data['hostname'] = self.system_info.get('hostname')
            
            # FIXED: Check against rules before storing
            self._check_event_against_rules(event_data, 'process')
            
            with self.buffer_lock:
                self.data_buffer['processes'].append(event_data)
                
                # FIXED: Better buffer management
                max_buffer = self.config.get('monitoring', 'batch_size', 50)
                if len(self.data_buffer['processes']) > max_buffer:
                    # Remove oldest entries
                    self.data_buffer['processes'] = self.data_buffer['processes'][-max_buffer:]
            
            self.stats['events_processed'] += 1
                    
        except Exception as e:
            self.logger.error(f"Error handling process event: {e}")
    
    def _on_file_event(self, event_data: Dict[str, Any]):
        """Handle file monitoring events"""
        try:
            # FIXED: Add data validation
            if not isinstance(event_data, dict):
                self.logger.error("Invalid file event data format")
                return
            
            # Add required fields if missing
            if 'timestamp' not in event_data:
                event_data['timestamp'] = datetime.utcnow().isoformat()
            if 'hostname' not in event_data:
                event_data['hostname'] = self.system_info.get('hostname')
            
            # FIXED: Check against rules before storing
            self._check_event_against_rules(event_data, 'file')
            
            with self.buffer_lock:
                self.data_buffer['files'].append(event_data)
                
                # FIXED: Better buffer management
                max_buffer = self.config.get('monitoring', 'batch_size', 50)
                if len(self.data_buffer['files']) > max_buffer:
                    # Remove oldest entries
                    self.data_buffer['files'] = self.data_buffer['files'][-max_buffer:]
            
            self.stats['events_processed'] += 1
                    
        except Exception as e:
            self.logger.error(f"Error handling file event: {e}")
    
    def _on_network_event(self, event_data: Dict[str, Any]):
        """Handle network monitoring events"""
        try:
            # FIXED: Add data validation
            if not isinstance(event_data, dict):
                self.logger.error("Invalid network event data format")
                return
            
            # Add required fields if missing
            if 'timestamp' not in event_data:
                event_data['timestamp'] = datetime.utcnow().isoformat()
            if 'hostname' not in event_data:
                event_data['hostname'] = self.system_info.get('hostname')
            
            # FIXED: Check against rules before storing
            self._check_event_against_rules(event_data, 'network')
            
            with self.buffer_lock:
                self.data_buffer['networks'].append(event_data)
                
                # FIXED: Better buffer management
                max_buffer = self.config.get('monitoring', 'batch_size', 50)
                if len(self.data_buffer['networks']) > max_buffer:
                    # Remove oldest entries
                    self.data_buffer['networks'] = self.data_buffer['networks'][-max_buffer:]
            
            self.stats['events_processed'] += 1
                    
        except Exception as e:
            self.logger.error(f"Error handling network event: {e}")
    
    def _check_event_against_rules(self, event_data: Dict[str, Any], event_type: str):
        """Check event against active rules"""
        try:
            with self.rules_lock:
                for rule in self.active_rules:
                    if self._rule_matches_event(rule, event_data, event_type):
                        self._trigger_rule(rule, event_data)
                        
        except Exception as e:
            self.logger.error(f"Error checking event against rules: {e}")
    
    def _rule_matches_event(self, rule: Dict[str, Any], event_data: Dict[str, Any], event_type: str) -> bool:
        """Check if rule matches the event"""
        try:
            # Check rule type
            rule_type = rule.get('rule_type', '').lower()
            if rule_type != event_type.lower():
                return False
            
            # Check OS compatibility
            rule_os = rule.get('os_type', 'All')
            if rule_os != 'All' and rule_os != 'Windows':
                return False
            
            # Check if rule is active
            if not rule.get('is_active', False):
                return False
            
            # Basic pattern matching based on rule type
            if event_type == 'process':
                return self._check_process_rule(rule, event_data)
            elif event_type == 'file':
                return self._check_file_rule(rule, event_data)
            elif event_type == 'network':
                return self._check_network_rule(rule, event_data)
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error matching rule: {e}")
            return False
    
    def _check_process_rule(self, rule: Dict[str, Any], event_data: Dict[str, Any]) -> bool:
        """Check process rule against event"""
        try:
            process_name = event_data.get('process_name', '').lower()
            command_line = event_data.get('command_line', '').lower()
            executable_path = event_data.get('executable_path', '').lower()
            
            # Simple pattern matching - in production this would be more sophisticated
            rule_name = rule.get('rule_name', '').lower()
            
            if 'powershell' in rule_name and 'powershell' in process_name:
                return True
            elif 'suspicious' in rule_name and event_data.get('is_suspicious', False):
                return True
            elif 'cmd' in rule_name and 'cmd.exe' in process_name:
                return True
            
            return False
            
        except Exception:
            return False
    
    def _check_file_rule(self, rule: Dict[str, Any], event_data: Dict[str, Any]) -> bool:
        """Check file rule against event"""
        try:
            file_name = event_data.get('file_name', '').lower()
            file_path = event_data.get('file_path', '').lower()
            
            rule_name = rule.get('rule_name', '').lower()
            
            if 'ransomware' in rule_name and event_data.get('is_suspicious', False):
                return True
            elif 'system32' in rule_name and 'system32' in file_path:
                return True
            elif 'download' in rule_name and 'downloads' in file_path:
                return True
            
            return False
            
        except Exception:
            return False
    
    def _check_network_rule(self, rule: Dict[str, Any], event_data: Dict[str, Any]) -> bool:
        """Check network rule against event"""
        try:
            remote_address = event_data.get('remote_address', '')
            remote_port = event_data.get('remote_port', 0)
            
            rule_name = rule.get('rule_name', '').lower()
            
            if 'suspicious' in rule_name and event_data.get('is_suspicious', False):
                return True
            elif 'c2' in rule_name and event_data.get('detection_reason', '').find('c2') >= 0:
                return True
            
            return False
            
        except Exception:
            return False
    
    def _trigger_rule(self, rule: Dict[str, Any], event_data: Dict[str, Any]):
        """Trigger rule action"""
        try:
            self.stats['rules_triggered'] += 1
            
            # Create alert
            alert_data = {
                'rule_id': rule.get('rule_id'),
                'rule_name': rule.get('rule_name'),
                'severity': rule.get('severity', 'Medium'),
                'title': f"Rule Triggered: {rule.get('rule_name', 'Unknown Rule')}",
                'description': rule.get('description', 'Security rule violation detected'),
                'event_data': event_data,
                'timestamp': datetime.utcnow().isoformat(),
                'hostname': self.system_info.get('hostname'),
                'agent_id': self.connection.agent_id
            }
            
            # Send alert to server
            self.connection.report_alert(alert_data)
            
            # Show local notification
            if self.notification_actions:
                self.notification_actions.show_alert({
                    'title': alert_data['title'],
                    'message': alert_data['description'],
                    'severity': alert_data['severity'],
                    'alert_type': 'rule_violation'
                })
            
            self.stats['alerts_generated'] += 1
            self.logger.warning(f"🚨 Rule triggered: {rule.get('rule_name')} - {alert_data['title']}")
            
            # Execute action if specified
            action = rule.get('action', 'Alert')
            if action == 'AlertAndBlock':
                self._execute_blocking_action(event_data, rule)
                
        except Exception as e:
            self.logger.error(f"Error triggering rule: {e}")
    
    def _execute_blocking_action(self, event_data: Dict[str, Any], rule: Dict[str, Any]):
        """Execute blocking action based on rule"""
        try:
            event_type = event_data.get('event_type', '')
            
            if 'process' in event_type:
                # Block process
                process_id = event_data.get('process_id')
                if process_id and self.process_actions:
                    success = self.process_actions.terminate_process(process_id=process_id)
                    if success:
                        self.logger.info(f"🛑 Blocked process {process_id} due to rule {rule.get('rule_name')}")
                    
            elif 'network' in event_type:
                # Block network connection
                remote_ip = event_data.get('remote_address')
                if remote_ip and self.network_monitor:
                    success = self.network_monitor.block_ip(remote_ip)
                    if success:
                        self.logger.info(f"🚫 Blocked IP {remote_ip} due to rule {rule.get('rule_name')}")
                        
            elif 'file' in event_type:
                # Quarantine file
                file_path = event_data.get('file_path')
                process_id = event_data.get('process_id')
                if file_path and process_id and self.process_actions:
                    success = self.process_actions.quarantine_process_executable(process_id)
                    if success:
                        self.logger.info(f"🔒 Quarantined file {file_path} due to rule {rule.get('rule_name')}")
                        
        except Exception as e:
            self.logger.error(f"Error executing blocking action: {e}")
    
    def _send_buffered_data(self):
        """Send buffered data to server"""
        try:
            with self.buffer_lock:
                if not any(self.data_buffer.values()):
                    return
                
                # Copy and clear buffers
                data_to_send = {
                    'processes': self.data_buffer['processes'].copy(),
                    'files': self.data_buffer['files'].copy(),
                    'networks': self.data_buffer['networks'].copy()
                }
                
                self.data_buffer = {'processes': [], 'files': [], 'networks': []}
            
            # Send data via log sender
            if self.log_sender:
                success = self.log_sender.send_logs(data_to_send)
                if success:
                    total_events = sum(len(logs) for logs in data_to_send.values())
                    self.logger.debug(f"✅ Sent {total_events} events to server")
                else:
                    self.logger.warning("⚠️ Failed to send data to server")
                    
        except Exception as e:
            self.logger.error(f"Error sending buffered data: {e}")
    
    def _load_initial_rules(self):
        """Load initial rules from config"""
        try:
            # Load rules from config if available
            config_rules = self.config.get('agent', 'rules', [])
            if config_rules:
                with self.rules_lock:
                    self.active_rules = config_rules
                self.logger.info(f"📋 Loaded {len(config_rules)} rules from config")
            
        except Exception as e:
            self.logger.error(f"Error loading initial rules: {e}")
    
    def _fetch_rules_from_server(self):
        """Fetch rules from server"""
        try:
            if self.connection and self.connection.is_connected():
                rules = self.connection.get_rules()
                if rules:
                    with self.rules_lock:
                        self.active_rules = rules
                    self.logger.info(f"📋 Updated {len(rules)} rules from server")
                    
        except Exception as e:
            self.logger.error(f"Error fetching rules from server: {e}")
    
    def _perform_health_check(self):
        """Perform periodic health check"""
        try:
            # Check monitor health
            monitors_healthy = True
            
            if self.process_monitor and not self.process_monitor.is_running():
                self.logger.warning("⚠️ Process monitor is not running, restarting...")
                self.process_monitor.start()
                monitors_healthy = False
            
            if self.file_monitor and not self.file_monitor.is_running():
                self.logger.warning("⚠️ File monitor is not running, restarting...")
                self.file_monitor.start()
                monitors_healthy = False
            
            if self.network_monitor and not self.network_monitor.is_running():
                self.logger.warning("⚠️ Network monitor is not running, restarting...")
                self.network_monitor.start()
                monitors_healthy = False
            
            # Check connection health
            if not self.connection.is_connected():
                monitors_healthy = False
            
            # Log health status periodically
            current_time = time.time()
            if hasattr(self, '_last_health_log'):
                if current_time - self._last_health_log > 300:  # Every 5 minutes
                    self.logger.info(f"💓 Health check: {'Healthy' if monitors_healthy else 'Issues detected'}")
                    self._last_health_log = current_time
            else:
                self._last_health_log = current_time
                
        except Exception as e:
            self.logger.error(f"Error in health check: {e}")
    
    def handle_server_command(self, command_data: Dict[str, Any]):
        """Handle commands from EDR server"""
        try:
            command_type = command_data.get('type')
            command_params = command_data.get('params', {})
            
            self.logger.info(f"📨 Received command: {command_type}")
            
            if command_type == 'alert':
                self._handle_alert_command(command_params)
            elif command_type == 'kill_process':
                self._handle_kill_process_command(command_params)
            elif command_type == 'block_network':
                self._handle_block_network_command(command_params)
            elif command_type == 'quarantine_file':
                self._handle_quarantine_file_command(command_params)
            elif command_type == 'update_config':
                self._handle_update_config_command(command_params)
            elif command_type == 'update_rules':
                self._handle_update_rules_command(command_params)
            elif command_type == 'get_status':
                self._handle_get_status_command(command_params)
            else:
                self.logger.warning(f"⚠️ Unknown command type: {command_type}")
                
        except Exception as e:
            self.logger.error(f"Error handling server command: {e}")
    
    def _handle_alert_command(self, params: Dict[str, Any]):
        """Handle alert command from server"""
        try:
            alert_data = {
                'title': params.get('title', 'Security Alert'),
                'message': params.get('message', 'Threat detected'),
                'severity': params.get('severity', 'Medium'),
                'alert_type': params.get('alert_type', 'Detection')
            }
            
            # Show notification
            if self.notification_actions:
                self.notification_actions.show_alert(alert_data)
            
            self.logger.info(f"🚨 Alert displayed: {alert_data['title']}")
            
        except Exception as e:
            self.logger.error(f"Error handling alert: {e}")
    
    def _handle_kill_process_command(self, params: Dict[str, Any]):
        """Handle kill process command"""
        try:
            process_id = params.get('process_id')
            process_name = params.get('process_name')
            force = params.get('force', False)
            
            if self.process_actions:
                success = self.process_actions.terminate_process(process_id, process_name, force)
                if success:
                    self.logger.info(f"✅ Process {process_name} ({process_id}) terminated by server command")
                else:
                    self.logger.warning(f"⚠️ Failed to terminate process {process_name} ({process_id})")
                    
        except Exception as e:
            self.logger.error(f"Error killing process: {e}")
    
    def _handle_block_network_command(self, params: Dict[str, Any]):
        """Handle block network command"""
        try:
            ip_address = params.get('ip_address')
            port = params.get('port')
            process_id = params.get('process_id')
            
            if ip_address and self.network_monitor:
                success = self.network_monitor.block_ip(ip_address)
                if success:
                    self.logger.info(f"🚫 IP {ip_address} blocked by server command")
            
            if process_id and self.process_actions:
                success = self.process_actions.block_process_network(process_id)
                if success:
                    self.logger.info(f"🚫 Network blocked for process {process_id} by server command")
            
        except Exception as e:
            self.logger.error(f"Error blocking network: {e}")
    
    def _handle_quarantine_file_command(self, params: Dict[str, Any]):
        """Handle quarantine file command"""
        try:
            file_path = params.get('file_path')
            process_id = params.get('process_id')
            
            if process_id and self.process_actions:
                success = self.process_actions.quarantine_process_executable(process_id)
                if success:
                    self.logger.info(f"🔒 File quarantined by server command: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error quarantining file: {e}")
    
    def _handle_update_config_command(self, params: Dict[str, Any]):
        """Handle configuration update command"""
        try:
            new_config = params.get('config', {})
            
            # Update configuration
            for section, values in new_config.items():
                if isinstance(values, dict):
                    for key, value in values.items():
                        self.config.set(section, key, value)
            
            # Save updated configuration
            self.config.save_config()
            
            self.logger.info("✅ Configuration updated from server")
            
        except Exception as e:
            self.logger.error(f"Error updating config: {e}")
    
    def _handle_update_rules_command(self, params: Dict[str, Any]):
        """Handle rules update command"""
        try:
            new_rules = params.get('rules', [])
            
            with self.rules_lock:
                self.active_rules = new_rules
            
            self.logger.info(f"✅ Rules updated from server: {len(new_rules)} rules")
            
        except Exception as e:
            self.logger.error(f"Error updating rules: {e}")
    
    def _handle_get_status_command(self, params: Dict[str, Any]):
        """Handle get status command"""
        try:
            status = self.get_status()
            
            # Send status back to server
            if self.connection:
                self.connection.send_logs({
                    'type': 'status_response',
                    'status': status
                })
            
            self.logger.info("📊 Status sent to server")
            
        except Exception as e:
            self.logger.error(f"Error handling get status: {e}")
    
    def update_rules(self, rules: List[Dict[str, Any]]):
        """Update active rules"""
        try:
            with self.rules_lock:
                self.active_rules = rules
            self.logger.info(f"📋 Updated {len(rules)} rules")
            
        except Exception as e:
            self.logger.error(f"Error updating rules: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status information"""
        try:
            uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
            
            return {
                'running': self.running,
                'connected': self.connection.is_connected() if self.connection else False,
                'agent_id': self.connection.agent_id if self.connection else None,
                'hostname': self.system_info.get('hostname'),
                'agent_version': self.config.get('agent', 'version'),
                'uptime': uptime,
                'monitors': {
                    'process': self.process_monitor.is_running() if self.process_monitor else False,
                    'file': self.file_monitor.is_running() if self.file_monitor else False,
                    'network': self.network_monitor.is_running() if self.network_monitor else False
                },
                'data_buffer_size': {
                    'processes': len(self.data_buffer.get('processes', [])),
                    'files': len(self.data_buffer.get('files', [])),
                    'networks': len(self.data_buffer.get('networks', []))
                },
                'statistics': self.stats.copy(),
                'active_rules': len(self.active_rules),
                'system_info': {
                    'cpu_usage': self._get_cpu_usage(),
                    'memory_usage': self._get_memory_usage(),
                    'disk_usage': self._get_disk_usage()
                }
            }
        except Exception as e:
            self.logger.error(f"Error getting status: {e}")
            return {'error': str(e)}
    
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