"""
enhanced_agent_core.py
Enhanced EDR Agent Core với database-ready logging
Tích hợp hoàn chỉnh với data formatters để gửi dữ liệu đúng schema database
"""

import os
import sys
import json
import time
import logging
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
import psutil
import platform
import queue
import socket

# Import enhanced formatters
from utils.data_formatters import (
    DataFormatter, 
    EnhancedEventProcessor,
    EnhancedProcessMonitor,
    EnhancedFileMonitor, 
    EnhancedNetworkMonitor,
    DatabaseSchemaValidator
)

# Import existing modules
from core.connection import ServerConnection
from core.scheduler import TaskScheduler
from actions.process_actions import ProcessActions
from actions.notification_actions import NotificationActions
from utils.log_sender import LogSender

class EnhancedEDRAgent:
    """Enhanced EDR Agent với database-ready logging và realtime transmission"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.system_info = {}
        
        # Core components
        self.connection = None
        self.scheduler = None
        self.log_sender = None
        
        # Enhanced components
        self.data_formatter = None
        self.event_processor = None
        self.schema_validator = None
        
        # Enhanced monitors
        self.process_monitor = None
        self.file_monitor = None
        self.network_monitor = None
        
        # Actions
        self.process_actions = None
        self.notification_actions = None
        
        # Rules và statistics
        self.active_rules = []
        self.rules_lock = threading.Lock()
        
        # Enhanced statistics
        self.stats = {
            'start_time': None,
            'events_processed': 0,
            'logs_sent': 0,
            'alerts_generated': 0,
            'rules_triggered': 0,
            'last_heartbeat': None,
            'format_errors': 0,
            'send_errors': 0,
            'validation_errors': 0,
            'database_logs_sent': {
                'process_logs': 0,
                'file_logs': 0,
                'network_logs': 0
            }
        }
        
        # Performance monitoring
        self.performance_stats = {
            'cpu_usage_samples': [],
            'memory_usage_samples': [],
            'event_processing_times': [],
            'last_performance_check': time.time()
        }
        
        # Initialize enhanced components
        self._initialize_enhanced_components()
        
        self.hostname = socket.gethostname()
        self.system_info['hostname'] = self.hostname
        
        self.logger.info("✅ Enhanced EDR Agent initialized with database-ready logging")
    
    def _initialize_enhanced_components(self):
        """Initialize all enhanced agent components"""
        try:
            # Get system information
            self.system_info = self.config.get_system_info()
            self.logger.info(f"System: {self.system_info.get('hostname')} - {self.system_info.get('os_version')}")
            
            # Initialize core connection
            self.connection = ServerConnection(self.config, self)
            
            # Initialize scheduler
            self.scheduler = TaskScheduler()
            
            # Initialize enhanced log sender
            self.log_sender = LogSender(self.config, self.connection)
            
            # Lấy hostname thực tế
            hostname = self.system_info.get('hostname') or getattr(self.connection, 'hostname', None)
            if not hostname or hostname == 'Unknown':
                try:
                    hostname = socket.gethostname()
                except:
                    hostname = None
            if not hostname:
                raise Exception('Không lấy được hostname thực tế cho agent!')
            # Initialize database components
            self.data_formatter = DataFormatter(self.config)
            self.event_processor = EnhancedEventProcessor(self.config, self.log_sender)
            self.schema_validator = DatabaseSchemaValidator()
            
            # Initialize enhanced monitors
            if self.config.PROCESS_MONITORING:
                self.process_monitor = EnhancedProcessMonitor(self.config, self.event_processor)
                self.logger.info("✅ Enhanced Process Monitor initialized")
                
            if self.config.FILE_MONITORING:
                self._initialize_file_monitor()
                
            if self.config.NETWORK_MONITORING:
                self.network_monitor = EnhancedNetworkMonitor(self.config, self.event_processor)
                self.logger.info("✅ Enhanced Network Monitor initialized")
            
            # Initialize actions
            self.process_actions = ProcessActions(self.config)
            self.notification_actions = NotificationActions(self.config)
            
            # Load initial rules
            self._load_initial_rules()
            
            # Start performance monitoring
            self._start_performance_monitoring()
            
            self.logger.info("✅ All enhanced components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize enhanced components: {e}")
            raise
    
    def start(self):
        """Start the enhanced EDR agent"""
        try:
            self.logger.info("🚀 Starting Enhanced EDR Agent with database-ready logging...")
            self.stats['start_time'] = time.time()
            self.running = True
            
            # Start connection
            if not self.connection.start():
                self.logger.warning("⚠️ Could not connect to server, starting in offline mode")
            
            # Register agent if connected
            if self.connection.is_connected():
                registration_success = self.connection.register_agent()
                if registration_success:
                    self.logger.info("✅ Agent registered successfully with server")
                    # Send initial database schema test
                    self._send_database_schema_test()
                else:
                    self.logger.warning("⚠️ Agent registration failed, continuing in offline mode")
            
            # Start enhanced log sender
            self.log_sender.start()
            
            # Start enhanced monitors with error handling
            monitors_started = 0
            if self.process_monitor:
                try:
                    result = self.process_monitor.start()
                    if result:
                        monitors_started += 1
                        self.logger.info("✅ Enhanced Process Monitor started")
                    else:
                        self.logger.error("❌ Process Monitor start() returned False")
                except Exception as e:
                    self.logger.error(f"Failed to start Process Monitor: {e}")
            else:
                self.logger.error("❌ Process Monitor is None (not initialized)")

            if self.file_monitor:
                try:
                    result = self.file_monitor.start()
                    if result:
                        monitors_started += 1
                        self.logger.info("✅ Enhanced File Monitor started")
                    else:
                        self.logger.error("❌ File Monitor start() returned False")
                except Exception as e:
                    self.logger.error(f"Failed to start File Monitor: {e}")
            else:
                self.logger.error("❌ File Monitor is None (not initialized)")

            if self.network_monitor:
                try:
                    result = self.network_monitor.start()
                    if result:
                        monitors_started += 1
                        self.logger.info("✅ Enhanced Network Monitor started")
                    else:
                        self.logger.error("❌ Network Monitor start() returned False")
                except Exception as e:
                    self.logger.error(f"Failed to start Network Monitor: {e}")
            else:
                self.logger.error("❌ Network Monitor is None (not initialized)")

            if monitors_started == 0:
                self.logger.error("❌ No monitors started successfully")
                return False
                
            # Start enhanced background tasks
            self._start_enhanced_tasks()
            
            # Start performance monitoring
            self._start_performance_monitoring()
            
            # Start validation monitoring
            self._start_validation_monitoring()
            
            # Start statistics reporting
            self._start_statistics_reporting()
            
            self.logger.info("✅ Enhanced EDR Agent started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to start Enhanced EDR Agent: {e}")
            return False
    
    def stop(self):
        """Stop the enhanced EDR agent gracefully"""
        try:
            self.logger.info("🛑 Stopping Enhanced EDR Agent...")
            self.running = False
            
            # Force send remaining logs before shutdown
            try:
                if self.log_sender:
                    flush_result = self.log_sender.emergency_flush()
                    if flush_result.get('success'):
                        sent_count = flush_result.get('items_sent', 0)
                        cached_count = flush_result.get('items_cached', 0)
                        self.logger.info(f"💾 Emergency flush: {sent_count} sent, {cached_count} cached")
            except Exception as e:
                self.logger.error(f"Error in emergency flush: {e}")
            
            # Stop enhanced monitors
            if self.process_monitor:
                self.process_monitor.stop()
                self.logger.info("✅ Enhanced Process Monitor stopped")
            
            if self.file_monitor:
                self.file_monitor.stop()
                self.logger.info("✅ Enhanced File Monitor stopped")
            
            if self.network_monitor:
                self.network_monitor.stop()
                self.logger.info("✅ Enhanced Network Monitor stopped")
            
            # Stop log sender
            if self.log_sender:
                self.log_sender.stop()
                self.logger.info("✅ Enhanced Log Sender stopped")
            
            # Stop connection
            if self.connection:
                self.connection.stop()
                self.logger.info("✅ Server Connection stopped")
            
            # Stop scheduler
            if self.scheduler:
                self.scheduler.stop()
                self.logger.info("✅ Scheduler stopped")
            
            # Stop notification actions
            if self.notification_actions:
                self.notification_actions.stop()
                self.logger.info("✅ Notification Actions stopped")
            
            # Log final statistics
            self._log_final_statistics()
            
            self.logger.info("✅ Enhanced EDR Agent stopped successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping enhanced agent: {e}")
    
    def _start_enhanced_tasks(self):
        """Start enhanced background tasks"""
        try:
            # Enhanced heartbeat with detailed metrics
            self._start_enhanced_heartbeat()
            
            # Enhanced rule checking
            self._start_enhanced_rule_checking()
            
            # Performance monitoring
            self._start_performance_monitoring()
            
            # Database validation monitoring
            self._start_validation_monitoring()
            
            # Statistics reporting
            self._start_statistics_reporting()
            
            self.logger.info("✅ All enhanced background tasks started")
            
        except Exception as e:
            self.logger.error(f"❌ Error starting enhanced tasks: {e}")
    
    def _start_enhanced_heartbeat(self):
        """Start enhanced heartbeat with system metrics"""
        def enhanced_heartbeat_task():
            while self.running:
                try:
                    # Send heartbeat
                    success = self.connection.send_heartbeat()
                    if success:
                        self.stats['last_heartbeat'] = time.time()
                    
                    # Send detailed system metrics every 5 minutes
                    if time.time() % 300 < 30:  # Every 5 minutes
                        self._send_detailed_system_metrics()
                    
                    time.sleep(self.config.HEARTBEAT_INTERVAL)
                    
                except Exception as e:
                    self.logger.error(f"Enhanced heartbeat error: {e}")
                    time.sleep(10)
        
        heartbeat_thread = threading.Thread(target=enhanced_heartbeat_task, daemon=True, name="EnhancedHeartbeat")
        heartbeat_thread.start()
        self.logger.info("✅ Enhanced heartbeat started")
    
    def _start_enhanced_rule_checking(self):
        """Start enhanced rule checking with database validation"""
        def enhanced_rule_check_task():
            while self.running:
                try:
                    # Check rules
                    self._check_rules()
                    
                    # Validate database schema
                    self._validate_database_schema()
                    
                    # Sync rules with server
                    self._sync_rules_with_server()
                    
                    # Update agent status
                    self._update_agent_status()
                    
                    time.sleep(self.config.RULE_CHECK_INTERVAL)
                    
                except Exception as e:
                    self.logger.error(f"Enhanced rule check error: {e}")
                    time.sleep(10)
        
        rule_check_thread = threading.Thread(target=enhanced_rule_check_task, daemon=True, name="EnhancedRuleCheck")
        rule_check_thread.start()
        self.logger.info("✅ Enhanced rule checking started")
    
    def _start_performance_monitoring(self):
        """Start performance monitoring"""
        def performance_monitor_task():
            while self.running:
                try:
                    # Collect performance metrics
                    self._collect_performance_metrics()
                    
                    # Send performance report every 5 minutes
                    if time.time() % 300 < 30:  # Every 5 minutes
                        self._send_performance_report()
                    
                    time.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"Performance monitoring error: {e}")
                    time.sleep(10)
        
        performance_thread = threading.Thread(target=performance_monitor_task, daemon=True, name="PerformanceMonitor")
        performance_thread.start()
        self.logger.info("✅ Performance monitoring started")
    
    def _start_validation_monitoring(self):
        """Start database validation monitoring"""
        def validation_monitor_task():
            while self.running:
                try:
                    # Validate database schema
                    validation_result = self.schema_validator.validate_schema()
                    
                    if not validation_result.get('valid'):
                        self.stats['validation_errors'] += 1
                        self.logger.error(f"Database schema validation failed: {validation_result.get('errors')}")
                    
                    time.sleep(300)  # Check every 5 minutes
                    
                except Exception as e:
                    self.logger.error(f"Validation monitoring error: {e}")
                    time.sleep(10)
        
        validation_thread = threading.Thread(target=validation_monitor_task, daemon=True, name="ValidationMonitor")
        validation_thread.start()
        self.logger.info("✅ Database validation monitoring started")
    
    def _start_statistics_reporting(self):
        """Start statistics reporting"""
        def statistics_report_task():
            while self.running:
                try:
                    # Send statistics report
                    self._send_statistics_report()
                    
                    time.sleep(300)  # Report every 5 minutes
                    
                except Exception as e:
                    self.logger.error(f"Statistics reporting error: {e}")
                    time.sleep(10)
        
        statistics_thread = threading.Thread(target=statistics_report_task, daemon=True, name="StatisticsReporter")
        statistics_thread.start()
        self.logger.info("✅ Statistics reporting started")
    
    def _check_rules(self):
        """Check rules with enhanced validation"""
        try:
            with self.rules_lock:
                for rule in self.active_rules:
                    try:
                        # Check if rule is still active
                        if not rule.is_active:
                            continue
                            
                        # Check rule
                        if rule.check():
                            self.stats['rules_triggered'] += 1
                            
                            # Generate alert
                            alert_data = rule.generate_alert()
                            if alert_data:
                                self.stats['alerts_generated'] += 1
                                
                                # Send alert
                                self.connection.send_alert(alert_data)
                                
                                # Show notification
                                if self.notification_actions:
                                    self.notification_actions.show_alert_notification(alert_data)
                    
                    except Exception as e:
                        self.logger.error(f"Error checking rule {rule.id}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error in rule checking: {e}")
    
    def _validate_database_schema(self):
        """Validate database schema"""
        try:
            validation_result = self.schema_validator.validate_schema()
            
            if not validation_result.get('valid'):
                self.stats['validation_errors'] += 1
                self.logger.error(f"Database schema validation failed: {validation_result.get('errors')}")
                
                # Try to fix schema
                fix_result = self.schema_validator.fix_schema()
                if fix_result.get('success'):
                    self.logger.info("✅ Database schema fixed successfully")
                else:
                    self.logger.error(f"Failed to fix database schema: {fix_result.get('errors')}")
            
        except Exception as e:
            self.logger.error(f"Error validating database schema: {e}")
    
    def _collect_performance_metrics(self):
        """Collect performance metrics"""
        try:
            # CPU Usage
            cpu_percent = psutil.cpu_percent()
            self.performance_stats['cpu_usage_samples'].append(cpu_percent)
            if len(self.performance_stats['cpu_usage_samples']) > 60:
                self.performance_stats['cpu_usage_samples'].pop(0)
            
            # Memory Usage
            memory = psutil.virtual_memory()
            self.performance_stats['memory_usage_samples'].append(memory.percent)
            if len(self.performance_stats['memory_usage_samples']) > 60:
                self.performance_stats['memory_usage_samples'].pop(0)
            
            # Event Processing Time
            if self.event_processor:
                event_stats = self.event_processor.get_stats()
                self.performance_stats['event_processing_times'].append({
                    'timestamp': time.time(),
                    'events_processed': event_stats['total_processed'],
                    'format_errors': event_stats['format_errors'],
                    'send_errors': event_stats['send_errors']
                })
                if len(self.performance_stats['event_processing_times']) > 60:
                    self.performance_stats['event_processing_times'].pop(0)
            
        except Exception as e:
            self.logger.error(f"Error collecting performance metrics: {e}")
    
    def _send_performance_report(self):
        """Send performance report to server"""
        try:
            if not self.connection.is_connected():
                return
            
            # Calculate averages
            cpu_avg = sum(self.performance_stats['cpu_usage_samples']) / len(self.performance_stats['cpu_usage_samples']) if self.performance_stats['cpu_usage_samples'] else 0
            memory_avg = sum(self.performance_stats['memory_usage_samples']) / len(self.performance_stats['memory_usage_samples']) if self.performance_stats['memory_usage_samples'] else 0
            
            # Prepare report
            report = {
                'timestamp': time.time(),
                'cpu_usage': {
                    'current': self.performance_stats['cpu_usage_samples'][-1] if self.performance_stats['cpu_usage_samples'] else 0,
                    'average': cpu_avg,
                    'samples': self.performance_stats['cpu_usage_samples']
                },
                'memory_usage': {
                    'current': self.performance_stats['memory_usage_samples'][-1] if self.performance_stats['memory_usage_samples'] else 0,
                    'average': memory_avg,
                    'samples': self.performance_stats['memory_usage_samples']
                },
                'event_processing': {
                    'total_processed': self.stats['events_processed'],
                    'format_errors': self.stats['format_errors'],
                    'send_errors': self.stats['send_errors'],
                    'samples': self.performance_stats['event_processing_times']
                }
            }
            
            # Send report
            self.connection.send_performance_report(report)
            
        except Exception as e:
            self.logger.error(f"Error sending performance report: {e}")
    
    def _send_statistics_report(self):
        """Send statistics report to server"""
        try:
            if not self.connection.is_connected():
                return
            
            # Prepare report
            report = {
                'timestamp': time.time(),
                'uptime': time.time() - self.stats['start_time'] if self.stats['start_time'] else 0,
                'events_processed': self.stats['events_processed'],
                'logs_sent': self.stats['logs_sent'],
                'alerts_generated': self.stats['alerts_generated'],
                'rules_triggered': self.stats['rules_triggered'],
                'format_errors': self.stats['format_errors'],
                'send_errors': self.stats['send_errors'],
                'validation_errors': self.stats['validation_errors'],
                'database_logs_sent': self.stats['database_logs_sent']
            }
            
            # Send report
            self.connection.send_statistics_report(report)
            
        except Exception as e:
            self.logger.error(f"Error sending statistics report: {e}")
    
    def _send_database_schema_test(self):
        """Send database schema test to server"""
        try:
            if not self.connection.is_connected():
                return
            
            # Get schema test data
            test_data = self.schema_validator.get_schema_test_data()
            
            # Send test
            self.connection.send_schema_test(test_data)
            
        except Exception as e:
            self.logger.error(f"Error sending database schema test: {e}")
    
    def _send_initial_system_info(self):
        """Send initial system info to server"""
        try:
            if not self.connection.is_connected():
                return
            
            # Send system info
            self.connection.send_system_info(self.system_info)
            
        except Exception as e:
            self.logger.error(f"Error sending initial system info: {e}")
    
    def _send_detailed_system_metrics(self):
        """Send detailed system metrics to server"""
        try:
            if not self.connection.is_connected():
                return
            metrics = {
                'timestamp': time.time(),
                'cpu': {
                    'percent': psutil.cpu_percent(interval=1),
                    'count': psutil.cpu_count(),
                    'frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 0
                },
                'memory': {
                    'total': psutil.virtual_memory().total,
                    'available': psutil.virtual_memory().available,
                    'percent': psutil.virtual_memory().percent
                },
                'disk': {
                    'total': 0,
                    'used': 0,
                    'free': 0,
                    'percent': 0
                },
                'network': {
                    'bytes_sent': psutil.net_io_counters().bytes_sent,
                    'bytes_recv': psutil.net_io_counters().bytes_recv,
                    'packets_sent': psutil.net_io_counters().packets_sent,
                    'packets_recv': psutil.net_io_counters().packets_recv
                }
            }
            # Try to get disk info (cross-platform)
            try:
                if platform.system() == 'Windows':
                    disk_usage = psutil.disk_usage('C:\\')
                else:
                    disk_usage = psutil.disk_usage('/')
                metrics['disk'] = {
                    'total': disk_usage.total,
                    'used': disk_usage.used,
                    'free': disk_usage.free,
                    'percent': disk_usage.percent
                }
            except Exception as e:
                self.logger.warning(f"Error getting disk info: {e}")
            self.connection.send_system_metrics(metrics)
        except Exception as e:
            self.logger.error(f"Error sending detailed system metrics: {e}")
    
    def _load_initial_rules(self):
        """Load initial rules from server"""
        try:
            if not self.connection.is_connected():
                self.logger.warning("⚠️ Not connected to server, loading default rules")
                return
                
            # Get rules from server
            response = self.connection.get_rules()
            if not response or 'rules' not in response:
                self.logger.warning("⚠️ No rules received from server")
                return
                
            # Create rules
            for rule_data in response['rules']:
                try:
                    if not rule_data['IsActive']:
                        continue
                        
                    rule = self._create_rule({
                        'id': rule_data['RuleID'],
                        'name': rule_data['RuleName'],
                        'type': rule_data['RuleType'],
                        'description': rule_data['Description'],
                        'severity': rule_data['Severity'],
                        'action': rule_data['Action'],
                        'is_global': rule_data['IsGlobal'],
                        'os_type': rule_data['OSType']
                    })
                    if rule:
                        self.active_rules.append(rule)
                except Exception as e:
                    self.logger.error(f"Error creating rule: {e}")
                    
            self.logger.info(f"✅ Loaded {len(self.active_rules)} initial rules")
            
        except Exception as e:
            self.logger.error(f"Error loading initial rules: {e}")
    
    def _create_rule(self, rule_config: Dict[str, Any]):
        """Create a rule from config"""
        try:
            # Import rule class
            rule_class = self._import_rule_class(rule_config.get('type'))
            if not rule_class:
                return None
            
            # Create rule
            rule = rule_class(
                id=rule_config.get('id'),
                name=rule_config.get('name'),
                description=rule_config.get('description'),
                conditions=rule_config.get('conditions', []),
                actions=rule_config.get('actions', []),
                config=self.config
            )
            
            return rule
            
        except Exception as e:
            self.logger.error(f"Error creating rule: {e}")
            return None
    
    def _import_rule_class(self, rule_type: str):
        """Import rule class"""
        try:
            # Import rule module
            module_name = f"rules.{rule_type.lower()}_rule"
            module = __import__(module_name, fromlist=['Rule'])
            
            # Get rule class
            rule_class = getattr(module, 'Rule')
            
            return rule_class
            
        except Exception as e:
            self.logger.error(f"Error importing rule class: {e}")
            return None
    
    def _log_final_statistics(self):
        """Log final statistics"""
        try:
            # Calculate uptime
            uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
            
            # Log statistics
            self.logger.info(f"""
Final Statistics:
----------------
Uptime: {uptime:.2f} seconds
Events Processed: {self.stats['events_processed']}
Logs Sent: {self.stats['logs_sent']}
Alerts Generated: {self.stats['alerts_generated']}
Rules Triggered: {self.stats['rules_triggered']}
Format Errors: {self.stats['format_errors']}
Send Errors: {self.stats['send_errors']}
Validation Errors: {self.stats['validation_errors']}

Database Logs Sent:
------------------
Process Logs: {self.stats['database_logs_sent']['process_logs']}
File Logs: {self.stats['database_logs_sent']['file_logs']}
Network Logs: {self.stats['database_logs_sent']['network_logs']}
""")
            
        except Exception as e:
            self.logger.error(f"Error logging final statistics: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        try:
            return {
                'running': self.running,
                'connected': self.connection.is_connected() if self.connection else False,
                'hostname': self.system_info.get('hostname', 'Unknown'),
                'agent_version': self.config.get('agent', 'version', '2.0.0'),
                'uptime': time.time() - self.stats['start_time'] if self.stats['start_time'] else 0,
                'monitors': {
                    'process': self.process_monitor is not None,
                    'file': self.file_monitor is not None,
                    'network': self.network_monitor is not None
                },
                'data_buffer_size': {
                    'processes': self.stats['database_logs_sent']['process_logs'],
                    'files': self.stats['database_logs_sent']['file_logs'],
                    'networks': self.stats['database_logs_sent']['network_logs']
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting agent status: {e}")
            return {
                'running': False,
                'error': str(e)
            }

    def _scan_watched_paths(self):
        """Scan all watched paths for initial file state"""
        try:
            if not self.file_monitor:
                return
                
            watched_paths = self.config.get('file_monitoring', {}).get('watch_paths', [])
            for path in watched_paths:
                try:
                    if os.path.exists(path):
                        for root, dirs, files in os.walk(path):
                            for file in files:
                                try:
                                    file_path = os.path.join(root, file)
                                    file_info = {
                                        'hostname': self.system_info.get('hostname'),
                                        'time': datetime.now(),
                                        'file_name': file,
                                        'file_path': file_path,
                                        'file_size': os.path.getsize(file_path),
                                        'file_hash': self._calculate_file_hash(file_path),
                                        'event_type': 'existing',
                                        'process_id': os.getpid(),
                                        'process_name': 'edr_agent.exe'
                                    }
                                    self.event_processor.process_file_event(file_info)
                                except Exception as e:
                                    self.logger.error(f"Error scanning file {file_path}: {e}")
                except Exception as e:
                    self.logger.error(f"Error scanning path {path}: {e}")
                    
            self.logger.info(f"✅ Initial file scan completed for {len(watched_paths)} paths")
            
        except Exception as e:
            self.logger.error(f"Error in initial file scan: {e}")

    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        try:
            import hashlib
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating file hash: {e}")
            return None

    def _sync_rules_with_server(self):
        """Sync rules with server and update local rules"""
        try:
            if not self.connection.is_connected():
                return
            
            # Get rules from server
            response = self.connection.get_rules()
            if not response or 'rules' not in response:
                return
                
            new_rules = response['rules']
            current_time = datetime.now()
            
            # Update rules
            with self.rules_lock:
                # Remove inactive rules
                self.active_rules = [rule for rule in self.active_rules 
                                   if any(r['RuleID'] == rule.id and r['IsActive'] 
                                         for r in new_rules)]
                
                # Add new rules
                for rule_data in new_rules:
                    if not rule_data['IsActive']:
                        continue
                        
                    # Check if rule already exists
                    if not any(rule.id == rule_data['RuleID'] for rule in self.active_rules):
                        try:
                            rule = self._create_rule({
                                'id': rule_data['RuleID'],
                                'name': rule_data['RuleName'],
                                'type': rule_data['RuleType'],
                                'description': rule_data['Description'],
                                'severity': rule_data['Severity'],
                                'action': rule_data['Action'],
                                'is_global': rule_data['IsGlobal'],
                                'os_type': rule_data['OSType']
                            })
                            if rule:
                                self.active_rules.append(rule)
                                self.logger.info(f"✅ Added new rule: {rule_data['RuleName']}")
                        except Exception as e:
                            self.logger.error(f"Error creating rule {rule_data['RuleName']}: {e}")
            
            self.logger.info(f"✅ Synced {len(self.active_rules)} active rules")
            
        except Exception as e:
            self.logger.error(f"Error syncing rules: {e}")

    def _update_agent_status(self):
        """Update agent status on server"""
        try:
            if not self.connection.is_connected():
                return
            
            # Prepare status update
            status_data = {
                'hostname': self.system_info.get('hostname'),
                'status': 'Online',
                'last_heartbeat': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'is_active': True,
                'agent_version': self.config.AGENT_VERSION,
                'os_type': self.system_info.get('os_type'),
                'os_version': self.system_info.get('os_version'),
                'architecture': self.system_info.get('architecture'),
                'ip_address': self.system_info.get('ip_address'),
                'mac_address': self.system_info.get('mac_address')
            }
            
            # Send status update
            success = self.connection.update_agent_status(status_data)
            if success:
                self.logger.debug("✅ Agent status updated")
            else:
                self.logger.warning("⚠️ Failed to update agent status")
            
        except Exception as e:
            self.logger.error(f"Error updating agent status: {e}")

    def _initialize_file_monitor(self):
        """Initialize file monitoring with enhanced error handling and multiple fallbacks"""
        try:
            from monitors.file_monitor import EnhancedFileMonitor
            self.file_monitor = EnhancedFileMonitor(self.config, self.event_processor)
            watched_paths = self.config.get('file_monitor', {}).get('watched_paths', [])
            if not watched_paths:
                watched_paths = [
                    'C:\\Windows\\System32',
                    'C:\\Program Files',
                    'C:\\Program Files (x86)',
                    os.path.expanduser('~'),
                    os.path.join(os.path.expanduser('~'), 'Desktop'),
                    os.path.join(os.path.expanduser('~'), 'Downloads'),
                    os.path.join(os.path.expanduser('~'), 'Documents'),
                    os.path.join(os.path.expanduser('~'), 'Pictures'),
                    os.path.join(os.path.expanduser('~'), 'Music'),
                    os.path.join(os.path.expanduser('~'), 'Videos'),
                ]
            # Loại bỏ các path không truy cập được
            valid_paths = []
            for path in watched_paths:
                try:
                    if os.path.exists(path) and os.access(path, os.R_OK):
                        # Thử truy cập thư mục
                        os.listdir(path)
                        valid_paths.append(path)
                except Exception:
                    continue  # Bỏ qua path lỗi
            self.file_monitor.set_watched_paths(valid_paths)
            self.logger.info(f"✅ Enhanced File Monitor started with {len(valid_paths)} valid paths")
        except Exception as e:
            self.file_monitor = None
            self.logger.error(f"Error initializing file monitor: {e}")

    def get_disk_info(self):
        """Get disk information with enhanced error handling and OS-specific paths"""
        try:
            disk_info = {}
            system = platform.system().lower()
            
            if system == 'windows':
                # Windows: Get all drive letters
                import string
                import ctypes
                
                drives = []
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for letter in string.ascii_uppercase:
                    if bitmask & 1:
                        drive = f"{letter}:\\"
                        try:
                            if os.path.exists(drive):
                                usage = psutil.disk_usage(drive)
                                disk_info[drive] = {
                                    'total': usage.total,
                                    'used': usage.used,
                                    'free': usage.free,
                                    'percent': usage.percent,
                                    'fstype': 'NTFS',  # Default for Windows
                                    'mountpoint': drive
                                }
                        except Exception as e:
                            self.logger.debug(f"Error getting disk info for {drive}: {e}")
                    bitmask >>= 1
            
            else:  # Linux/Unix/Mac
                for partition in psutil.disk_partitions():
                    try:
                        if os.path.exists(partition.mountpoint):
                            usage = psutil.disk_usage(partition.mountpoint)
                            disk_info[partition.device] = {
                                'total': usage.total,
                                'used': usage.used,
                                'free': usage.free,
                                'percent': usage.percent,
                                'fstype': partition.fstype,
                                'mountpoint': partition.mountpoint
                            }
                    except Exception as e:
                        self.logger.debug(f"Error getting disk info for {partition.device}: {e}")
            
            if not disk_info:
                self.logger.debug("No disk information could be retrieved")
            
            return disk_info
            
        except Exception as e:
            self.logger.debug(f"Error getting disk info: {e}")
            return {}

    def _send_logs_to_server(self):
        """Send logs to server with enhanced error handling and retry mechanism"""
        try:
            if not self.connection or not hasattr(self.connection, 'socketio'):
                self.logger.warning("Server connection not initialized, attempting to reconnect...")
                self._reconnect_to_server()
                return
            
            if not self.connection.is_connected():
                self.logger.warning("Not connected to server, attempting to reconnect...")
                self._reconnect_to_server()
                return
            
            # Get logs from queue with size limit
            max_batch_size = 100
            logs_to_send = []
            while len(logs_to_send) < max_batch_size and not self.log_queue.empty():
                try:
                    log = self.log_queue.get_nowait()
                    # Ensure hostname is set correctly
                    if isinstance(log, dict):
                        if 'Hostname' in log:
                            log['Hostname'] = self.system_info.get('hostname', 'Unknown')
                        elif 'hostname' in log:
                            log['hostname'] = self.system_info.get('hostname', 'Unknown')
                    logs_to_send.append(log)
                except queue.Empty:
                    break
            
            if not logs_to_send:
                return
            
            # Send logs with retry
            retry_count = 0
            max_retries = 3
            while retry_count < max_retries:
                try:
                    success = self.connection.send_logs(logs_to_send)
                    if success:
                        self.logger.debug(f"✅ Successfully sent {len(logs_to_send)} logs to server")
                        return
                    else:
                        self.logger.warning(f"Failed to send logs (attempt {retry_count + 1}/{max_retries})")
                except Exception as e:
                    self.logger.error(f"Error sending logs (attempt {retry_count + 1}/{max_retries}): {e}")
                
                retry_count += 1
                if retry_count < max_retries:
                    time.sleep(1)  # Wait before retry
            
            # If all retries failed, put logs back in queue
            for log in logs_to_send:
                self.log_queue.put(log)
            
            # If queue is too large, log warning
            if self.log_queue.qsize() > 1000:
                self.logger.warning(f"Log queue size too large: {self.log_queue.qsize()}")
            
        except Exception as e:
            self.logger.error(f"Error in _send_logs_to_server: {e}")
    
    def _reconnect_to_server(self):
        """Reconnect to server with retry mechanism"""
        try:
            retry_count = 0
            max_retries = 3
            while retry_count < max_retries:
                try:
                    if self.connection:
                        self.connection.disconnect()
                    
                    self.connection = ServerConnection(
                        self.config.get('server_url', 'http://localhost:5000'),
                        self.config.get('agent_id', 'default-agent'),
                        self.logger
                    )
                    
                    if self.connection.connect():
                        self.logger.info("✅ Successfully reconnected to server")
                        return True
                    else:
                        self.logger.warning(f"Failed to reconnect (attempt {retry_count + 1}/{max_retries})")
                except Exception as e:
                    self.logger.error(f"Error reconnecting (attempt {retry_count + 1}/{max_retries}): {e}")
                
                retry_count += 1
                if retry_count < max_retries:
                    time.sleep(2)  # Wait longer between reconnection attempts
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error in _reconnect_to_server: {e}")
            return False

    def _on_process_event(self, event_data: Dict[str, Any]):
        try:
            if not isinstance(event_data, dict):
                self.logger.error("Invalid process event data format")
                return
            if 'timestamp' not in event_data:
                event_data['timestamp'] = datetime.utcnow().isoformat()
            event_data['hostname'] = self.hostname
            # ... existing code ...
        except Exception as e:
            self.logger.error(f"Error processing process event: {e}")

    def _on_file_event(self, event_data: Dict[str, Any]):
        try:
            if not isinstance(event_data, dict):
                self.logger.error("Invalid file event data format")
                return
            if 'timestamp' not in event_data:
                event_data['timestamp'] = datetime.utcnow().isoformat()
            event_data['hostname'] = self.hostname
            # ... existing code ...
        except Exception as e:
            self.logger.error(f"Error processing file event: {e}")

    def _on_network_event(self, event_data: Dict[str, Any]):
        try:
            if not isinstance(event_data, dict):
                self.logger.error("Invalid network event data format")
                return
            if 'timestamp' not in event_data:
                event_data['timestamp'] = datetime.utcnow().isoformat()
            event_data['hostname'] = self.hostname
            # ... existing code ...
        except Exception as e:
            self.logger.error(f"Error processing network event: {e}") 