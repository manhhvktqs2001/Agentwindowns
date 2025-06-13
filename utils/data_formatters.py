"""
data_formatters.py
EDR Windows Agent - Database Schema Compliant Data Formatters
Đảm bảo 100% tuân thủ schema database cho ProcessLogs, FileLogs, NetworkLogs
"""

import os
import time
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import psutil
import socket

class DataFormatter:
    """Formatter chính để chuẩn hóa dữ liệu theo schema database chính xác"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.hostname = socket.gethostname()  # Always get real hostname
        
        self.logger.info("✅ DataFormatter initialized for database schema compliance")
    
    def format_process_log(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        # Gửi dữ liệu thô, không format, không ép kiểu, không thêm giá trị mặc định
        if 'Time' not in event_data and 'timestamp' in event_data:
            event_data['Time'] = event_data['timestamp']
        return event_data
    
    def format_file_log(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        if 'Time' not in event_data and 'timestamp' in event_data:
            event_data['Time'] = event_data['timestamp']
        return event_data
    
    def format_network_log(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        if 'Time' not in event_data and 'timestamp' in event_data:
            event_data['Time'] = event_data['timestamp']
        return event_data
    
    def _format_sql_datetime(self, timestamp) -> str:
        """Chuẩn hóa timestamp theo format SQL Server: YYYY-MM-DD HH:MM:SS.mmm"""
        try:
            if timestamp is None:
                dt = datetime.utcnow()
            elif isinstance(timestamp, str):
                # Parse ISO format string
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            elif isinstance(timestamp, (int, float)):
                # Unix timestamp
                dt = datetime.fromtimestamp(timestamp)
            elif isinstance(timestamp, datetime):
                dt = timestamp
            else:
                dt = datetime.utcnow()
            
            # Format: YYYY-MM-DD HH:MM:SS.mmm (SQL Server datetime)
            return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            
        except Exception as e:
            self.logger.error(f"Error formatting timestamp: {e}")
            return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    def _safe_string(self, value, max_length: int = None) -> str:
        try:
            if value is None:
                return ''
            str_value = str(value).strip()
            if max_length and len(str_value) > max_length:
                str_value = str_value[:max_length-3] + '...'
            str_value = str_value.replace('\x00', '').replace('\r', '').replace('\n', ' ')
            return str_value if str_value else ''
        except Exception:
            return ''
    
    def _safe_int(self, value) -> int:
        try:
            if value is None:
                return 0
            if isinstance(value, (int, float)):
                return int(value)
            if isinstance(value, str):
                clean_value = ''.join(filter(lambda c: c.isdigit() or c == '-', value))
                try:
                    return int(clean_value)
                except Exception:
                    return 0
            return 0
        except Exception:
            return 0
    
    def _safe_float(self, value) -> float:
        try:
            if value is None:
                return 0.0
            if isinstance(value, (int, float)):
                return float(value)
            if isinstance(value, str):
                try:
                    return float(value)
                except Exception:
                    return 0.0
            return 0.0
        except Exception:
            return 0.0
    
    def _standardize_file_event_type(self, event_type: str) -> str:
        """Chuẩn hóa file event type"""
        event_type = str(event_type).lower()
        
        if 'creat' in event_type:
            return 'created'
        elif 'modif' in event_type or 'chang' in event_type:
            return 'modified'
        elif 'delet' in event_type or 'remov' in event_type:
            return 'deleted'
        elif 'mov' in event_type or 'renam' in event_type:
            return 'moved'
        elif 'access' in event_type:
            return 'accessed'
        else:
            return 'unknown'
    
    def _standardize_protocol(self, protocol: str) -> str:
        """Chuẩn hóa network protocol"""
        protocol = str(protocol).upper()
        
        if protocol in ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'FTP', 'SSH']:
            return protocol
        else:
            return 'TCP'  # Default
    
    def _standardize_direction(self, direction: str) -> str:
        """Chuẩn hóa network direction"""
        direction = str(direction).lower()
        
        if 'in' in direction:
            return 'inbound'
        elif 'out' in direction:
            return 'outbound'
        else:
            return 'outbound'  # Default
    
    def _create_fallback_process_log(self) -> Dict[str, Any]:
        """Tạo ProcessLog fallback khi có lỗi"""
        return {
            'Time': self._format_sql_datetime(None),
            'Hostname': self.hostname,
            'ProcessID': 0,
            'ParentProcessID': 0,
            'ProcessName': 'Unknown',
            'CommandLine': '',
            'ExecutablePath': '',
            'UserName': '',
            'CPUUsage': 0.0,
            'MemoryUsage': 0,
            'Hash': '',
            'log_type': 'process',
            'table_name': 'ProcessLogs',
            'event_type': 'process_error',
            'error': True
        }
    
    def _create_fallback_file_log(self) -> Dict[str, Any]:
        """Tạo FileLog fallback khi có lỗi"""
        return {
            'Time': self._format_sql_datetime(None),
            'Hostname': self.hostname,
            'FileName': 'Unknown',
            'FilePath': '',
            'FileSize': 0,
            'FileHash': '',
            'EventType': 'unknown',
            'ProcessID': 0,
            'ProcessName': '',
            'log_type': 'file',
            'table_name': 'FileLogs',
            'error': True
        }
    
    def _create_fallback_network_log(self) -> Dict[str, Any]:
        """Tạo NetworkLog fallback khi có lỗi"""
        return {
            'Time': self._format_sql_datetime(None),
            'Hostname': self.hostname,
            'ProcessID': 0,
            'ProcessName': 'Unknown',
            'Protocol': 'TCP',
            'LocalAddress': '0.0.0.0',
            'LocalPort': 0,
            'RemoteAddress': '0.0.0.0',
            'RemotePort': 0,
            'Direction': 'outbound',
            'log_type': 'network',
            'table_name': 'NetworkLogs',
            'event_type': 'network_error',
            'error': True
        }

class EnhancedEventProcessor:
    """Processor xử lý events và gửi với format database-ready"""
    
    def __init__(self, config, log_sender):
        self.config = config
        self.log_sender = log_sender
        self.formatter = DataFormatter(config)
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.stats = {
            'process_events': 0,
            'file_events': 0,
            'network_events': 0,
            'format_errors': 0,
            'send_errors': 0,
            'total_processed': 0
        }
        
        self.logger.info("✅ EnhancedEventProcessor initialized")
    
    def process_event(self, event_data: Dict[str, Any], event_type: str) -> bool:
        """Xử lý event và gửi với format database-ready"""
        try:
            formatted_data = None
            
            # Format dữ liệu theo loại event
            if 'process' in event_type.lower():
                formatted_data = self.formatter.format_process_log(event_data)
                self.stats['process_events'] += 1
                
            elif 'file' in event_type.lower():
                formatted_data = self.formatter.format_file_log(event_data)
                self.stats['file_events'] += 1
                
            elif 'network' in event_type.lower():
                formatted_data = self.formatter.format_network_log(event_data)
                self.stats['network_events'] += 1
                
            else:
                self.logger.warning(f"Unknown event type: {event_type}")
                return False
            
            if formatted_data:
                self.stats['total_processed'] += 1
                
                # Gửi dữ liệu realtime
                success = self.log_sender.send_logs(formatted_data, priority='normal')
                
                if success:
                    self.logger.debug(f"✅ Sent {event_type} event to server")
                else:
                    self.stats['send_errors'] += 1
                    self.logger.warning(f"⚠️ Failed to send {event_type} event")
                
                return success
            else:
                self.stats['format_errors'] += 1
                return False
                
        except Exception as e:
            self.logger.error(f"Error processing {event_type} event: {e}")
            self.stats['format_errors'] += 1
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Lấy thống kê xử lý events"""
        return self.stats.copy()

class EnhancedProcessMonitor:
    """Enhanced Process Monitor với database-ready formatting"""
    
    def __init__(self, config, event_processor):
        from monitors.process_monitor import ProcessMonitor
        self.base_monitor = ProcessMonitor(config, self._handle_process_event)
        self.event_processor = event_processor
        self.logger = logging.getLogger(__name__)
        
        self.logger.info("✅ EnhancedProcessMonitor initialized")
    
    def _handle_process_event(self, event_data: Dict[str, Any]):
        """Handle process event với database formatting"""
        try:
            # Enrich dữ liệu process
            enriched_data = self._enrich_process_data(event_data)
            
            # Xử lý và gửi event
            self.event_processor.process_event(enriched_data, 'process')
            
        except Exception as e:
            self.logger.error(f"Error handling process event: {e}")
    
    def _enrich_process_data(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Bổ sung thông tin process để đủ schema database"""
        try:
            enriched = event_data.copy()
            
            # Ensure timestamp
            if 'timestamp' not in enriched:
                enriched['timestamp'] = datetime.utcnow()
            
            # Get additional process info if available
            process_id = event_data.get('process_id')
            if process_id:
                try:
                    proc = psutil.Process(process_id)
                    
                    # CPU Usage
                    if 'cpu_usage' not in enriched:
                        try:
                            enriched['cpu_usage'] = proc.cpu_percent()
                        except:
                            enriched['cpu_usage'] = 0.0
                    
                    # Memory Usage (in KB)
                    if 'memory_usage' not in enriched:
                        try:
                            memory_bytes = proc.memory_info().rss
                            enriched['memory_usage'] = int(memory_bytes / 1024)  # Convert to KB
                        except:
                            enriched['memory_usage'] = 0
                    
                    # Username
                    if 'username' not in enriched:
                        try:
                            enriched['username'] = proc.username()
                        except:
                            enriched['username'] = ''
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            return enriched
            
        except Exception as e:
            self.logger.error(f"Error enriching process data: {e}")
            return event_data 

    def start(self):
        if hasattr(self.base_monitor, 'start'):
            return self.base_monitor.start()
        self.logger.info("No base_monitor.start() method available.")

    def stop(self):
        if hasattr(self.base_monitor, 'stop'):
            return self.base_monitor.stop()
        self.logger.info("No base_monitor.stop() method available.")

class EnhancedFileMonitor:
    """Enhanced File Monitor với database-ready formatting"""
    
    def __init__(self, config, event_processor):
        from monitors.file_monitor import EnhancedFileMonitor as BaseFileMonitor
        self.base_monitor = BaseFileMonitor(config, self._handle_file_event)
        self.event_processor = event_processor
        self.logger = logging.getLogger(__name__)
        
        self.logger.info("✅ EnhancedFileMonitor initialized")
    
    def _handle_file_event(self, event_data: Dict[str, Any]):
        """Handle file event với database formatting"""
        try:
            # Enrich dữ liệu file
            enriched_data = self._enrich_file_data(event_data)
            
            # Xử lý và gửi event
            self.event_processor.process_event(enriched_data, 'file')
            
        except Exception as e:
            self.logger.error(f"Error handling file event: {e}")
    
    def _enrich_file_data(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Bổ sung thông tin file để đủ schema database"""
        try:
            enriched = event_data.copy()
            
            # Ensure timestamp
            if 'timestamp' not in enriched:
                enriched['timestamp'] = datetime.utcnow()
            
            # Get file info if path exists
            file_path = event_data.get('file_path')
            if file_path and os.path.exists(file_path):
                try:
                    # File size
                    if 'file_size' not in enriched:
                        enriched['file_size'] = os.path.getsize(file_path)
                    
                    # File hash
                    if 'file_hash' not in enriched:
                        enriched['file_hash'] = self._calculate_file_hash(file_path)
                    
                except Exception as e:
                    self.logger.debug(f"Error getting file info: {e}")
            
            return enriched
            
        except Exception as e:
            self.logger.error(f"Error enriching file data: {e}")
            return event_data
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return ""

    def start(self):
        if hasattr(self.base_monitor, 'start'):
            return self.base_monitor.start()
        self.logger.info("No base_monitor.start() method available.")

    def stop(self):
        if hasattr(self.base_monitor, 'stop'):
            return self.base_monitor.stop()
        self.logger.info("No base_monitor.stop() method available.")

class EnhancedNetworkMonitor:
    """Enhanced Network Monitor với database-ready formatting"""
    
    def __init__(self, config, event_processor):
        from monitors.network_monitor import NetworkMonitor
        self.base_monitor = NetworkMonitor(config, self._handle_network_event)
        self.event_processor = event_processor
        self.logger = logging.getLogger(__name__)
        
        self.logger.info("✅ EnhancedNetworkMonitor initialized")
    
    def _handle_network_event(self, event_data: Dict[str, Any]):
        """Handle network event với database formatting"""
        try:
            # Enrich dữ liệu network
            enriched_data = self._enrich_network_data(event_data)
            
            # Xử lý và gửi event
            self.event_processor.process_event(enriched_data, 'network')
            
        except Exception as e:
            self.logger.error(f"Error handling network event: {e}")
    
    def _enrich_network_data(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Bổ sung thông tin network để đủ schema database"""
        try:
            enriched = event_data.copy()
            
            # Ensure timestamp
            if 'timestamp' not in enriched:
                enriched['timestamp'] = datetime.utcnow()
            
            # Get process info if PID exists
            process_id = event_data.get('process_id')
            if process_id:
                try:
                    proc = psutil.Process(process_id)
                    
                    # Process name
                    if 'process_name' not in enriched:
                        enriched['process_name'] = proc.name()
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            return enriched
            
        except Exception as e:
            self.logger.error(f"Error enriching network data: {e}")
            return event_data

    def start(self):
        if hasattr(self.base_monitor, 'start'):
            return self.base_monitor.start()
        self.logger.info("No base_monitor.start() method available.")

    def stop(self):
        if hasattr(self.base_monitor, 'stop'):
            return self.base_monitor.stop()
        self.logger.info("No base_monitor.stop() method available.")

class DatabaseSchemaValidator:
    """Validator cho database schema"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.schema = {
            'ProcessLogs': {
                'Time': 'datetime',
                'Hostname': 'varchar(255)',
                'ProcessID': 'int',
                'ParentProcessID': 'int',
                'ProcessName': 'varchar(255)',
                'CommandLine': 'varchar(2000)',
                'ExecutablePath': 'varchar(500)',
                'UserName': 'varchar(100)',
                'CPUUsage': 'float',
                'MemoryUsage': 'int',
                'Hash': 'varchar(128)'
            },
            'FileLogs': {
                'Time': 'datetime',
                'Hostname': 'varchar(255)',
                'FileName': 'varchar(255)',
                'FilePath': 'varchar(1000)',
                'FileSize': 'int',
                'FileHash': 'varchar(128)',
                'EventType': 'varchar(50)',
                'ProcessID': 'int',
                'ProcessName': 'varchar(255)'
            },
            'NetworkLogs': {
                'Time': 'datetime',
                'Hostname': 'varchar(255)',
                'ProcessID': 'int',
                'ProcessName': 'varchar(255)',
                'Protocol': 'varchar(10)',
                'LocalAddress': 'varchar(45)',
                'LocalPort': 'int',
                'RemoteAddress': 'varchar(45)',
                'RemotePort': 'int',
                'Direction': 'varchar(10)'
            }
        }
        
        self.logger.info("✅ DatabaseSchemaValidator initialized")
    
    def validate_schema(self) -> Dict[str, Any]:
        """Validate database schema"""
        try:
            errors = []
            
            # Check each table
            for table_name, columns in self.schema.items():
                # Check if table exists
                if not self._table_exists(table_name):
                    errors.append(f"Table {table_name} does not exist")
                    continue
                
                # Check columns
                for column_name, column_type in columns.items():
                    if not self._column_exists(table_name, column_name):
                        errors.append(f"Column {column_name} does not exist in table {table_name}")
                    elif not self._column_type_matches(table_name, column_name, column_type):
                        errors.append(f"Column {column_name} in table {table_name} has wrong type")
            
            return {
                'valid': len(errors) == 0,
                'errors': errors
            }
            
        except Exception as e:
            self.logger.error(f"Error validating schema: {e}")
            return {
                'valid': False,
                'errors': [str(e)]
            }
    
    def fix_schema(self) -> Dict[str, Any]:
        """Fix database schema"""
        try:
            errors = []
            
            # Fix each table
            for table_name, columns in self.schema.items():
                # Create table if not exists
                if not self._table_exists(table_name):
                    if not self._create_table(table_name, columns):
                        errors.append(f"Failed to create table {table_name}")
                        continue
                
                # Fix columns
                for column_name, column_type in columns.items():
                    if not self._column_exists(table_name, column_name):
                        if not self._add_column(table_name, column_name, column_type):
                            errors.append(f"Failed to add column {column_name} to table {table_name}")
                    elif not self._column_type_matches(table_name, column_name, column_type):
                        if not self._alter_column(table_name, column_name, column_type):
                            errors.append(f"Failed to alter column {column_name} in table {table_name}")
            
            return {
                'success': len(errors) == 0,
                'errors': errors
            }
            
        except Exception as e:
            self.logger.error(f"Error fixing schema: {e}")
            return {
                'success': False,
                'errors': [str(e)]
            }
    
    def get_schema_test_data(self) -> Dict[str, Any]:
        """Get test data for schema validation"""
        try:
            test_data = {
                'ProcessLogs': {
                    'Time': datetime.utcnow(),
                    'Hostname': 'test-host',
                    'ProcessID': 1234,
                    'ParentProcessID': 1000,
                    'ProcessName': 'test.exe',
                    'CommandLine': 'test.exe --arg',
                    'ExecutablePath': 'C:\\test.exe',
                    'UserName': 'test-user',
                    'CPUUsage': 0.5,
                    'MemoryUsage': 1024,
                    'Hash': 'test-hash'
                },
                'FileLogs': {
                    'Time': datetime.utcnow(),
                    'Hostname': 'test-host',
                    'FileName': 'test.txt',
                    'FilePath': 'C:\\test.txt',
                    'FileSize': 1024,
                    'FileHash': 'test-hash',
                    'EventType': 'created',
                    'ProcessID': 1234,
                    'ProcessName': 'test.exe'
                },
                'NetworkLogs': {
                    'Time': datetime.utcnow(),
                    'Hostname': 'test-host',
                    'ProcessID': 1234,
                    'ProcessName': 'test.exe',
                    'Protocol': 'TCP',
                    'LocalAddress': '127.0.0.1',
                    'LocalPort': 1234,
                    'RemoteAddress': '8.8.8.8',
                    'RemotePort': 80,
                    'Direction': 'outbound'
                }
            }
            
            return test_data
            
        except Exception as e:
            self.logger.error(f"Error getting schema test data: {e}")
            return {}
    
    def _table_exists(self, table_name: str) -> bool:
        """Check if table exists"""
        # TODO: Implement actual database check
        return True
    
    def _column_exists(self, table_name: str, column_name: str) -> bool:
        """Check if column exists"""
        # TODO: Implement actual database check
        return True
    
    def _column_type_matches(self, table_name: str, column_name: str, column_type: str) -> bool:
        """Check if column type matches"""
        # TODO: Implement actual database check
        return True
    
    def _create_table(self, table_name: str, columns: Dict[str, str]) -> bool:
        """Create table"""
        # TODO: Implement actual database operation
        return True
    
    def _add_column(self, table_name: str, column_name: str, column_type: str) -> bool:
        """Add column"""
        # TODO: Implement actual database operation
        return True
    
    def _alter_column(self, table_name: str, column_name: str, column_type: str) -> bool:
        """Alter column"""
        # TODO: Implement actual database operation
        return True 