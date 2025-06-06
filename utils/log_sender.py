"""
EDR Windows Agent - Log Data Sender
"""

import json
import time
import logging
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime
from queue import Queue, Empty
import os

class LogSender:
    """Handles sending log data to EDR Server"""
    
    def __init__(self, config, connection):
        self.config = config
        self.connection = connection
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.batch_size = config.get('monitoring', 'batch_size', 50)
        self.send_interval = config.get('monitoring', 'send_interval', 30)
        self.offline_cache_size = config.get('agent', 'offline_cache_size', 1000)
        
        # Data queues
        self.log_queue = Queue(maxsize=self.offline_cache_size)
        self.failed_logs = Queue(maxsize=500)  # For retry
        
        # Offline storage
        self.cache_dir = os.path.join(os.getcwd(), 'data', 'cache')
        os.makedirs(self.cache_dir, exist_ok=True)
        self.cache_file = os.path.join(self.cache_dir, 'offline_logs.json')
        
        # Threading
        self.running = False
        self.sender_thread = None
        self.retry_thread = None
        
        # Statistics
        self.stats = {
            'logs_sent': 0,
            'logs_failed': 0,
            'logs_cached': 0,
            'last_send_time': None,
            'connection_errors': 0
        }
        
        # Load cached logs on startup
        self._load_cached_logs()
        
        self.logger.info("✅ Log sender initialized")
    
    def start(self):
        """Start log sender"""
        try:
            if self.running:
                return
            
            self.running = True
            
            # Start sender thread
            self.sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
            self.sender_thread.start()
            
            # Start retry thread
            self.retry_thread = threading.Thread(target=self._retry_loop, daemon=True)
            self.retry_thread.start()
            
            self.logger.info("✅ Log sender started")
            
        except Exception as e:
            self.logger.error(f"Failed to start log sender: {e}")
            raise
    
    def stop(self):
        """Stop log sender"""
        try:
            self.running = False
            
            # Save pending logs to cache
            self._save_logs_to_cache()
            
            # Wait for threads to finish
            if self.sender_thread and self.sender_thread.is_alive():
                self.sender_thread.join(timeout=5)
            
            if self.retry_thread and self.retry_thread.is_alive():
                self.retry_thread.join(timeout=5)
            
            self.logger.info("🛑 Log sender stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping log sender: {e}")
    
    def send_logs(self, log_data: Dict[str, Any]) -> bool:
        """Send log data to server"""
        try:
            # Add metadata
            enriched_data = self._enrich_log_data(log_data)
            
            # Try to send immediately if connected
            if self.connection and self.connection.is_connected():
                success = self._send_to_server(enriched_data)
                if success:
                    self.stats['logs_sent'] += 1
                    self.stats['last_send_time'] = datetime.utcnow().isoformat()
                    return True
                else:
                    self.stats['logs_failed'] += 1
            
            # Queue for later sending if not connected or failed
            try:
                self.log_queue.put_nowait(enriched_data)
                self.stats['logs_cached'] += 1
                return True
            except:
                # Queue is full, save to disk
                self._save_log_to_cache(enriched_data)
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending logs: {e}")
            return False
    
    def _sender_loop(self):
        """Main sender loop"""
        while self.running:
            try:
                # Collect logs from queue
                logs_to_send = []
                
                # Get logs from queue (non-blocking)
                for _ in range(self.batch_size):
                    try:
                        log_data = self.log_queue.get_nowait()
                        logs_to_send.append(log_data)
                    except Empty:
                        break
                
                # Send batch if we have logs and are connected
                if logs_to_send and self.connection and self.connection.is_connected():
                    success = self._send_batch_to_server(logs_to_send)
                    
                    if success:
                        self.stats['logs_sent'] += len(logs_to_send)
                        self.stats['last_send_time'] = datetime.utcnow().isoformat()
                    else:
                        # Put failed logs back for retry
                        for log_data in logs_to_send:
                            try:
                                self.failed_logs.put_nowait(log_data)
                            except:
                                self._save_log_to_cache(log_data)
                        
                        self.stats['logs_failed'] += len(logs_to_send)
                        self.stats['connection_errors'] += 1
                
                time.sleep(self.send_interval)
                
            except Exception as e:
                self.logger.error(f"Error in sender loop: {e}")
                time.sleep(5)
    
    def _retry_loop(self):
        """Retry failed logs"""
        while self.running:
            try:
                # Wait a bit before retrying
                time.sleep(60)  # Retry every minute
                
                if not (self.connection and self.connection.is_connected()):
                    continue
                
                # Retry failed logs
                failed_logs = []
                while not self.failed_logs.empty():
                    try:
                        log_data = self.failed_logs.get_nowait()
                        failed_logs.append(log_data)
                    except Empty:
                        break
                
                if failed_logs:
                    success = self._send_batch_to_server(failed_logs)
                    
                    if success:
                        self.stats['logs_sent'] += len(failed_logs)
                        self.logger.info(f"✅ Retried {len(failed_logs)} failed logs")
                    else:
                        # Put back for another retry
                        for log_data in failed_logs:
                            try:
                                self.failed_logs.put_nowait(log_data)
                            except:
                                self._save_log_to_cache(log_data)
                
                # Try to send cached logs from disk
                self._send_cached_logs()
                
            except Exception as e:
                self.logger.error(f"Error in retry loop: {e}")
                time.sleep(10)
    
    def _send_to_server(self, log_data: Dict[str, Any]) -> bool:
        """Send single log entry to server"""
        try:
            if self.connection:
                # Try Socket.IO first
                success = self.connection.send_logs(log_data)
                
                if not success:
                    # Fallback to HTTP
                    success = self.connection.send_http_logs(log_data)
                
                return success
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error sending to server: {e}")
            return False
    
    def _send_batch_to_server(self, logs: List[Dict[str, Any]]) -> bool:
        """Send batch of logs to server"""
        try:
            batch_data = {
                'batch': True,
                'logs': logs,
                'count': len(logs),
                'hostname': self.config.get_system_info().get('hostname'),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return self._send_to_server(batch_data)
            
        except Exception as e:
            self.logger.error(f"Error sending batch to server: {e}")
            return False
    
    def _enrich_log_data(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add metadata to log data"""
        try:
            enriched = log_data.copy()
            
            # Add system information
            system_info = self.config.get_system_info()
            enriched.update({
                'hostname': system_info.get('hostname'),
                'agent_version': self.config.get('agent', 'version'),
                'os_type': system_info.get('os_type'),
                'timestamp': datetime.utcnow().isoformat(),
                'timezone': time.tzname[0]
            })
            
            # Add process information for events that have it
            for event_type in ['processes', 'files', 'networks']:
                if event_type in enriched and isinstance(enriched[event_type], list):
                    for event in enriched[event_type]:
                        if 'timestamp' not in event:
                            event['timestamp'] = datetime.utcnow().isoformat()
                        event['hostname'] = system_info.get('hostname')
            
            return enriched
            
        except Exception as e:
            self.logger.error(f"Error enriching log data: {e}")
            return log_data
    
    def _save_logs_to_cache(self):
        """Save all pending logs to cache file"""
        try:
            pending_logs = []
            
            # Get logs from queue
            while not self.log_queue.empty():
                try:
                    log_data = self.log_queue.get_nowait()
                    pending_logs.append(log_data)
                except Empty:
                    break
            
            # Get failed logs
            while not self.failed_logs.empty():
                try:
                    log_data = self.failed_logs.get_nowait()
                    pending_logs.append(log_data)
                except Empty:
                    break
            
            if pending_logs:
                # Load existing cached logs
                existing_logs = self._load_logs_from_cache()
                
                # Combine and limit size
                all_logs = existing_logs + pending_logs
                if len(all_logs) > self.offline_cache_size:
                    all_logs = all_logs[-self.offline_cache_size:]
                
                # Save to file
                with open(self.cache_file, 'w', encoding='utf-8') as f:
                    json.dump(all_logs, f, indent=2)
                
                self.logger.info(f"💾 Saved {len(pending_logs)} logs to cache")
                
        except Exception as e:
            self.logger.error(f"Error saving logs to cache: {e}")
    
    def _save_log_to_cache(self, log_data: Dict[str, Any]):
        """Save single log to cache file"""
        try:
            # Load existing logs
            cached_logs = self._load_logs_from_cache()
            
            # Add new log
            cached_logs.append(log_data)
            
            # Limit size
            if len(cached_logs) > self.offline_cache_size:
                cached_logs = cached_logs[-self.offline_cache_size:]
            
            # Save to file
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(cached_logs, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error saving log to cache: {e}")
    
    def _load_cached_logs(self):
        """Load cached logs on startup"""
        try:
            cached_logs = self._load_logs_from_cache()
            
            if cached_logs:
                # Put cached logs into queue for sending
                for log_data in cached_logs:
                    try:
                        self.log_queue.put_nowait(log_data)
                    except:
                        break  # Queue is full
                
                self.logger.info(f"📂 Loaded {len(cached_logs)} cached logs")
                
                # Clear cache file
                try:
                    os.remove(self.cache_file)
                except:
                    pass
                    
        except Exception as e:
            self.logger.error(f"Error loading cached logs: {e}")
    
    def _load_logs_from_cache(self) -> List[Dict[str, Any]]:
        """Load logs from cache file"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return []
            
        except Exception as e:
            self.logger.error(f"Error loading logs from cache: {e}")
            return []
    
    def _send_cached_logs(self):
        """Send logs from cache file"""
        try:
            if not os.path.exists(self.cache_file):
                return
            
            cached_logs = self._load_logs_from_cache()
            
            if cached_logs:
                # Send in batches
                for i in range(0, len(cached_logs), self.batch_size):
                    batch = cached_logs[i:i + self.batch_size]
                    success = self._send_batch_to_server(batch)
                    
                    if success:
                        self.stats['logs_sent'] += len(batch)
                    else:
                        # Stop trying if we can't send
                        break
                
                # If all sent successfully, remove cache file
                if success:
                    try:
                        os.remove(self.cache_file)
                        self.logger.info(f"✅ Sent {len(cached_logs)} cached logs")
                    except:
                        pass
                        
        except Exception as e:
            self.logger.error(f"Error sending cached logs: {e}")
    
    def get_queue_size(self) -> int:
        """Get current queue size"""
        return self.log_queue.qsize()
    
    def get_failed_queue_size(self) -> int:
        """Get failed logs queue size"""
        return self.failed_logs.qsize()
    
    def get_cached_logs_count(self) -> int:
        """Get number of cached logs on disk"""
        try:
            cached_logs = self._load_logs_from_cache()
            return len(cached_logs)
        except:
            return 0
    
    def clear_cache(self) -> bool:
        """Clear all cached logs"""
        try:
            # Clear queues
            while not self.log_queue.empty():
                try:
                    self.log_queue.get_nowait()
                except Empty:
                    break
            
            while not self.failed_logs.empty():
                try:
                    self.failed_logs.get_nowait()
                except Empty:
                    break
            
            # Remove cache file
            if os.path.exists(self.cache_file):
                os.remove(self.cache_file)
            
            # Reset stats
            self.stats['logs_cached'] = 0
            
            self.logger.info("🗑️ Log cache cleared")
            return True
            
        except Exception as e:
            self.logger.error(f"Error clearing cache: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get log sender statistics"""
        try:
            return {
                'running': self.running,
                'queue_size': self.get_queue_size(),
                'failed_queue_size': self.get_failed_queue_size(),
                'cached_logs_count': self.get_cached_logs_count(),
                'batch_size': self.batch_size,
                'send_interval': self.send_interval,
                'stats': self.stats.copy()
            }
        except Exception as e:
            self.logger.error(f"Error getting log sender stats: {e}")
            return {'error': str(e)}