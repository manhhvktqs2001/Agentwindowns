"""
EDR Windows Agent - Enhanced Log Data Sender (COMPLETELY FIXED)
Fixed all threading, shutdown, and blocking issues
"""

import json
import time
import logging
import threading
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from queue import Queue, Empty, Full
import requests
from pathlib import Path
import gzip
import pickle

logger = logging.getLogger(__name__)

class LogSender:
    """Enhanced log sender with proper thread management and fast shutdown"""
    
    def __init__(self, config, connection):
        self.config = config
        self.connection = connection
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.send_interval = config.get('monitoring', 'send_interval', 30)
        self.batch_size = config.get('monitoring', 'batch_size', 50)
        self.offline_cache_size = config.get('agent', 'offline_cache_size', 1000)
        self.realtime_send = config.get('monitoring', 'realtime_send', True)
        self.compression_enabled = config.get('performance', 'compress_logs', True)
        
        # State management - FIXED
        self.running = False
        self.paused = False
        self.shutdown_requested = False
        
        # Threading with proper shutdown handling
        self.send_thread = None
        self.retry_thread = None
        self.cache_thread = None
        self.thread_lock = threading.Lock()
        
        # FIXED: Add shutdown events for clean thread termination
        self.shutdown_event = threading.Event()
        self.all_threads_stopped = threading.Event()
        
        # Data queues with different priorities
        self.high_priority_queue = Queue(maxsize=200)    # Alerts, critical events
        self.normal_priority_queue = Queue(maxsize=500)  # Regular monitoring data
        self.low_priority_queue = Queue(maxsize=300)     # Performance metrics, stats
        
        # Retry and offline storage
        self.retry_queue = Queue(maxsize=200)
        self.failed_sends = []
        self.max_retry_attempts = 3
        self.retry_delay = [5, 15, 60]  # Progressive retry delays
        
        # Offline cache management
        self.cache_dir = Path(config.get('agent', 'cache_directory', 'data/cache'))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / 'offline_logs.json'
        self.backup_cache_file = self.cache_dir / 'offline_logs_backup.json'
        
        # Statistics
        self.stats = {
            'total_sent': 0,
            'total_failed': 0,
            'total_cached': 0,
            'total_bytes_sent': 0,
            'last_send_time': None,
            'send_rate': 0.0,
            'cache_hits': 0,
            'compression_ratio': 0.0,
            'retry_success_rate': 0.0,
            'queue_high_water_mark': 0
        }
        
        # Rate limiting and flow control
        self.rate_limiter = {
            'max_sends_per_minute': 60,
            'current_minute': int(time.time() / 60),
            'sends_this_minute': 0
        }
        
        # Load existing cache
        self._load_offline_cache()
        
        self.logger.info("✅ Enhanced log sender initialized")
    
    def start(self):
        """Start the log sender with all worker threads"""
        try:
            if self.running:
                self.logger.warning("⚠️ Log sender already running")
                return
            
            self.running = True
            self.paused = False
            self.shutdown_requested = False
            self.shutdown_event.clear()
            self.all_threads_stopped.clear()
            
            # Start primary send thread
            self.send_thread = threading.Thread(
                target=self._send_worker,
                name="LogSender-Main",
                daemon=True
            )
            self.send_thread.start()
            
            # Start retry thread
            self.retry_thread = threading.Thread(
                target=self._retry_worker,
                name="LogSender-Retry",
                daemon=True
            )
            self.retry_thread.start()
            
            # Start cache management thread
            self.cache_thread = threading.Thread(
                target=self._cache_worker,
                name="LogSender-Cache",
                daemon=True
            )
            self.cache_thread.start()
            
            self.logger.info("✅ Log sender started with all worker threads")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to start log sender: {e}")
            self.running = False
    
    def stop(self):
        """Stop the log sender gracefully - COMPLETELY FIXED"""
        try:
            self.logger.info("🛑 Stopping log sender...")
            
            # Set shutdown flags immediately
            self.shutdown_requested = True
            self.running = False
            self.shutdown_event.set()
            
            # Put stop signals in all queues to wake up waiting threads
            stop_signal = {"_stop_signal": True, "_timestamp": time.time()}
            
            try:
                # Wake up all worker threads with stop signals
                for _ in range(3):  # Multiple signals to ensure all threads get one
                    try:
                        self.high_priority_queue.put_nowait(stop_signal)
                        self.normal_priority_queue.put_nowait(stop_signal)
                        self.low_priority_queue.put_nowait(stop_signal)
                        self.retry_queue.put_nowait({"data": stop_signal, "attempt": 999})
                    except Full:
                        pass  # Queue full is ok, threads will see shutdown_event
            except Exception as e:
                self.logger.debug(f"Error sending stop signals: {e}")
            
            # Quick save of critical data before thread shutdown
            try:
                self._emergency_save_queues()
            except Exception as e:
                self.logger.debug(f"Emergency save error: {e}")
            
            # Wait for threads to finish with very short timeouts
            threads_to_stop = [
                ('send_thread', self.send_thread),
                ('retry_thread', self.retry_thread), 
                ('cache_thread', self.cache_thread)
            ]
            
            for thread_name, thread in threads_to_stop:
                if thread and thread.is_alive():
                    thread.join(timeout=1.0)  # 1 second max per thread
                    if thread.is_alive():
                        self.logger.debug(f"Thread {thread_name} did not stop gracefully")
            
            # Mark all threads as stopped
            self.all_threads_stopped.set()
            
            self.logger.info("✅ Log sender stopped")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping log sender: {e}")
            self.all_threads_stopped.set()
    
    def _emergency_save_queues(self):
        """Emergency save queue contents - FAST VERSION"""
        try:
            # Quick save without complex processing
            emergency_data = []
            max_items = 50  # Reduced limit to prevent hanging
            
            # Collect data from all queues quickly
            queues_to_save = [
                self.high_priority_queue,
                self.normal_priority_queue,
                self.low_priority_queue
            ]
            
            for queue in queues_to_save:
                count = 0
                while not queue.empty() and count < max_items:
                    try:
                        item = queue.get_nowait()
                        # Skip stop signals and None
                        if item is not None and isinstance(item, dict) and ("_stop_signal" not in item):
                            emergency_data.append(item)
                        count += 1
                    except Empty:
                        break
            
            # Handle retry queue
            count = 0
            while not self.retry_queue.empty() and count < max_items:
                try:
                    retry_item = self.retry_queue.get_nowait()
                    if retry_item is not None and isinstance(retry_item, dict) and "data" in retry_item:
                        data = retry_item["data"]
                        if data is not None and isinstance(data, dict) and ("_stop_signal" not in data):
                            emergency_data.append(data)
                    count += 1
                except Empty:
                    break
            
            # Quick save to cache file
            if emergency_data:
                try:
                    cache_file = self.cache_dir / "emergency_cache.json"
                    with open(cache_file, 'w', encoding='utf-8') as f:
                        json.dump(emergency_data[:50], f)  # Limit size further
                    
                    self.logger.info(f"💾 Emergency saved {len(emergency_data)} items")
                except Exception as e:
                    self.logger.debug(f"Emergency save file error: {e}")
                        
        except Exception as e:
            self.logger.debug(f"Emergency save error: {e}")
    
    def send_logs(self, log_data: Dict[str, Any], priority: str = 'normal') -> bool:
        """Send log data with specified priority"""
        try:
            if not self.running or self.shutdown_requested:
                print("[Agent] Log sender not running, caching data")
                self._cache_log_data(log_data)
                return False
            if self.paused:
                print("[Agent] Log sender paused, queuing data")
            enriched_data = self._enrich_log_data(log_data)
            if priority == 'high' or priority == 'critical':
                target_queue = self.high_priority_queue
            elif priority == 'low':
                target_queue = self.low_priority_queue
            else:
                target_queue = self.normal_priority_queue
            try:
                if priority == 'high':
                    target_queue.put_nowait(enriched_data)
                else:
                    target_queue.put(enriched_data, timeout=0.5)
                print(f"[Agent] Log queued successfully. Queue size: {target_queue.qsize()}")
                return True
            except Full:
                self._cache_log_data(enriched_data)
                print(f"[Agent] {priority} priority queue full, data cached")
                return False
        except Exception as e:
            print(f"[Agent] Error sending logs: {e}")
            self._cache_log_data(log_data)
            return False
    
    def send_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send alert data with highest priority"""
        return self.send_logs(alert_data, priority='high')
    
    def send_metrics(self, metrics_data: Dict[str, Any]) -> bool:
        """Send performance metrics with low priority"""
        return self.send_logs(metrics_data, priority='low')
    
    def _send_worker(self):
        """Main worker thread for sending data - COMPLETELY FIXED"""
        self.logger.info("🔄 Log sender main worker started")
        
        while not self.shutdown_requested:
            try:
                # Check shutdown event with timeout
                if self.shutdown_event.wait(timeout=0.1):
                    break
                
                if self.paused:
                    time.sleep(0.5)
                    continue
                
                # Check rate limiting
                if not self._check_rate_limit():
                    time.sleep(0.5)
                    continue
                
                # Process queues in priority order
                data_to_send = []
                
                # High priority queue first
                while len(data_to_send) < self.batch_size and not self.high_priority_queue.empty():
                    try:
                        data = self.high_priority_queue.get_nowait()
                        # Check for stop signal
                        if isinstance(data, dict) and "_stop_signal" in data:
                            self.logger.debug("Received stop signal in send worker")
                            return
                        data_to_send.append(data)
                    except Empty:
                        break
                
                # Normal priority queue
                while len(data_to_send) < self.batch_size and not self.normal_priority_queue.empty():
                    try:
                        data = self.normal_priority_queue.get_nowait()
                        # Check for stop signal
                        if isinstance(data, dict) and "_stop_signal" in data:
                            self.logger.debug("Received stop signal in send worker")
                            return
                        data_to_send.append(data)
                    except Empty:
                        break
                
                # Low priority queue (only if batch not full)
                while len(data_to_send) < self.batch_size // 2 and not self.low_priority_queue.empty():
                    try:
                        data = self.low_priority_queue.get_nowait()
                        # Check for stop signal
                        if isinstance(data, dict) and "_stop_signal" in data:
                            self.logger.debug("Received stop signal in send worker")
                            return
                        data_to_send.append(data)
                    except Empty:
                        break
                
                # Send data if we have any
                if data_to_send:
                    success = self._send_batch(data_to_send)
                    if not success:
                        # Add failed data to retry queue
                        for data in data_to_send:
                            self._add_to_retry_queue(data)
                else:
                    # No data to send, check for cached data
                    cached_data = self._load_cached_data_batch()
                    if cached_data:
                        success = self._send_batch(cached_data)
                        if success:
                            self.stats['cache_hits'] += len(cached_data)
                        else:
                            # Put failed cached data back
                            for data in cached_data:
                                self._add_to_retry_queue(data)
                
                # Sleep based on send interval (with shutdown check)
                sleep_time = min(self.send_interval, 5)
                for _ in range(int(sleep_time * 10)):  # Check every 0.1 seconds
                    if self.shutdown_event.wait(timeout=0.1):
                        return
                
            except Exception as e:
                self.logger.error(f"❌ Error in send worker: {e}")
                if self.shutdown_event.wait(timeout=1):
                    break
        
        self.logger.info("🛑 Log sender main worker stopped")
    
    def _retry_worker(self):
        """Worker thread for retrying failed sends - COMPLETELY FIXED"""
        self.logger.info("🔄 Log sender retry worker started")
        
        while not self.shutdown_requested:
            try:
                # Get data from retry queue with timeout
                try:
                    retry_item = self.retry_queue.get(timeout=1)
                except Empty:
                    continue
                
                # Check for stop signal
                if isinstance(retry_item, dict) and "data" in retry_item:
                    data = retry_item["data"]
                    if isinstance(data, dict) and "_stop_signal" in data:
                        self.logger.debug("Received stop signal in retry worker")
                        return
                
                attempt = retry_item.get('attempt', 0)
                
                if attempt >= self.max_retry_attempts:
                    # Max retries reached, cache the data
                    self._cache_log_data(retry_item['data'])
                    self.logger.warning(f"⚠️ Max retries reached, caching data")
                    continue
                
                # Wait before retry (with shutdown check)
                delay = min(self.retry_delay[min(attempt, len(self.retry_delay) - 1)], 10)
                if self.shutdown_event.wait(timeout=delay):
                    return
                
                # Check if connection is available
                if not self.connection or not self.connection.is_connected():
                    # Re-queue for later retry
                    retry_item['attempt'] += 1
                    try:
                        self.retry_queue.put_nowait(retry_item)
                    except Full:
                        self._cache_log_data(retry_item['data'])
                    continue
                
                # Try to send
                success = self._send_single_item(retry_item['data'])
                if success:
                    self.logger.debug(f"✅ Retry successful after {attempt + 1} attempts")
                    self.stats['retry_success_rate'] = (
                        self.stats.get('retry_successes', 0) + 1
                    ) / max(self.stats.get('retry_attempts', 0) + 1, 1)
                else:
                    # Re-queue for another retry
                    retry_item['attempt'] += 1
                    try:
                        self.retry_queue.put_nowait(retry_item)
                    except Full:
                        self._cache_log_data(retry_item['data'])
                
                self.stats['retry_attempts'] = self.stats.get('retry_attempts', 0) + 1
                if success:
                    self.stats['retry_successes'] = self.stats.get('retry_successes', 0) + 1
                    
            except Exception as e:
                self.logger.error(f"❌ Error in retry worker: {e}")
                if self.shutdown_event.wait(timeout=1):
                    break
        
        self.logger.info("🛑 Log sender retry worker stopped")
    
    def _cache_worker(self):
        """Worker thread for managing offline cache - COMPLETELY FIXED"""
        self.logger.info("🔄 Log sender cache worker started")
        
        while not self.shutdown_requested:
            try:
                # Check for shutdown every second during the wait
                for _ in range(60):  # 60 seconds total
                    if self.shutdown_event.wait(timeout=1):
                        self.logger.debug("Cache worker received shutdown signal")
                        return
                
                # Periodic cache maintenance (only if still running)
                if not self.shutdown_requested:
                    self._cleanup_old_cache_files()
                    self._rotate_cache_files()
                    self._save_statistics()
                
            except Exception as e:
                self.logger.error(f"❌ Error in cache worker: {e}")
                if self.shutdown_event.wait(timeout=5):
                    break
        
        self.logger.info("🛑 Log sender cache worker stopped")
    
    def _send_batch(self, data_batch: List[Dict[str, Any]]) -> bool:
        """Send a batch of data to server"""
        try:
            if not data_batch:
                return True

            if not self.connection or not self.connection.is_connected():
                print("[Agent] No server connection, cannot send batch")
                return False

            batch_data = {
                'batch_id': f"{int(time.time())}_{len(data_batch)}",
                'timestamp': datetime.utcnow().isoformat(),
                'agent_id': self.config.AGENT_ID,
                'hostname': self.config.get_system_info().get('hostname'),
                'count': len(data_batch),
                'data': data_batch
            }

            is_compressed = False
            if self.compression_enabled and len(data_batch) > 10:
                try:
                    compressed_data = self._compress_data(batch_data)
                    if compressed_data:
                        batch_data = compressed_data
                        is_compressed = True
                except Exception as e:
                    print(f"[Agent] Compression failed, sending uncompressed: {e}")

            data_size = len(json.dumps(batch_data).encode('utf-8'))
            if is_compressed:
                batch_data['is_compressed'] = True

            # Determine log type from the first item in batch
            first_item = data_batch[0]
            log_type = first_item.get('log_type', 'process')  # Default to process if not specified

            # Send via Socket.IO with correct event name
            if log_type == 'process':
                success = self.connection.socketio.emit('process_logs', batch_data)
            elif log_type == 'file':
                success = self.connection.socketio.emit('file_logs', batch_data)
            elif log_type == 'network':
                success = self.connection.socketio.emit('network_logs', batch_data)
            else:
                print(f"[Agent] Unknown log type: {log_type}")
                return False

            if success:
                print(f"[Agent] Sent batch of {len(data_batch)} {log_type} items ({data_size} bytes)")
                return True
            else:
                print(f"[Agent] Failed to send batch of {len(data_batch)} {log_type} items")
                return False

        except Exception as e:
            print(f"[Agent] Error sending batch: {e}")
            return False
    
    def _send_single_item(self, data: Dict[str, Any]) -> bool:
        """Send a single data item"""
        try:
            if not self.connection or not self.connection.is_connected():
                return False
            
            success = self.connection.send_logs(data, priority=True)
            
            if success:
                self.stats['total_sent'] += 1
                self.stats['last_send_time'] = time.time()
                return True
            else:
                self.stats['total_failed'] += 1
                return False
            
        except Exception as e:
            self.logger.error(f"❌ Error sending single item: {e}")
            self.stats['total_failed'] += 1
            return False
    
    def _enrich_log_data(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich log data with additional metadata"""
        try:
            system_info = self.config.get_system_info()
            
            enriched = log_data.copy()
            enriched.update({
                'agent_id': self.config.AGENT_ID,
                'hostname': system_info.get('hostname'),
                'sender_timestamp': datetime.utcnow().isoformat(),
                'agent_version': self.config.AGENT_VERSION,
                'os_type': system_info.get('os_type'),
                'data_version': '2.0'
            })
            
            # Add original timestamp if not present
            if 'timestamp' not in log_data:
                enriched['original_timestamp'] = enriched['sender_timestamp']
            
            return enriched
            
        except Exception as e:
            self.logger.error(f"❌ Error enriching log data: {e}")
            return log_data
    
    def _compress_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Compress data if beneficial"""
        try:
            # Convert to JSON string
            json_str = json.dumps(data)
            original_size = len(json_str.encode('utf-8'))
            
            # Compress using gzip
            compressed = gzip.compress(json_str.encode('utf-8'))
            compressed_size = len(compressed)
            
            # Only use compression if it saves significant space
            if compressed_size < original_size * 0.8:  # 20% reduction minimum
                self.stats['compression_ratio'] = compressed_size / original_size
                return {
                    'compressed': True,
                    'original_size': original_size,
                    'compressed_size': compressed_size,
                    'data': compressed.hex()  # Convert to hex for JSON serialization
                }
            else:
                return data
                
        except Exception as e:
            self.logger.error(f"❌ Error compressing data: {e}")
            return data
    
    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits"""
        try:
            current_minute = int(time.time() / 60)
            
            if current_minute != self.rate_limiter['current_minute']:
                # New minute, reset counter
                self.rate_limiter['current_minute'] = current_minute
                self.rate_limiter['sends_this_minute'] = 0
            
            if self.rate_limiter['sends_this_minute'] >= self.rate_limiter['max_sends_per_minute']:
                return False
            
            self.rate_limiter['sends_this_minute'] += 1
            return True
            
        except Exception:
            return True  # Allow send on error
    
    def _update_send_rate(self):
        """Update send rate statistics"""
        try:
            current_time = time.time()
            if hasattr(self, '_last_rate_update'):
                time_diff = current_time - self._last_rate_update
                if time_diff > 0:
                    sends_diff = self.stats['total_sent'] - getattr(self, '_last_total_sent', 0)
                    self.stats['send_rate'] = sends_diff / time_diff
            
            self._last_rate_update = current_time
            self._last_total_sent = self.stats['total_sent']
                
        except Exception as e:
            self.logger.error(f"❌ Error updating send rate: {e}")
    
    def _add_to_retry_queue(self, data: Dict[str, Any], attempt: int = 0):
        """Add data to retry queue"""
        try:
            retry_item = {
                'data': data,
                'attempt': attempt,
                'queued_at': time.time()
            }
            
            try:
                self.retry_queue.put_nowait(retry_item)
            except Full:
                # Retry queue full, cache the data
                self._cache_log_data(data)
                self.logger.warning("⚠️ Retry queue full, caching data")
                
        except Exception as e:
            self.logger.error(f"❌ Error adding to retry queue: {e}")
    
    def _cache_log_data(self, data: Dict[str, Any]):
        """Cache log data for offline storage"""
        try:
            with self.thread_lock:
                # Load existing cache
                cached_data = self._load_offline_cache()
                
                # Add new data
                cached_data.append({
                    'data': data,
                    'cached_at': time.time(),
                    'attempts': 0
                })
                
                # Limit cache size
                if len(cached_data) > self.offline_cache_size:
                    # Remove oldest entries
                    cached_data = cached_data[-self.offline_cache_size:]
                
                # Save back to cache
                self._save_offline_cache(cached_data)
                
                self.stats['total_cached'] += 1
                    
        except Exception as e:
            self.logger.error(f"❌ Error caching log data: {e}")
    
    def _load_offline_cache(self) -> List[Dict[str, Any]]:
        """Load data from offline cache"""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return data
            return []
        except Exception as e:
            self.logger.error(f"❌ Error loading offline cache: {e}")
            # Try backup file
            try:
                if self.backup_cache_file.exists():
                    with open(self.backup_cache_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            return data
            except Exception:
                pass
            return []
    
    def _save_offline_cache(self, data: List[Dict[str, Any]]):
        """Save data to offline cache with backup"""
        try:
            # Create backup of existing cache
            if self.cache_file.exists():
                self.cache_file.replace(self.backup_cache_file)
            
            # Save new cache
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
                    
        except Exception as e:
            self.logger.error(f"❌ Error saving offline cache: {e}")
    
    def _load_cached_data_batch(self, batch_size: int = None) -> List[Dict[str, Any]]:
        """Load a batch of data from cache"""
        try:
            if batch_size is None:
                batch_size = self.batch_size
            
            with self.thread_lock:
                cached_data = self._load_offline_cache()
                if not cached_data:
                    return []
                
                # Get batch of oldest data
                batch = []
                remaining = []
                
                for i, item in enumerate(cached_data):
                    if len(batch) < batch_size:
                        # Handle both old and new cache format
                        if isinstance(item, dict) and 'data' in item:
                            batch.append(item['data'])
                        else:
                            batch.append(item)
                    else:
                        remaining.append(item)
                
                # Save remaining data back to cache
                if remaining != cached_data:  # Only save if changed
                    self._save_offline_cache(remaining)
                
                return batch
                        
        except Exception as e:
            self.logger.error(f"❌ Error loading cached data batch: {e}")
            return []
    
    def _cleanup_old_cache_files(self):
        """Clean up old cache files"""
        try:
            # Remove cache files older than 7 days
            cutoff_time = time.time() - (7 * 24 * 3600)
            
            for file_path in self.cache_dir.glob("*.json"):
                try:
                    if file_path.stat().st_mtime < cutoff_time:
                        file_path.unlink()
                        self.logger.debug(f"🗑️ Removed old cache file: {file_path}")
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"❌ Error cleaning up cache files: {e}")
    
    def _rotate_cache_files(self):
        """Rotate cache files if they get too large"""
        try:
            if self.cache_file.exists():
                file_size = self.cache_file.stat().st_size
                max_size = 50 * 1024 * 1024  # 50MB
                
                if file_size > max_size:
                    # Rotate to timestamped file
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    rotated_file = self.cache_dir / f"offline_logs_{timestamp}.json"
                    self.cache_file.replace(rotated_file)
                    
                    self.logger.info(f"🔄 Rotated cache file: {rotated_file}")
                    
        except Exception as e:
            self.logger.error(f"❌ Error rotating cache files: {e}")
    
    def _save_statistics(self):
        """Save statistics to file"""
        try:
            stats_file = self.cache_dir / "log_sender_stats.json"
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(self.stats, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"❌ Error saving statistics: {e}")
    
    def pause(self):
        """Pause log sending (queue data but don't send)"""
        self.paused = True
        self.logger.info("⏸️ Log sender paused")
    
    def resume(self):
        """Resume log sending"""
        self.paused = False
        self.logger.info("▶️ Log sender resumed")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive sender statistics"""
        try:
            # Update send rate
            self._update_send_rate()
            
            # Calculate success rate
            total_attempts = self.stats['total_sent'] + self.stats['total_failed']
            success_rate = (self.stats['total_sent'] / max(total_attempts, 1)) * 100
            
            return {
                'running': self.running,
                'paused': self.paused,
                'shutdown_requested': self.shutdown_requested,
                'statistics': {
                    **self.stats,
                    'success_rate': success_rate,
                    'total_attempts': total_attempts
                },
                'queues': {
                    'high_priority': self.high_priority_queue.qsize(),
                    'normal_priority': self.normal_priority_queue.qsize(),
                    'low_priority': self.low_priority_queue.qsize(),
                    'retry': self.retry_queue.qsize(),
                    'cached_items': len(self._load_offline_cache())
                },
                'configuration': {
                    'send_interval': self.send_interval,
                'batch_size': self.batch_size,
                    'offline_cache_size': self.offline_cache_size,
                    'realtime_send': self.realtime_send,
                    'compression_enabled': self.compression_enabled,
                    'max_retry_attempts': self.max_retry_attempts
                },
                'thread_status': {
                    'send_thread_alive': self.send_thread.is_alive() if self.send_thread else False,
                    'retry_thread_alive': self.retry_thread.is_alive() if self.retry_thread else False,
                    'cache_thread_alive': self.cache_thread.is_alive() if self.cache_thread else False,
                    'all_threads_stopped': self.all_threads_stopped.is_set()
            }
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error getting stats: {e}")
            return {'error': str(e)}
    
    def emergency_flush(self):
        """Flush all queues to disk immediately (for emergency shutdown)"""
        try:
            self._emergency_save_queues()
            self.logger.info("✅ Emergency flush completed.")
            return {'success': True}
        except Exception as e:
            self.logger.error(f"❌ Error in emergency flush: {e}")
            return {'success': False, 'error': str(e)}