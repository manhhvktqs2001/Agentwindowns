"""
EDR Windows Agent - Network Monitor
"""

import time
import socket
import psutil
import logging
import threading
from datetime import datetime
from typing import Dict, List, Any, Callable, Optional, Set, Tuple
import ipaddress

class NetworkMonitor:
    """Monitors network activities on Windows system"""
    
    def __init__(self, config, event_callback: Callable):
        self.config = config
        self.event_callback = event_callback
        self.logger = logging.getLogger(__name__)
        
        # Monitoring state
        self.running = False
        self.monitor_thread = None
        
        # Configuration
        self.monitor_interval = config.get('monitoring', 'interval', 5)
        self.monitor_connections = config.get('network_monitoring', 'monitor_connections', True)
        self.monitor_dns = config.get('network_monitoring', 'monitor_dns', True)
        
        # Suspicious indicators
        self.suspicious_ports = set(config.get('network_monitoring', 'suspicious_ports', []))
        self.blocked_ips = set(config.get('network_monitoring', 'blocked_ips', []))
        
        # Connection tracking
        self.known_connections = {}  # (laddr, raddr, pid) -> connection_info
        self.connection_stats = {}   # PID -> stats
        
        # Suspicious patterns
        self.c2_indicators = [
            'pastebin.com',
            'raw.githubusercontent.com',
            'bit.ly',
            'tinyurl.com'
        ]
        
        # Private IP ranges
        self.private_ranges = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8')
        ]
        
        self.logger.info("✅ Network monitor initialized")
    
    def start(self):
        """Start network monitoring"""
        try:
            if self.running:
                self.logger.warning("NetworkMonitor.start() called but already running.")
                return False
            self.running = True
            # Initialize known connections
            self._initialize_connections()
            # Start monitoring thread
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            self.logger.info("🔍 Network monitoring started")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start network monitor: {e}")
            return False
    
    def stop(self):
        """Stop network monitoring"""
        try:
            self.running = False
            
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=5)
            
            self.logger.info("🛑 Network monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping network monitor: {e}")
    
    def is_running(self) -> bool:
        """Check if monitor is running"""
        return self.running and (self.monitor_thread and self.monitor_thread.is_alive())
    
    def _initialize_connections(self):
        """Initialize current network connections"""
        try:
            current_connections = {}
            
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED:
                    key = self._get_connection_key(conn)
                    if key:
                        current_connections[key] = {
                            'pid': conn.pid,
                            'local_addr': conn.laddr,
                            'remote_addr': conn.raddr,
                            'status': conn.status,
                            'family': conn.family,
                            'type': conn.type,
                            'first_seen': datetime.utcnow()
                        }
            
            self.known_connections = current_connections
            self.logger.info(f"📊 Initialized with {len(current_connections)} existing connections")
            
        except Exception as e:
            self.logger.error(f"Error initializing connections: {e}")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                if self.monitor_connections:
                    self._check_network_connections()
                
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                self.logger.error(f"Error in network monitor loop: {e}")
                time.sleep(5)
    
    def _check_network_connections(self):
        """Check for new and closed network connections"""
        try:
            current_connections = {}
            
            # Get current connections
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    key = self._get_connection_key(conn)
                    if key:
                        current_connections[key] = {
                            'pid': conn.pid,
                            'local_addr': conn.laddr,
                            'remote_addr': conn.raddr,
                            'status': conn.status,
                            'family': conn.family,
                            'type': conn.type,
                            'process_name': self._get_process_name(conn.pid)
                        }
            
            # Check for new connections
            new_connections = set(current_connections.keys()) - set(self.known_connections.keys())
            for key in new_connections:
                self._handle_new_connection(current_connections[key])
            
            # Check for closed connections
            closed_connections = set(self.known_connections.keys()) - set(current_connections.keys())
            for key in closed_connections:
                self._handle_closed_connection(self.known_connections[key])
            
            # Update known connections
            self.known_connections = current_connections
            
            # Update connection statistics
            self._update_connection_stats()
            
        except Exception as e:
            self.logger.error(f"Error checking network connections: {e}")
    
    def _get_connection_key(self, conn) -> Optional[Tuple]:
        """Generate unique key for connection"""
        try:
            if conn.laddr and conn.raddr:
                return (
                    conn.laddr.ip, conn.laddr.port,
                    conn.raddr.ip, conn.raddr.port,
                    conn.pid
                )
            return None
        except Exception:
            return None
    
    def _handle_new_connection(self, conn_info: Dict[str, Any]):
        """Handle new network connection"""
        try:
            remote_ip = conn_info['remote_addr'].ip
            remote_port = conn_info['remote_addr'].port
            local_port = conn_info['local_addr'].port
            
            # Determine connection direction
            direction = 'outbound' if self._is_outbound_connection(conn_info) else 'inbound'
            
            # Check for suspicious activity
            is_suspicious = self._is_suspicious_connection(conn_info)
            
            event_data = {
                'event_type': 'network_connection',
                'process_id': conn_info['pid'],
                'process_name': conn_info.get('process_name'),
                'protocol': 'TCP' if conn_info['type'] == socket.SOCK_STREAM else 'UDP',
                'local_address': conn_info['local_addr'].ip,
                'local_port': local_port,
                'remote_address': remote_ip,
                'remote_port': remote_port,
                'direction': direction,
                'is_suspicious': is_suspicious,
                'detection_reason': self._get_detection_reason(conn_info) if is_suspicious else None
            }
            
            # Send event to agent
            self.event_callback(event_data)
            
            # Log suspicious connections
            if is_suspicious:
                self.logger.warning(f"🚨 Suspicious connection: {conn_info.get('process_name')} -> {remote_ip}:{remote_port}")
            else:
                self.logger.debug(f"🔗 New connection: {conn_info.get('process_name')} -> {remote_ip}:{remote_port}")
                
        except Exception as e:
            self.logger.error(f"Error handling new connection: {e}")
    
    def _handle_closed_connection(self, conn_info: Dict[str, Any]):
        """Handle closed network connection"""
        try:
            event_data = {
                'event_type': 'network_disconnection',
                'process_id': conn_info['pid'],
                'process_name': conn_info.get('process_name'),
                'remote_address': conn_info['remote_addr'].ip,
                'remote_port': conn_info['remote_addr'].port,
                'duration': (datetime.utcnow() - conn_info.get('first_seen', datetime.utcnow())).total_seconds()
            }
            
            # Send event to agent
            self.event_callback(event_data)
            
            self.logger.debug(f"🔌 Connection closed: {conn_info.get('process_name')} -> {conn_info['remote_addr'].ip}")
            
        except Exception as e:
            self.logger.error(f"Error handling closed connection: {e}")
    
    def _is_outbound_connection(self, conn_info: Dict[str, Any]) -> bool:
        """Determine if connection is outbound"""
        try:
            local_ip = conn_info['local_addr'].ip
            remote_ip = conn_info['remote_addr'].ip
            
            # Check if local IP is private and remote is public
            local_is_private = self._is_private_ip(local_ip)
            remote_is_private = self._is_private_ip(remote_ip)
            
            return local_is_private and not remote_is_private
            
        except Exception:
            return True  # Default to outbound
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP address is private"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return any(ip in network for network in self.private_ranges)
        except Exception:
            return False
    
    def _is_suspicious_connection(self, conn_info: Dict[str, Any]) -> bool:
        """Check if connection is suspicious"""
        try:
            remote_ip = conn_info['remote_addr'].ip
            remote_port = conn_info['remote_addr'].port
            process_name = conn_info.get('process_name', '').lower()
            
            # Check blocked IPs
            if remote_ip in self.blocked_ips:
                return True
            
            # Check suspicious ports
            if remote_port in self.suspicious_ports:
                return True
            
            # Check for connections to known C2 domains (simplified)
            # In practice, you'd resolve IPs to domains
            
            # Check for suspicious process names
            suspicious_processes = [
                'cmd.exe',
                'powershell.exe',
                'wmic.exe',
                'reg.exe',
                'net.exe'
            ]
            
            if process_name in suspicious_processes:
                return True
            
            # Check for non-standard ports for common services
            standard_ports = {80, 443, 53, 25, 110, 143, 993, 995}
            if remote_port not in standard_ports and remote_port < 1024:
                return True
            
            # Check for connections to uncommon high ports
            if remote_port > 8000 and remote_port not in {8080, 8443, 9000}:
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking suspicious connection: {e}")
            return False
    
    def _get_detection_reason(self, conn_info: Dict[str, Any]) -> str:
        """Get reason why connection is considered suspicious"""
        reasons = []
        
        try:
            remote_ip = conn_info['remote_addr'].ip
            remote_port = conn_info['remote_addr'].port
            process_name = conn_info.get('process_name', '').lower()
            
            if remote_ip in self.blocked_ips:
                reasons.append("blocked_ip")
            
            if remote_port in self.suspicious_ports:
                reasons.append("suspicious_port")
            
            suspicious_processes = ['cmd.exe', 'powershell.exe', 'wmic.exe']
            if process_name in suspicious_processes:
                reasons.append("suspicious_process")
            
            if remote_port > 8000:
                reasons.append("high_port")
            
            return ', '.join(reasons)
            
        except Exception:
            return "unknown"
    
    def _get_process_name(self, pid: int) -> Optional[str]:
        """Get process name from PID"""
        try:
            if pid:
                proc = psutil.Process(pid)
                return proc.name()
            return None
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    def _update_connection_stats(self):
        """Update connection statistics per process"""
        try:
            current_stats = {}
            
            for conn_info in self.known_connections.values():
                pid = conn_info['pid']
                if pid:
                    if pid not in current_stats:
                        current_stats[pid] = {
                            'process_name': conn_info.get('process_name'),
                            'connection_count': 0,
                            'unique_destinations': set(),
                            'suspicious_connections': 0
                        }
                    
                    current_stats[pid]['connection_count'] += 1
                    current_stats[pid]['unique_destinations'].add(conn_info['remote_addr'].ip)
                    
                    if self._is_suspicious_connection(conn_info):
                        current_stats[pid]['suspicious_connections'] += 1
            
            # Convert sets to counts for JSON serialization
            for stats in current_stats.values():
                stats['unique_destinations'] = len(stats['unique_destinations'])
            
            self.connection_stats = current_stats
            
        except Exception as e:
            self.logger.error(f"Error updating connection stats: {e}")
    
    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get list of active network connections"""
        try:
            connections = []
            
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    connections.append({
                        'pid': conn.pid,
                        'process_name': self._get_process_name(conn.pid),
                        'local_address': conn.laddr.ip,
                        'local_port': conn.laddr.port,
                        'remote_address': conn.raddr.ip,
                        'remote_port': conn.raddr.port,
                        'status': conn.status,
                        'family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                        'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'is_suspicious': self._is_suspicious_connection({
                            'remote_addr': conn.raddr,
                            'process_name': self._get_process_name(conn.pid)
                        })
                    })
            
            return connections
            
        except Exception as e:
            self.logger.error(f"Error getting active connections: {e}")
            return []
    
    def get_network_stats(self) -> Dict[str, Any]:
        """Get network statistics"""
        try:
            net_io = psutil.net_io_counters()
            
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'errin': net_io.errin,
                'errout': net_io.errout,
                'dropin': net_io.dropin,
                'dropout': net_io.dropout,
                'active_connections': len(self.known_connections),
                'suspicious_connections': sum(
                    1 for conn in self.known_connections.values()
                    if self._is_suspicious_connection(conn)
                )
            }
            
        except Exception as e:
            self.logger.error(f"Error getting network stats: {e}")
            return {}
    
    def get_process_network_activity(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get network activity for specific process"""
        try:
            if pid in self.connection_stats:
                return self.connection_stats[pid].copy()
            
            # Get current connections for this process
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.pid == pid and conn.raddr:
                    connections.append({
                        'local_address': conn.laddr.ip,
                        'local_port': conn.laddr.port,
                        'remote_address': conn.raddr.ip,
                        'remote_port': conn.raddr.port,
                        'status': conn.status,
                        'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                    })
            
            return {
                'process_name': self._get_process_name(pid),
                'connections': connections,
                'connection_count': len(connections)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting process network activity for PID {pid}: {e}")
            return None
    
    def block_ip(self, ip_address: str) -> bool:
        """Add IP to blocked list"""
        try:
            self.blocked_ips.add(ip_address)
            self.logger.info(f"🚫 IP blocked: {ip_address}")
            return True
        except Exception as e:
            self.logger.error(f"Error blocking IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """Remove IP from blocked list"""
        try:
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
                self.logger.info(f"✅ IP unblocked: {ip_address}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs"""
        return list(self.blocked_ips)
    
    def check_dns_activity(self):
        """Monitor DNS queries (simplified implementation)"""
        try:
            # This would typically use ETW or packet capture
            # For now, we'll just monitor DNS-related network connections
            dns_connections = []
            
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr and conn.raddr.port == 53:  # DNS port
                    dns_connections.append({
                        'pid': conn.pid,
                        'process_name': self._get_process_name(conn.pid),
                        'dns_server': conn.raddr.ip,
                        'timestamp': datetime.utcnow().isoformat()
                    })
            
            if dns_connections:
                event_data = {
                    'event_type': 'dns_activity',
                    'connections': dns_connections
                }
                self.event_callback(event_data)
                
        except Exception as e:
            self.logger.error(f"Error checking DNS activity: {e}")
    
    def detect_data_exfiltration(self):
        """Detect potential data exfiltration"""
        try:
            # Look for processes with high outbound traffic
            high_traffic_threshold = 100 * 1024 * 1024  # 100MB
            
            for pid, stats in self.connection_stats.items():
                if stats['connection_count'] > 10 and stats['unique_destinations'] > 5:
                    # Potential data exfiltration pattern
                    event_data = {
                        'event_type': 'potential_data_exfiltration',
                        'process_id': pid,
                        'process_name': stats['process_name'],
                        'connection_count': stats['connection_count'],
                        'unique_destinations': stats['unique_destinations'],
                        'detection_reason': 'high_connection_volume'
                    }
                    
                    self.event_callback(event_data)
                    self.logger.warning(f"🚨 Potential data exfiltration: {stats['process_name']} (PID: {pid})")
                    
        except Exception as e:
            self.logger.error(f"Error detecting data exfiltration: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get monitor statistics"""
        try:
            return {
                'running': self.running,
                'active_connections': len(self.known_connections),
                'monitored_processes': len(self.connection_stats),
                'blocked_ips': len(self.blocked_ips),
                'suspicious_ports': len(self.suspicious_ports),
                'monitor_interval': self.monitor_interval,
                'monitor_connections': self.monitor_connections,
                'monitor_dns': self.monitor_dns
            }
        except Exception as e:
            self.logger.error(f"Error getting network monitor stats: {e}")
            return {'error': str(e)}