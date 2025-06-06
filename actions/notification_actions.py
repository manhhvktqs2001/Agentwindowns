"""
EDR Windows Agent - User Notification Actions
"""

import os
import time
import logging
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

try:
    from win10toast import ToastNotifier
    WIN10TOAST_AVAILABLE = True
except ImportError:
    WIN10TOAST_AVAILABLE = False

try:
    import win32gui
    import win32con
    import win32api
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

class NotificationActions:
    """Handles user notifications and alerts"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.show_notifications = config.get('ui', 'show_notifications', True)
        self.notification_timeout = config.get('ui', 'notification_timeout', 5)
        self.alert_sound = config.get('ui', 'alert_sound', True)
        self.startup_notification = config.get('ui', 'startup_notification', True)
        
        # Notification tracking
        self.notification_history = []
        self.max_history = 100
        self.rate_limit = {}  # Type -> last shown time
        self.rate_limit_seconds = 60  # Don't show same type of alert more than once per minute
        
        # Toast notifier
        self.toast_notifier = None
        if WIN10TOAST_AVAILABLE:
            try:
                self.toast_notifier = ToastNotifier()
            except Exception as e:
                self.logger.warning(f"Failed to initialize toast notifier: {e}")
        
        # Notification queue for threading
        self.notification_queue = []
        self.queue_lock = threading.Lock()
        self.notification_thread = None
        self.running = False
        
        self._start_notification_thread()
        
        self.logger.info("✅ Notification actions initialized")
    
    def _start_notification_thread(self):
        """Start background thread for processing notifications"""
        try:
            self.running = True
            self.notification_thread = threading.Thread(target=self._notification_worker, daemon=True)
            self.notification_thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start notification thread: {e}")
    
    def _notification_worker(self):
        """Background worker for processing notifications"""
        while self.running:
            try:
                with self.queue_lock:
                    if self.notification_queue:
                        notification_data = self.notification_queue.pop(0)
                    else:
                        notification_data = None
                
                if notification_data:
                    self._show_notification_internal(notification_data)
                
                time.sleep(0.5)  # Check queue every 500ms
                
            except Exception as e:
                self.logger.error(f"Error in notification worker: {e}")
                time.sleep(1)
    
    def show_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Show security alert to user"""
        try:
            if not self.show_notifications:
                return False
            
            # Check rate limiting
            alert_type = alert_data.get('alert_type', 'generic')
            if self._is_rate_limited(alert_type):
                self.logger.debug(f"Alert rate limited: {alert_type}")
                return False
            
            # Prepare notification
            title = alert_data.get('title', 'Security Alert')
            message = alert_data.get('message', 'Threat detected by EDR Agent')
            severity = alert_data.get('severity', 'Medium')
            
            # Get appropriate icon based on severity
            icon_path = self._get_alert_icon(severity)
            
            notification_data = {
                'type': 'alert',
                'title': f"🚨 {title}",
                'message': message,
                'icon': icon_path,
                'timeout': self._get_timeout_for_severity(severity),
                'sound': self.alert_sound,
                'severity': severity,
                'alert_data': alert_data
            }
            
            # Queue notification
            with self.queue_lock:
                self.notification_queue.append(notification_data)
            
            # Update rate limiting
            self.rate_limit[alert_type] = time.time()
            
            # Add to history
            self._add_to_history(notification_data)
            
            self.logger.info(f"🔔 Alert queued: {title} ({severity})")
            return True
            
        except Exception as e:
            self.logger.error(f"Error showing alert: {e}")
            return False
    
    def show_info(self, title: str, message: str, timeout: Optional[int] = None) -> bool:
        """Show informational notification"""
        try:
            if not self.show_notifications:
                return False
            
            notification_data = {
                'type': 'info',
                'title': f"ℹ️ {title}",
                'message': message,
                'icon': self._get_info_icon(),
                'timeout': timeout or self.notification_timeout,
                'sound': False,
                'severity': 'Info'
            }
            
            with self.queue_lock:
                self.notification_queue.append(notification_data)
            
            self._add_to_history(notification_data)
            
            self.logger.debug(f"📢 Info notification queued: {title}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error showing info notification: {e}")
            return False
    
    def show_startup_notification(self) -> bool:
        """Show agent startup notification"""
        try:
            if not self.startup_notification:
                return False
            
            hostname = self.config.get_system_info().get('hostname', 'Unknown')
            agent_version = self.config.get('agent', 'version', '2.0.0')
            
            return self.show_info(
                "EDR Agent Started",
                f"EDR Agent v{agent_version} is now protecting {hostname}"
            )
            
        except Exception as e:
            self.logger.error(f"Error showing startup notification: {e}")
            return False
    
    def show_connection_status(self, connected: bool) -> bool:
        """Show connection status notification"""
        try:
            if connected:
                return self.show_info(
                    "Server Connected",
                    "Successfully connected to EDR Server"
                )
            else:
                return self.show_alert({
                    'title': 'Server Disconnected',
                    'message': 'Lost connection to EDR Server. Agent will continue monitoring locally.',
                    'severity': 'Medium',
                    'alert_type': 'connection'
                })
                
        except Exception as e:
            self.logger.error(f"Error showing connection status: {e}")
            return False
    
    def show_threat_blocked(self, threat_info: Dict[str, Any]) -> bool:
        """Show threat blocked notification"""
        try:
            threat_name = threat_info.get('name', 'Unknown threat')
            action_taken = threat_info.get('action', 'blocked')
            
            return self.show_alert({
                'title': 'Threat Blocked',
                'message': f"{threat_name} was {action_taken}",
                'severity': 'High',
                'alert_type': 'threat_blocked'
            })
            
        except Exception as e:
            self.logger.error(f"Error showing threat blocked notification: {e}")
            return False
    
    def _show_notification_internal(self, notification_data: Dict[str, Any]):
        """Internal method to show notification"""
        try:
            title = notification_data['title']
            message = notification_data['message']
            icon = notification_data.get('icon')
            timeout = notification_data.get('timeout', self.notification_timeout)
            sound = notification_data.get('sound', False)
            
            # Try different notification methods in order of preference
            success = False
            
            # Method 1: Windows 10 Toast Notifications
            if WIN10TOAST_AVAILABLE and self.toast_notifier:
                try:
                    self.toast_notifier.show_toast(
                        title=title,
                        msg=message,
                        icon_path=icon,
                        duration=timeout,
                        threaded=True
                    )
                    success = True
                    self.logger.debug(f"📱 Toast notification shown: {title}")
                except Exception as e:
                    self.logger.debug(f"Toast notification failed: {e}")
            
            # Method 2: Plyer notifications
            if not success and PLYER_AVAILABLE:
                try:
                    notification.notify(
                        title=title,
                        message=message,
                        app_name="EDR Agent",
                        timeout=timeout,
                        app_icon=icon
                    )
                    success = True
                    self.logger.debug(f"📱 Plyer notification shown: {title}")
                except Exception as e:
                    self.logger.debug(f"Plyer notification failed: {e}")
            
            # Method 3: Windows MessageBox (fallback)
            if not success and WIN32_AVAILABLE:
                try:
                    # Only for critical alerts
                    severity = notification_data.get('severity', 'Info')
                    if severity in ['Critical', 'High']:
                        self._show_message_box(title, message, severity)
                        success = True
                        self.logger.debug(f"📱 MessageBox shown: {title}")
                except Exception as e:
                    self.logger.debug(f"MessageBox failed: {e}")
            
            # Method 4: Console output (last resort)
            if not success:
                print(f"\n🔔 {title}: {message}\n")
                self.logger.info(f"📱 Console notification: {title}")
            
            # Play sound if requested
            if sound and self.alert_sound:
                self._play_alert_sound()
                
        except Exception as e:
            self.logger.error(f"Error in _show_notification_internal: {e}")
    
    def _show_message_box(self, title: str, message: str, severity: str):
        """Show Windows MessageBox"""
        try:
            # Determine icon based on severity
            if severity == 'Critical':
                icon = win32con.MB_ICONERROR
            elif severity == 'High':
                icon = win32con.MB_ICONWARNING
            else:
                icon = win32con.MB_ICONINFORMATION
            
            # Show non-blocking message box
            threading.Thread(
                target=lambda: win32gui.MessageBox(0, message, title, icon),
                daemon=True
            ).start()
            
        except Exception as e:
            self.logger.error(f"Error showing message box: {e}")
    
    def _play_alert_sound(self):
        """Play alert sound"""
        try:
            if WIN32_AVAILABLE:
                # Play system sound
                win32api.MessageBeep(win32con.MB_ICONEXCLAMATION)
            else:
                # Try to use system bell
                print('\a')  # Bell character
                
        except Exception as e:
            self.logger.debug(f"Error playing alert sound: {e}")
    
    def _get_alert_icon(self, severity: str) -> Optional[str]:
        """Get appropriate icon path for alert severity"""
        try:
            # You would typically have icon files in a resources directory
            icon_dir = os.path.join(os.getcwd(), 'resources', 'icons')
            
            if severity == 'Critical':
                icon_file = 'critical.ico'
            elif severity == 'High':
                icon_file = 'warning.ico'
            elif severity == 'Medium':
                icon_file = 'info.ico'
            else:
                icon_file = 'edr.ico'
            
            icon_path = os.path.join(icon_dir, icon_file)
            return icon_path if os.path.exists(icon_path) else None
            
        except Exception:
            return None
    
    def _get_info_icon(self) -> Optional[str]:
        """Get info icon path"""
        try:
            icon_dir = os.path.join(os.getcwd(), 'resources', 'icons')
            icon_path = os.path.join(icon_dir, 'info.ico')
            return icon_path if os.path.exists(icon_path) else None
        except Exception:
            return None
    
    def _get_timeout_for_severity(self, severity: str) -> int:
        """Get notification timeout based on severity"""
        if severity == 'Critical':
            return 30  # Critical alerts stay longer
        elif severity == 'High':
            return 15
        else:
            return self.notification_timeout
    
    def _is_rate_limited(self, alert_type: str) -> bool:
        """Check if alert type is rate limited"""
        try:
            if alert_type not in self.rate_limit:
                return False
            
            last_shown = self.rate_limit[alert_type]
            return (time.time() - last_shown) < self.rate_limit_seconds
            
        except Exception:
            return False
    
    def _add_to_history(self, notification_data: Dict[str, Any]):
        """Add notification to history"""
        try:
            history_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'type': notification_data.get('type'),
                'title': notification_data.get('title'),
                'message': notification_data.get('message'),
                'severity': notification_data.get('severity')
            }
            
            self.notification_history.append(history_entry)
            
            # Limit history size
            if len(self.notification_history) > self.max_history:
                self.notification_history = self.notification_history[-self.max_history:]
                
        except Exception as e:
            self.logger.error(f"Error adding to notification history: {e}")
    
    def get_notification_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get notification history for specified hours"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            filtered_history = []
            for entry in self.notification_history:
                try:
                    entry_time = datetime.fromisoformat(entry['timestamp'])
                    if entry_time >= cutoff_time:
                        filtered_history.append(entry)
                except Exception:
                    continue
            
            return filtered_history
            
        except Exception as e:
            self.logger.error(f"Error getting notification history: {e}")
            return []
    
    def clear_notification_history(self) -> bool:
        """Clear notification history"""
        try:
            self.notification_history.clear()
            self.logger.info("🗑️ Notification history cleared")
            return True
        except Exception as e:
            self.logger.error(f"Error clearing notification history: {e}")
            return False
    
    def show_custom_alert(self, title: str, message: str, severity: str = 'Medium', 
                         alert_type: str = 'custom', timeout: Optional[int] = None) -> bool:
        """Show custom alert with specified parameters"""
        try:
            alert_data = {
                'title': title,
                'message': message,
                'severity': severity,
                'alert_type': alert_type
            }
            
            return self.show_alert(alert_data)
            
        except Exception as e:
            self.logger.error(f"Error showing custom alert: {e}")
            return False
    
    def stop(self):
        """Stop notification service"""
        try:
            self.running = False
            
            if self.notification_thread and self.notification_thread.is_alive():
                self.notification_thread.join(timeout=5)
            
            self.logger.info("🛑 Notification service stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping notification service: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get notification statistics"""
        try:
            return {
                'show_notifications': self.show_notifications,
                'notification_timeout': self.notification_timeout,
                'alert_sound': self.alert_sound,
                'startup_notification': self.startup_notification,
                'history_count': len(self.notification_history),
                'queue_size': len(self.notification_queue),
                'running': self.running,
                'rate_limit_seconds': self.rate_limit_seconds,
                'available_methods': {
                    'plyer': PLYER_AVAILABLE,
                    'win10toast': WIN10TOAST_AVAILABLE,
                    'win32': WIN32_AVAILABLE
                }
            }
        except Exception as e:
            self.logger.error(f"Error getting notification stats: {e}")
            return {'error': str(e)}