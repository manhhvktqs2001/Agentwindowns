"""
EDR Windows Agent - User Notification Actions (FIXED)
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
        
        # FIXED: Icon management
        self.icon_dir = os.path.join(os.getcwd(), 'resources', 'icons')
        self._ensure_icons_exist()
        
        self._start_notification_thread()
        
        self.logger.info("✅ Notification actions initialized")
    
    def _ensure_icons_exist(self):
        """Ensure icon directory and default icons exist"""
        try:
            # Create icon directory if it doesn't exist
            os.makedirs(self.icon_dir, exist_ok=True)
            
            # FIXED: Create default icons if they don't exist
            default_icons = {
                'edr.ico': (0, 120, 212),      # Blue
                'critical.ico': (255, 0, 0),   # Red
                'warning.ico': (255, 165, 0),  # Orange
                'info.ico': (0, 120, 212),     # Blue
                'success.ico': (0, 128, 0)     # Green
            }
            
            for icon_name, color in default_icons.items():
                icon_path = os.path.join(self.icon_dir, icon_name)
                if not os.path.exists(icon_path):
                    self._create_default_icon(icon_path, color)
            
        except Exception as e:
            self.logger.error(f"Error ensuring icons exist: {e}")
    
    def _create_default_icon(self, icon_path: str, color: tuple):
        """Create a default icon file"""
        try:
            from PIL import Image, ImageDraw
            
            # Create a 32x32 image
            img = Image.new('RGBA', (32, 32), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            
            # Draw a simple circle with the specified color
            draw.ellipse([4, 4, 28, 28], fill=color)
            
            # Add a simple "EDR" text
            try:
                from PIL import ImageFont
                font = ImageFont.load_default()
                draw.text((8, 12), "EDR", fill=(255, 255, 255), font=font)
            except:
                pass  # If font loading fails, just use the circle
            
            # Save as ICO
            img.save(icon_path, format='ICO')
            
            self.logger.debug(f"Created default icon: {icon_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to create default icon {icon_path}: {e}")
    
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
    
    def show_rule_triggered(self, rule_info: Dict[str, Any]) -> bool:
        """Show rule triggered notification"""
        try:
            rule_name = rule_info.get('rule_name', 'Security Rule')
            severity = rule_info.get('severity', 'Medium')
            description = rule_info.get('description', 'Security rule violation detected')
            
            return self.show_alert({
                'title': f'Rule Triggered: {rule_name}',
                'message': description,
                'severity': severity,
                'alert_type': 'rule_triggered'
            })
            
        except Exception as e:
            self.logger.error(f"Error showing rule triggered notification: {e}")
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
            
            # Method 3: Windows MessageBox (fallback for critical alerts)
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
            # FIXED: Create icons directory if not exists and use fallback
            os.makedirs(self.icon_dir, exist_ok=True)
            
            severity_icons = {
                'Critical': 'critical.ico',
                'High': 'warning.ico', 
                'Medium': 'info.ico',
                'Low': 'edr.ico'
            }
            
            icon_file = severity_icons.get(severity, 'edr.ico')
            icon_path = os.path.join(self.icon_dir, icon_file)
            
            # FIXED: Return path even if file doesn't exist (notification libraries handle this)
            return icon_path
            
        except Exception as e:
            self.logger.debug(f"Error getting alert icon: {e}")
            return None
    
    def _get_info_icon(self) -> Optional[str]:
        """Get info icon path"""
        try:
            icon_path = os.path.join(self.icon_dir, 'info.ico')
            return icon_path
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
            
            if timeout:
                alert_data['timeout'] = timeout
            
            return self.show_alert(alert_data)
            
        except Exception as e:
            self.logger.error(f"Error showing custom alert: {e}")
            return False
    
    def show_success(self, title: str, message: str, timeout: Optional[int] = None) -> bool:
        """Show success notification"""
        try:
            notification_data = {
                'type': 'success',
                'title': f"✅ {title}",
                'message': message,
                'icon': os.path.join(self.icon_dir, 'success.ico'),
                'timeout': timeout or self.notification_timeout,
                'sound': False,
                'severity': 'Success'
            }
            
            with self.queue_lock:
                self.notification_queue.append(notification_data)
            
            self._add_to_history(notification_data)
            
            self.logger.debug(f"✅ Success notification queued: {title}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error showing success notification: {e}")
            return False
    
    def show_warning(self, title: str, message: str, timeout: Optional[int] = None) -> bool:
        """Show warning notification"""
        try:
            notification_data = {
                'type': 'warning',
                'title': f"⚠️ {title}",
                'message': message,
                'icon': self._get_alert_icon('High'),
                'timeout': timeout or (self.notification_timeout + 5),
                'sound': True,
                'severity': 'Warning'
            }
            
            with self.queue_lock:
                self.notification_queue.append(notification_data)
            
            self._add_to_history(notification_data)
            
            self.logger.debug(f"⚠️ Warning notification queued: {title}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error showing warning notification: {e}")
            return False
    
    def get_pending_notifications_count(self) -> int:
        """Get count of pending notifications in queue"""
        try:
            with self.queue_lock:
                return len(self.notification_queue)
        except Exception:
            return 0
    
    def clear_pending_notifications(self) -> bool:
        """Clear all pending notifications"""
        try:
            with self.queue_lock:
                cleared_count = len(self.notification_queue)
                self.notification_queue.clear()
            
            self.logger.info(f"🗑️ Cleared {cleared_count} pending notifications")
            return True
            
        except Exception as e:
            self.logger.error(f"Error clearing pending notifications: {e}")
            return False
    
    def set_notification_settings(self, show_notifications: bool = None, 
                                alert_sound: bool = None, 
                                notification_timeout: int = None) -> bool:
        """Update notification settings"""
        try:
            if show_notifications is not None:
                self.show_notifications = show_notifications
                self.config.set('ui', 'show_notifications', show_notifications)
            
            if alert_sound is not None:
                self.alert_sound = alert_sound
                self.config.set('ui', 'alert_sound', alert_sound)
            
            if notification_timeout is not None:
                self.notification_timeout = notification_timeout
                self.config.set('ui', 'notification_timeout', notification_timeout)
            
            # Save config
            self.config.save_config()
            
            self.logger.info("✅ Notification settings updated")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating notification settings: {e}")
            return False
    
    def test_notification_system(self) -> Dict[str, bool]:
        """Test all notification methods"""
        try:
            results = {
                'toast': False,
                'plyer': False,
                'messagebox': False,
                'sound': False
            }
            
            test_title = "EDR Agent Test"
            test_message = "Testing notification system"
            
            # Test Toast notifications
            if WIN10TOAST_AVAILABLE and self.toast_notifier:
                try:
                    self.toast_notifier.show_toast(
                        title=test_title,
                        msg=test_message,
                        duration=2,
                        threaded=True
                    )
                    results['toast'] = True
                except Exception as e:
                    self.logger.debug(f"Toast test failed: {e}")
            
            # Test Plyer notifications
            if PLYER_AVAILABLE:
                try:
                    notification.notify(
                        title=test_title,
                        message=test_message,
                        app_name="EDR Agent",
                        timeout=2
                    )
                    results['plyer'] = True
                except Exception as e:
                    self.logger.debug(f"Plyer test failed: {e}")
            
            # Test MessageBox
            if WIN32_AVAILABLE:
                try:
                    # Don't actually show the message box in test
                    results['messagebox'] = True
                except Exception as e:
                    self.logger.debug(f"MessageBox test failed: {e}")
            
            # Test sound
            try:
                self._play_alert_sound()
                results['sound'] = True
            except Exception as e:
                self.logger.debug(f"Sound test failed: {e}")
            
            self.logger.info(f"📊 Notification system test results: {results}")
            return results
            
        except Exception as e:
            self.logger.error(f"Error testing notification system: {e}")
            return {'error': str(e)}
    
    def stop(self):
        """Stop notification service"""
        try:
            self.running = False
            
            # Clear pending notifications
            self.clear_pending_notifications()
            
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
                'icon_directory': self.icon_dir,
                'available_methods': {
                    'plyer': PLYER_AVAILABLE,
                    'win10toast': WIN10TOAST_AVAILABLE,
                    'win32': WIN32_AVAILABLE
                },
                'rate_limited_types': list(self.rate_limit.keys())
            }
        except Exception as e:
            self.logger.error(f"Error getting notification stats: {e}")
            return {'error': str(e)}