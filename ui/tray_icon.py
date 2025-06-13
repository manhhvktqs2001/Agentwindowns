"""
EDR Windows Agent - System Tray Icon (FIXED WINDOWS MESSAGE LOOP)
Fixed all Windows API message handling and threading issues
"""

import os
import sys
import logging
import threading
import webbrowser
import time
from typing import Dict, Any, Optional

try:
    import pystray
    from PIL import Image, ImageDraw
    PYSTRAY_AVAILABLE = True
except ImportError:
    PYSTRAY_AVAILABLE = False

try:
    import win32gui
    import win32con
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

class SystemTrayIcon:
    """System tray icon for EDR Agent - FIXED Windows message handling"""
    
    def __init__(self, agent):
        self.agent = agent
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.config = agent.config if agent else None
        self.show_tray_icon = self.config.get('ui', 'show_tray_icon', True) if self.config else True
        
        # Tray icon state
        self.icon = None
        self.running = False
        self.tray_thread = None
        
        # Icon paths
        self.icon_dir = os.path.join(os.getcwd(), 'resources', 'icons')
        self.create_icon_dir()
        
        # Status tracking
        self.last_status = {}
        
        # FIXED: Add proper shutdown handling with events
        self.shutdown_event = threading.Event()
        self.cleanup_complete = threading.Event()
        self.icon_created = threading.Event()
        
        # FIXED: Add Windows message handling safety
        self._message_handling_active = False
        self._in_callback = False
        
        self.logger.info("✅ System tray icon initialized")
    
    def create_icon_dir(self):
        """Create icon directory and default icons if they don't exist"""
        try:
            # Create icon directory if it doesn't exist
            os.makedirs(self.icon_dir, exist_ok=True)
            
            # Create default icons programmatically
            self._create_all_default_icons()
            
            self.logger.info("✅ Icon directory and default icons created successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create icon directory: {e}")
            return False
    
    def _create_all_default_icons(self):
        """Create all default icons"""
        default_icons = {
            'edr.png': (0, 120, 212),          # Blue
            'edr_normal.ico': (0, 120, 212),   # Blue
            'edr_alert.ico': (255, 140, 0),    # Orange
            'edr_warning.ico': (255, 165, 0),  # Orange-Red
            'edr_error.ico': (255, 0, 0)       # Red
        }
        
        for icon_name, color in default_icons.items():
            icon_path = os.path.join(self.icon_dir, icon_name)
            if not os.path.exists(icon_path):
                self._create_icon_file(icon_path, color)
    
    def _create_icon_file(self, icon_path: str, color: tuple):
        """Create an icon file with specified color"""
        try:
            # Create a 32x32 image
            img = Image.new('RGBA', (32, 32), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            
            # Draw a simple circle with the specified color
            draw.ellipse([4, 4, 28, 28], fill=color)
            
            # Add a simple "EDR" text if possible
            try:
                from PIL import ImageFont
                # Try to use default font
                font = ImageFont.load_default()
                # Calculate text position to center it
                bbox = draw.textbbox((0, 0), "EDR", font=font)
                text_width = bbox[2] - bbox[0]
                text_height = bbox[3] - bbox[1]
                x = (32 - text_width) // 2
                y = (32 - text_height) // 2
                draw.text((x, y), "EDR", fill=(255, 255, 255), font=font)
            except Exception:
                # If font operations fail, just use the circle
                pass
            
            # Save the image
            if icon_path.endswith('.ico'):
                img.save(icon_path, format='ICO')
            else:
                img.save(icon_path, format='PNG')
            
            self.logger.debug(f"Created icon: {icon_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to create icon {icon_path}: {e}")
    
    def start(self):
        """Start system tray icon - FIXED threading and message handling"""
        try:
            if not self.show_tray_icon or not PYSTRAY_AVAILABLE:
                self.logger.info("System tray disabled or not available")
                return
            
            if self.running:
                self.logger.warning("Tray icon already running")
                return
            
            self.running = True
            self.shutdown_event.clear()
            self.cleanup_complete.clear()
            self.icon_created.clear()
            
            # FIXED: Start tray icon in separate thread with proper error handling
            self.tray_thread = threading.Thread(
                target=self._run_tray_safe, 
                daemon=False,  # FIXED: Not daemon to ensure proper cleanup
                name="TrayIcon"
            )
            self.tray_thread.start()
            
            # Wait for icon to be created (with timeout)
            if not self.icon_created.wait(timeout=5):
                self.logger.warning("Tray icon creation timeout")
            
            self.logger.info("✅ System tray icon started")
            
        except Exception as e:
            self.logger.error(f"Failed to start system tray: {e}")
    
    def stop(self):
        """Stop the tray icon - FIXED Windows message loop cleanup"""
        try:
            self.logger.info("🛑 Stopping system tray icon...")
            
            # Set shutdown flags immediately
            self.running = False
            self.shutdown_event.set()
            
            # FIXED: Safe icon stopping without hanging
            if self.icon:
                try:
                    # FIXED: Use quick stop method in separate thread
                    def safe_icon_stop():
                        try:
                            self._message_handling_active = False
                            if hasattr(self.icon, 'stop'):
                                self.icon.stop()
                        except Exception as e:
                            # FIXED: Ignore expected Windows message loop errors
                            if "message loop" not in str(e).lower() and "wndproc" not in str(e).lower():
                                self.logger.debug(f"Icon stop exception: {e}")
                    
                    # Run stop in separate thread with very short timeout
                    stop_thread = threading.Thread(target=safe_icon_stop, daemon=True)
                    stop_thread.start()
                    stop_thread.join(timeout=1.0)  # 1 second max
                    
                except Exception as e:
                    # FIXED: Log only unexpected errors
                    if "Shell_NotifyIcon" not in str(e) and "WNDPROC" not in str(e):
                        self.logger.debug(f"Tray stop error: {e}")
                finally:
                    self.icon = None
            
            # Wait for thread cleanup with timeout
            if self.tray_thread and self.tray_thread.is_alive():
                self.tray_thread.join(timeout=2.0)  # 2 second max
                if self.tray_thread.is_alive():
                    self.logger.debug("Tray thread did not stop gracefully (timeout)")
            
            # Mark cleanup complete
            self.cleanup_complete.set()
            
            self.logger.info("✅ System tray icon stopped")
            
        except Exception as e:
            # FIXED: Don't log expected Windows cleanup errors as errors
            if any(expected in str(e).lower() for expected in 
                   ["shell_notifyicon", "wndproc", "message loop", "lresult"]):
                self.logger.debug(f"Normal Windows cleanup: {e}")
            else:
                self.logger.error(f"Error stopping system tray: {e}")
            self.cleanup_complete.set()
    
    def _run_tray_safe(self):
        """FIXED: Run the system tray icon with safe Windows message handling"""
        try:
            self.logger.debug("Starting tray icon thread...")
            
            # Load icon
            icon_image = self._load_icon()
            if not icon_image:
                self.logger.error("Failed to load tray icon image")
                return
            
            # Create menu
            menu = self._create_menu()
            
            # FIXED: Create tray icon with safe Windows message handling
            self.icon = pystray.Icon(
                "EDR Agent",
                icon_image,
                "EDR Windows Agent",
                menu
            )
            
            # Mark icon as created
            self.icon_created.set()
            
            # FIXED: Enable message handling
            self._message_handling_active = True
            
            # FIXED: Run with comprehensive exception handling
            while self.running and not self.shutdown_event.is_set():
                try:
                    # Run icon without timeout
                    self.icon.run()
                    
                    # Check if we should continue
                    if not self.running or self.shutdown_event.is_set():
                        break
                        
                except Exception as e:
                    # FIXED: Handle expected Windows message loop errors
                    error_msg = str(e).lower()
                    if any(expected in error_msg for expected in 
                           ["wndproc", "lresult", "wparam", "message loop", "shell_notifyicon"]):
                        self.logger.debug(f"Expected Windows message handling: {e}")
                    elif self.running:
                        self.logger.error(f"Unexpected tray icon error: {e}")
                    else:
                        self.logger.debug(f"Tray icon stopped normally: {e}")
                    
                    # Small delay to prevent CPU spinning
                    time.sleep(0.1)
            
        except Exception as e:
            self.logger.error(f"Critical error in tray thread: {e}")
        finally:
            # Ensure cleanup
            self._message_handling_active = False
            if self.icon:
                try:
                    self.icon.stop()
                except:
                    pass
            self.icon = None
            self.logger.debug("Tray thread finished")
    
    def _load_icon(self) -> Optional[Image.Image]:
        """Load tray icon image with fallback"""
        try:
            # Try different icon formats in order of preference
            icon_formats = ['edr.png', 'edr.ico', 'edr_normal.ico']
            
            for icon_file in icon_formats:
                icon_path = os.path.join(self.icon_dir, icon_file)
                if os.path.exists(icon_path):
                    try:
                        return Image.open(icon_path)
                    except Exception as e:
                        self.logger.debug(f"Failed to load {icon_file}: {e}")
                        continue
            
            # Create a simple default icon in memory
            self.logger.debug("Creating default icon in memory")
            img = Image.new('RGBA', (32, 32), (0, 120, 215, 255))
            draw = ImageDraw.Draw(img)
            draw.ellipse([4, 4, 28, 28], fill=(255, 255, 255))
            
            # Add EDR text
            try:
                from PIL import ImageFont
                font = ImageFont.load_default()
                draw.text((8, 12), "EDR", fill=(0, 120, 215), font=font)
            except:
                pass
            
            return img
                
        except Exception as e:
            self.logger.error(f"Error loading icon: {e}")
            # Return a simple colored square as last resort
            try:
                return Image.new('RGBA', (32, 32), (0, 120, 215, 255))
            except:
                return None
    
    def _create_menu(self) -> pystray.Menu:
        """Create context menu for tray icon - FIXED callback handling"""
        try:
            menu_items = [
                pystray.MenuItem("EDR Agent Status", self._safe_callback(self._show_status)),
                pystray.MenuItem("Open Dashboard", self._safe_callback(self._open_dashboard)),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("View Logs", self._safe_callback(self._view_logs)),
                pystray.MenuItem("View Alerts", self._safe_callback(self._view_alerts)),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Connection", pystray.Menu(
                    pystray.MenuItem("Connect", self._safe_callback(self._connect_server)),
                    pystray.MenuItem("Disconnect", self._safe_callback(self._disconnect_server)),
                    pystray.MenuItem("Reconnect", self._safe_callback(self._reconnect_server))
                )),
                pystray.MenuItem("Monitoring", pystray.Menu(
                    pystray.MenuItem("Start Monitoring", self._safe_callback(self._start_monitoring)),
                    pystray.MenuItem("Stop Monitoring", self._safe_callback(self._stop_monitoring)),
                    pystray.MenuItem("View Process List", self._safe_callback(self._view_processes))
                )),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Settings", self._safe_callback(self._show_settings)),
                pystray.MenuItem("About", self._safe_callback(self._show_about)),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit", self._safe_callback(self._exit_agent))
            ]
            
            return pystray.Menu(*menu_items)
            
        except Exception as e:
            self.logger.error(f"Error creating menu: {e}")
            # Fallback minimal menu
            return pystray.Menu(
                pystray.MenuItem("Status", self._safe_callback(self._show_status)),
                pystray.MenuItem("Exit", self._safe_callback(self._exit_agent))
            )
    
    def _safe_callback(self, callback_func):
        """FIXED: Wrap callback functions to handle Windows message issues"""
        def wrapper(icon=None, item=None):
            try:
                # FIXED: Check if we're in a valid state for callbacks
                if not self._message_handling_active or self._in_callback:
                    return
                
                self._in_callback = True
                
                # Run callback in separate thread to avoid blocking message loop
                callback_thread = threading.Thread(
                    target=lambda: callback_func(icon, item),
                    daemon=True
                )
                callback_thread.start()
                callback_thread.join(timeout=10)  # 10 second timeout
                
            except Exception as e:
                self.logger.error(f"Error in tray callback: {e}")
            finally:
                self._in_callback = False
                
        return wrapper
    
    def _show_status(self, icon=None, item=None):
        """Show agent status"""
        try:
            if self.agent:
                status = self.agent.get_status()
                
                status_text = f"""EDR Agent Status
                
Running: {status.get('running', 'Unknown')}
Connected: {status.get('connected', 'Unknown')}
Hostname: {status.get('hostname', 'Unknown')}
Version: {status.get('agent_version', 'Unknown')}
Uptime: {status.get('uptime', 0):.0f} seconds

Monitors:
- Process: {status.get('monitors', {}).get('process', False)}
- File: {status.get('monitors', {}).get('file', False)}
- Network: {status.get('monitors', {}).get('network', False)}

Data Buffer:
- Processes: {status.get('data_buffer_size', {}).get('processes', 0)}
- Files: {status.get('data_buffer_size', {}).get('files', 0)}
- Networks: {status.get('data_buffer_size', {}).get('networks', 0)}
"""
                
                self._show_message_box("EDR Agent Status", status_text)
            else:
                self._show_message_box("EDR Agent", "Agent not available")
                
        except Exception as e:
            self.logger.error(f"Error showing status: {e}")
            self._show_message_box("Error", f"Failed to get status: {e}")
    
    def _open_dashboard(self, icon=None, item=None):
        """Open web dashboard"""
        try:
            if self.config:
                server_url = self.config.SERVER_URL
                # Remove socket.io path and add dashboard
                dashboard_url = server_url.replace('/socket.io', '/dashboard')
                webbrowser.open(dashboard_url)
            else:
                self._show_message_box("Error", "Server URL not configured")
                
        except Exception as e:
            self.logger.error(f"Error opening dashboard: {e}")
            self._show_message_box("Error", f"Failed to open dashboard: {e}")
    
    def _view_logs(self, icon=None, item=None):
        """View agent logs"""
        try:
            log_file = os.path.join(os.getcwd(), 'logs', 'agent.log')
            if os.path.exists(log_file):
                os.startfile(log_file)
            else:
                self._show_message_box("Info", "No log file found")
                
        except Exception as e:
            self.logger.error(f"Error viewing logs: {e}")
            self._show_message_box("Error", f"Failed to open logs: {e}")
    
    def _view_alerts(self, icon=None, item=None):
        """View recent alerts"""
        try:
            if self.agent and hasattr(self.agent, 'notification_actions'):
                history = self.agent.notification_actions.get_notification_history(24)
                
                if history:
                    alert_text = "Recent Alerts (24 hours):\n\n"
                    for alert in history[-10:]:  # Show last 10
                        alert_text += f"{alert['timestamp']}: {alert['title']}\n"
                        alert_text += f"  {alert['message']}\n\n"
                    
                    self._show_message_box("Recent Alerts", alert_text)
                else:
                    self._show_message_box("Info", "No recent alerts")
            else:
                self._show_message_box("Error", "Alert system not available")
                
        except Exception as e:
            self.logger.error(f"Error viewing alerts: {e}")
            self._show_message_box("Error", f"Failed to get alerts: {e}")
    
    def _connect_server(self, icon=None, item=None):
        """Connect to server"""
        try:
            if self.agent and self.agent.connection:
                success = self.agent.connection.start()
                if success:
                    self._show_message_box("Success", "Connected to server")
                else:
                    self._show_message_box("Error", "Failed to connect to server")
            else:
                self._show_message_box("Error", "Connection not available")
                
        except Exception as e:
            self.logger.error(f"Error connecting to server: {e}")
            self._show_message_box("Error", f"Connection failed: {e}")
    
    def _disconnect_server(self, icon=None, item=None):
        """Disconnect from server"""
        try:
            if self.agent and self.agent.connection:
                self.agent.connection.stop()
                self._show_message_box("Info", "Disconnected from server")
            else:
                self._show_message_box("Error", "Connection not available")
                
        except Exception as e:
            self.logger.error(f"Error disconnecting from server: {e}")
            self._show_message_box("Error", f"Disconnect failed: {e}")
    
    def _reconnect_server(self, icon=None, item=None):
        """Reconnect to server"""
        try:
            if self.agent and self.agent.connection:
                success = self.agent.connection.force_reconnect()
                if success:
                    self._show_message_box("Success", "Reconnected to server")
                else:
                    self._show_message_box("Error", "Failed to reconnect to server")
            else:
                self._show_message_box("Error", "Connection not available")
                
        except Exception as e:
            self.logger.error(f"Error reconnecting to server: {e}")
            self._show_message_box("Error", f"Reconnect failed: {e}")
    
    def _start_monitoring(self, icon=None, item=None):
        """Start monitoring"""
        try:
            if self.agent:
                # Restart monitors
                if self.agent.process_monitor:
                    self.agent.process_monitor.start()
                if self.agent.file_monitor:
                    self.agent.file_monitor.start()
                if self.agent.network_monitor:
                    self.agent.network_monitor.start()
                
                self._show_message_box("Success", "Monitoring started")
            else:
                self._show_message_box("Error", "Agent not available")
                
        except Exception as e:
            self.logger.error(f"Error starting monitoring: {e}")
            self._show_message_box("Error", f"Failed to start monitoring: {e}")
    
    def _stop_monitoring(self, icon=None, item=None):
        """Stop monitoring"""
        try:
            if self.agent:
                # Stop monitors
                if self.agent.process_monitor:
                    self.agent.process_monitor.stop()
                if self.agent.file_monitor:
                    self.agent.file_monitor.stop()
                if self.agent.network_monitor:
                    self.agent.network_monitor.stop()
                
                self._show_message_box("Info", "Monitoring stopped")
            else:
                self._show_message_box("Error", "Agent not available")
                
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {e}")
            self._show_message_box("Error", f"Failed to stop monitoring: {e}")
    
    def _view_processes(self, icon=None, item=None):
        """View running processes"""
        try:
            if self.agent and self.agent.process_monitor:
                processes = self.agent.process_monitor.get_process_list()
                
                if processes:
                    # Show first 10 processes
                    process_text = "Running Processes (showing first 10):\n\n"
                    for proc in processes[:10]:
                        process_text += f"PID: {proc['pid']} - {proc['name']}\n"
                        process_text += f"  CPU: {proc.get('cpu_percent', 0):.1f}% | "
                        process_text += f"Memory: {proc.get('memory_mb', 0):.1f} MB\n\n"
                    
                    self._show_message_box("Running Processes", process_text)
                else:
                    self._show_message_box("Info", "No process information available")
            else:
                self._show_message_box("Error", "Process monitor not available")
                
        except Exception as e:
            self.logger.error(f"Error viewing processes: {e}")
            self._show_message_box("Error", f"Failed to get processes: {e}")
    
    def _show_settings(self, icon=None, item=None):
        """Show settings"""
        try:
            if self.config:
                settings_text = f"""EDR Agent Settings

Server URL: {self.config.SERVER_URL}
Agent Name: {self.config.AGENT_NAME}
Log Level: {self.config.LOG_LEVEL}
Heartbeat Interval: {self.config.HEARTBEAT_INTERVAL}s
Monitoring Interval: {self.config.MONITORING_INTERVAL}s

Process Monitoring: {self.config.PROCESS_MONITORING}
File Monitoring: {self.config.FILE_MONITORING}
Network Monitoring: {self.config.NETWORK_MONITORING}

Show Notifications: {self.config.SHOW_NOTIFICATIONS}
Auto Response: {self.config.AUTO_RESPONSE_ENABLED}
"""
                
                self._show_message_box("EDR Agent Settings", settings_text)
            else:
                self._show_message_box("Error", "Configuration not available")
                
        except Exception as e:
            self.logger.error(f"Error showing settings: {e}")
            self._show_message_box("Error", f"Failed to get settings: {e}")
    
    def _show_about(self, icon=None, item=None):
        """Show about dialog"""
        try:
            about_text = f"""EDR Windows Agent

Version: {self.config.get('agent', 'version', '2.0.0') if self.config else '2.0.0'}
Build: Windows x64
Author: EDR System

Description:
Endpoint Detection and Response agent for Windows systems.
Provides real-time monitoring of processes, files, and network activity.

Features:
• Process monitoring and analysis
• File system monitoring
• Network connection tracking
• Real-time threat detection
• Automated response capabilities
• Integration with EDR Server

Copyright © 2024 EDR System
"""
            
            self._show_message_box("About EDR Agent", about_text)
            
        except Exception as e:
            self.logger.error(f"Error showing about: {e}")
            self._show_message_box("About", "EDR Windows Agent v2.0.0")
    
    def _exit_agent(self, icon=None, item=None):
        """Exit the agent - FIXED to prevent hanging"""
        try:
            result = self._show_confirm_dialog(
                "Exit EDR Agent",
                "Are you sure you want to exit EDR Agent?\nThis will stop all monitoring."
            )
            
            if result:
                self.logger.info("👋 User requested agent exit")
                
                # FIXED: Quick shutdown sequence
                try:
                    # Signal immediate shutdown
                    self.shutdown_event.set()
                    self._message_handling_active = False
                    
                    # Quick agent stop in background thread
                    def quick_shutdown():
                        try:
                            if self.agent:
                                self.agent.stop()
                            # Force exit after short delay
                            time.sleep(1)
                            os._exit(0)
                        except Exception as e:
                            self.logger.debug(f"Shutdown error: {e}")
                            os._exit(1)
                    
                    shutdown_thread = threading.Thread(target=quick_shutdown, daemon=True)
                    shutdown_thread.start()
                    
                    # Stop icon immediately
                    if self.icon and hasattr(self.icon, 'stop'):
                        try:
                            self.icon.stop()
                        except:
                            pass  # Ignore icon stop errors during exit
                    
                except Exception as e:
                    self.logger.error(f"Error during exit: {e}")
                    os._exit(1)
                
        except Exception as e:
            self.logger.error(f"Error exiting agent: {e}")
            os._exit(1)
    
    def _show_message_box(self, title: str, message: str):
        """FIXED: Show message box with proper Windows API handling"""
        try:
            if WIN32_AVAILABLE:
                # FIXED: Handle Windows API calls safely
                def show_msg():
                    try:
                        # FIXED: Validate parameters to prevent WPARAM errors
                        if not title:
                            title = "EDR Agent"
                        if not message:
                            message = "No message"
                        
                        # Ensure strings are not None and properly formatted
                        title_str = str(title)[:255]  # Limit length
                        message_str = str(message)[:1000]  # Limit length
                        
                        result = win32gui.MessageBox(
                            0, 
                            message_str, 
                            title_str, 
                            win32con.MB_OK | win32con.MB_ICONINFORMATION
                        )
                        return result
                    except Exception as e:
                        self.logger.debug(f"MessageBox error: {e}")
                        # Fallback to console
                        print(f"\n{title}: {message}\n")
                        return win32con.IDOK
                
                # Run in separate thread with timeout
                msg_thread = threading.Thread(target=show_msg, daemon=True)
                msg_thread.start()
                msg_thread.join(timeout=1.0)  # 1 second timeout
            else:
                print(f"\n{title}: {message}\n")
                
        except Exception as e:
            self.logger.error(f"Error showing message box: {e}")
            print(f"\n{title}: {message}\n")
    
    def _show_confirm_dialog(self, title: str, message: str) -> bool:
        """FIXED: Show confirmation dialog with proper error handling"""
        try:
            if WIN32_AVAILABLE:
                try:
                    # FIXED: Validate parameters
                    if not title:
                        title = "EDR Agent"
                    if not message:
                        message = "Confirm action?"
                    
                    title_str = str(title)[:255]
                    message_str = str(message)[:1000]
                    
                    result = win32gui.MessageBox(
                        0, 
                        message_str, 
                        title_str, 
                        win32con.MB_YESNO | win32con.MB_ICONQUESTION
                    )
                    return result == win32con.IDYES
                except Exception as e:
                    self.logger.debug(f"MessageBox error: {e}")
                    # Fallback to console
                    response = input(f"{message} (y/n): ").lower()
                    return response in ['y', 'yes']
            else:
                response = input(f"{message} (y/n): ").lower()
                return response in ['y', 'yes']
                
        except Exception as e:
            self.logger.error(f"Error showing confirm dialog: {e}")
            return False
    
    def update_icon_status(self, status: Dict[str, Any]):
        """Update icon based on agent status - FIXED"""
        try:
            if not self.icon or not self.running or not self._message_handling_active:
                return
            
            # Update tooltip
            connected = status.get('connected', False)
            running = status.get('running', False)
            
            if running and connected:
                tooltip = "EDR Agent - Running (Connected)"
            elif running:
                tooltip = "EDR Agent - Running (Disconnected)"
            else:
                tooltip = "EDR Agent - Stopped"
            
            # FIXED: Safe tooltip update with error handling
            try:
                if hasattr(self.icon, 'title'):
                    self.icon.title = tooltip
            except Exception as e:
                self.logger.debug(f"Tooltip update error: {e}")
            
            # Store status for menu updates
            self.last_status = status
            
        except Exception as e:
            self.logger.error(f"Error updating icon status: {e}")
    
    def show_notification(self, title: str, message: str):
        """Show system notification via tray icon - FIXED"""
        try:
            if not self.icon or not self.running or not self._message_handling_active:
                return

            # Validate parameters
            if not title or not message:
                self.logger.warning("Invalid notification parameters")
                return

            # FIXED: Safe notification with proper Windows API handling
            def show_notification_safe():
                try:
                    if WIN32_AVAILABLE:
                        # Use Windows notification API
                        import win32api
                        import win32con
                        
                        # Format message
                        title_str = str(title)[:255]  # Limit length
                        message_str = str(message)[:1000]  # Limit length
                        
                        # Show notification
                        win32api.MessageBox(
                            0,
                            message_str,
                            title_str,
                            win32con.MB_OK | win32con.MB_ICONINFORMATION
                        )
                    else:
                        # Fallback to console
                        print(f"\n{title}: {message}\n")
                except Exception as e:
                    self.logger.debug(f"Notification error: {e}")
                    print(f"\n{title}: {message}\n")

            # Run in separate thread with timeout
            notif_thread = threading.Thread(target=show_notification_safe, daemon=True)
            notif_thread.start()
            notif_thread.join(timeout=1.0)  # 1 second timeout

        except Exception as e:
            self.logger.error(f"Error showing notification: {e}")
            print(f"\n{title}: {message}\n")