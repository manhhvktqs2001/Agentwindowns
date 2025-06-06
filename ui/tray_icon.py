"""
EDR Windows Agent - System Tray Icon
"""

import os
import sys
import logging
import threading
import webbrowser
from typing import Dict, Any, Optional

try:
    import pystray
    from PIL import Image
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
    """System tray icon for EDR Agent"""
    
    def __init__(self, agent):
        self.agent = agent
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.config = agent.config if agent else None
        self.show_tray_icon = self.config.get('ui', 'show_tray_icon', True) if self.config else True
        
        # Tray icon
        self.icon = None
        self.running = False
        self.tray_thread = None
        
        # Icon paths
        self.icon_dir = os.path.join(os.getcwd(), 'resources', 'icons')
        self.create_icon_dir()
        
        # Status
        self.last_status = {}
        
        self.logger.info("✅ System tray icon initialized")
    
    def create_icon_dir(self):
        """Create icon directory and default icons if they don't exist"""
        try:
            # Create icon directory if it doesn't exist
            os.makedirs(self.icon_dir, exist_ok=True)
            
            # Default icon paths
            default_icons = {
                'normal': 'edr_normal.ico',
                'alert': 'edr_alert.ico',
                'warning': 'edr_warning.ico',
                'error': 'edr_error.ico'
            }
            
            # Check if default icons exist, if not create them
            for icon_name, icon_file in default_icons.items():
                icon_path = os.path.join(self.icon_dir, icon_file)
                if not os.path.exists(icon_path):
                    self._create_default_icon(icon_path, icon_name)
            
            self.logger.info("✅ Icon directory and default icons created successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create icon directory: {e}")
            return False
            
    def _create_default_icon(self, icon_path: str, icon_type: str):
        """Create a default icon file"""
        try:
            # Create a simple colored icon based on type
            from PIL import Image, ImageDraw
            
            # Create a 32x32 image
            img = Image.new('RGBA', (32, 32), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            
            # Set color based on icon type
            if icon_type == 'normal':
                color = (0, 120, 212)  # Blue
            elif icon_type == 'alert':
                color = (255, 140, 0)  # Orange
            elif icon_type == 'warning':
                color = (255, 165, 0)  # Orange-Red
            else:  # error
                color = (255, 0, 0)  # Red
                
            # Draw a simple circle
            draw.ellipse([4, 4, 28, 28], fill=color)
            
            # Save as ICO
            img.save(icon_path, format='ICO')
            
            self.logger.debug(f"Created default icon: {icon_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to create default icon {icon_path}: {e}")
            # If icon creation fails, copy a fallback icon if available
            fallback_icon = os.path.join(os.path.dirname(__file__), 'resources', 'fallback.ico')
            if os.path.exists(fallback_icon):
                import shutil
                shutil.copy2(fallback_icon, icon_path)
                self.logger.info(f"Used fallback icon for {icon_path}")
    
    def start(self):
        """Start system tray icon"""
        try:
            if not self.show_tray_icon or not PYSTRAY_AVAILABLE:
                self.logger.info("System tray disabled or not available")
                return
            
            self.running = True
            
            # Start tray icon in separate thread
            self.tray_thread = threading.Thread(target=self._run_tray, daemon=True)
            self.tray_thread.start()
            
            self.logger.info("✅ System tray icon started")
            
        except Exception as e:
            self.logger.error(f"Failed to start system tray: {e}")
    
    def stop(self):
        """Stop system tray icon"""
        try:
            self.running = False
            
            if self.icon:
                self.icon.stop()
            
            if self.tray_thread and self.tray_thread.is_alive():
                self.tray_thread.join(timeout=5)
            
            self.logger.info("🛑 System tray icon stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping system tray: {e}")
    
    def _run_tray(self):
        """Run the system tray icon"""
        try:
            # Load icon
            icon_image = self._load_icon()
            
            # Create menu
            menu = self._create_menu()
            
            # Create tray icon
            self.icon = pystray.Icon(
                "EDR Agent",
                icon_image,
                "EDR Windows Agent",
                menu
            )
            
            # Run tray icon
            self.icon.run()
            
        except Exception as e:
            self.logger.error(f"Error running system tray: {e}")
    
    def _load_icon(self) -> Optional[Image.Image]:
        """Load tray icon image"""
        try:
            icon_path = os.path.join(self.icon_dir, 'edr.png')
            
            if os.path.exists(icon_path):
                return Image.open(icon_path)
            else:
                # Create a simple default icon in memory
                img = Image.new('RGBA', (32, 32), (0, 120, 215, 255))
                return img
                
        except Exception as e:
            self.logger.error(f"Error loading icon: {e}")
            # Return a simple colored square as fallback
            return Image.new('RGBA', (32, 32), (0, 120, 215, 255))
    
    def _create_menu(self) -> pystray.Menu:
        """Create context menu for tray icon"""
        try:
            menu_items = [
                pystray.MenuItem("EDR Agent Status", self._show_status),
                pystray.MenuItem("Open Dashboard", self._open_dashboard),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("View Logs", self._view_logs),
                pystray.MenuItem("View Alerts", self._view_alerts),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Connection", pystray.Menu(
                    pystray.MenuItem("Connect", self._connect_server),
                    pystray.MenuItem("Disconnect", self._disconnect_server),
                    pystray.MenuItem("Reconnect", self._reconnect_server)
                )),
                pystray.MenuItem("Monitoring", pystray.Menu(
                    pystray.MenuItem("Start Monitoring", self._start_monitoring),
                    pystray.MenuItem("Stop Monitoring", self._stop_monitoring),
                    pystray.MenuItem("View Process List", self._view_processes)
                )),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Settings", self._show_settings),
                pystray.MenuItem("About", self._show_about),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit", self._exit_agent)
            ]
            
            return pystray.Menu(*menu_items)
            
        except Exception as e:
            self.logger.error(f"Error creating menu: {e}")
            return pystray.Menu(
                pystray.MenuItem("Status", self._show_status),
                pystray.MenuItem("Exit", self._exit_agent)
            )
    
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
                success = self.agent.connection.reconnect()
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
        """Exit the agent"""
        try:
            result = self._show_confirm_dialog(
                "Exit EDR Agent",
                "Are you sure you want to exit EDR Agent?\nThis will stop all monitoring."
            )
            
            if result:
                self.logger.info("👋 User requested agent exit")
                if self.agent:
                    self.agent.stop()
                self.stop()
                sys.exit(0)
                
        except Exception as e:
            self.logger.error(f"Error exiting agent: {e}")
            sys.exit(1)
    
    def _show_message_box(self, title: str, message: str):
        """Show message box"""
        try:
            if WIN32_AVAILABLE:
                win32gui.MessageBox(0, message, title, win32con.MB_OK | win32con.MB_ICONINFORMATION)
            else:
                print(f"\n{title}: {message}\n")
                
        except Exception as e:
            self.logger.error(f"Error showing message box: {e}")
            print(f"\n{title}: {message}\n")
    
    def _show_confirm_dialog(self, title: str, message: str) -> bool:
        """Show confirmation dialog"""
        try:
            if WIN32_AVAILABLE:
                result = win32gui.MessageBox(0, message, title, win32con.MB_YESNO | win32con.MB_ICONQUESTION)
                return result == win32con.IDYES
            else:
                response = input(f"{message} (y/n): ").lower()
                return response in ['y', 'yes']
                
        except Exception as e:
            self.logger.error(f"Error showing confirm dialog: {e}")
            return False
    
    def update_icon_status(self, status: Dict[str, Any]):
        """Update icon based on agent status"""
        try:
            if not self.icon:
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
            
            self.icon.title = tooltip
            
            # Store status for menu updates
            self.last_status = status
            
        except Exception as e:
            self.logger.error(f"Error updating icon status: {e}")
    
    def show_notification(self, title: str, message: str):
        """Show system notification via tray icon"""
        try:
            if self.icon and hasattr(self.icon, 'notify'):
                self.icon.notify(message, title)
            else:
                self._show_message_box(title, message)
                
        except Exception as e:
            self.logger.error(f"Error showing tray notification: {e}")
    
    def is_running(self) -> bool:
        """Check if tray icon is running"""
        return self.running and (self.tray_thread and self.tray_thread.is_alive())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get tray icon statistics"""
        try:
            return {
                'running': self.running,
                'show_tray_icon': self.show_tray_icon,
                'pystray_available': PYSTRAY_AVAILABLE,
                'win32_available': WIN32_AVAILABLE,
                'icon_dir': self.icon_dir,
                'last_status': self.last_status
            }
        except Exception as e:
            self.logger.error(f"Error getting tray icon stats: {e}")
            return {'error': str(e)}