#!/usr/bin/env python3
"""
EDR Windows Agent - Main Entry Point (FIXED APPLICATION LIFECYCLE)
Fixed main loop to keep application alive
"""

import sys
import os
import argparse
import logging
import signal
import time
import threading
from pathlib import Path
from datetime import datetime

# Add current directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import modules
from config import AgentConfig
from core.agent import EDRAgent
from core.enhanced_agent_core import EnhancedEDRAgent
from utils.windows_utils import WindowsUtils

class EDRAgentMain:
    """Main application class for EDR Agent - FIXED"""
    
    def __init__(self):
        """Initialize main application"""
        self.agent = None
        self.tray_icon = None
        self.running = False
        self.shutdown_event = threading.Event()
        self.logger = None
        self.graceful_shutdown = False
        
        # FIXED: Add application lifecycle control
        self.app_lifecycle_event = threading.Event()
        self.main_loop_running = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # For Windows service compatibility
        if hasattr(signal, 'SIGBREAK'):
            signal.signal(signal.SIGBREAK, self.signal_handler)
    
    def setup_logging(self, debug=False, log_file=None):
        """Setup comprehensive logging with better error handling"""
        try:
            # Create logs directory
            logs_dir = Path("logs")
            logs_dir.mkdir(exist_ok=True)
            
            # Determine log level
            log_level = logging.DEBUG if debug else logging.INFO
            
            # Create formatters
            detailed_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
            )
            simple_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            
            # Setup root logger
            root_logger = logging.getLogger()
            root_logger.setLevel(log_level)
            
            # Remove existing handlers
            for handler in root_logger.handlers[:]:
                try:
                    handler.close()
                    root_logger.removeHandler(handler)
                except:
                    pass
            
            # File handler for detailed logs
            if not log_file:
                log_file = logs_dir / f"agent_{datetime.now().strftime('%Y%m%d')}.log"
            
            try:
                file_handler = logging.FileHandler(log_file, encoding='utf-8')
                file_handler.setLevel(log_level)
                file_handler.setFormatter(detailed_formatter)
                root_logger.addHandler(file_handler)
            except Exception as e:
                print(f"Warning: Could not create file handler: {e}")
            
            # Console handler for immediate feedback
            try:
                console_handler = logging.StreamHandler(sys.stdout)
                console_handler.setLevel(logging.INFO if not debug else logging.DEBUG)
                console_handler.setFormatter(simple_formatter)
                root_logger.addHandler(console_handler)
            except Exception as e:
                print(f"Warning: Could not create console handler: {e}")
            
            # Error file handler
            try:
                error_handler = logging.FileHandler(logs_dir / "errors.log", encoding='utf-8')
                error_handler.setLevel(logging.ERROR)
                error_handler.setFormatter(detailed_formatter)
                root_logger.addHandler(error_handler)
            except Exception as e:
                print(f"Warning: Could not create error handler: {e}")
            
            # Create main logger
            self.logger = logging.getLogger(__name__)
            self.logger.info("✅ Logging system initialized")
            self.logger.info(f"📁 Log file: {log_file}")
            
            # Log system information
            self._log_system_info()
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to setup logging: {e}")
            # Create basic console logger as fallback
            try:
                logging.basicConfig(
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)]
                )
                self.logger = logging.getLogger(__name__)
                self.logger.error(f"Fallback logging active due to error: {e}")
                return True
            except:
                return False
    
    def _log_system_info(self):
        """Log system information at startup"""
        try:
            import platform
            import psutil
            
            self.logger.info("=" * 50)
            self.logger.info("EDR WINDOWS AGENT STARTUP")
            self.logger.info("=" * 50)
            self.logger.info(f"🖥️ System: {platform.platform()}")
            self.logger.info(f"🏠 Hostname: {platform.node()}")
            self.logger.info(f"👤 User: {os.environ.get('USERNAME', 'Unknown')}")
            self.logger.info(f"🔧 Python: {sys.version}")
            self.logger.info(f"📁 Working Directory: {os.getcwd()}")
            self.logger.info(f"🔑 Admin Rights: {WindowsUtils.is_admin()}")
            
            # Memory and CPU info
            try:
                memory = psutil.virtual_memory()
                self.logger.info(f"💾 Memory: {memory.total // (1024**3)}GB total, {memory.percent}% used")
                self.logger.info(f"🔄 CPU: {psutil.cpu_count()} cores, {psutil.cpu_percent()}% usage")
            except Exception as e:
                self.logger.warning(f"Could not get system metrics: {e}")
            
            self.logger.info("=" * 50)
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error logging system info: {e}")
    
    def check_requirements(self) -> bool:
        """Check system requirements and dependencies"""
        try:
            if self.logger:
                self.logger.info("🔍 Checking system requirements...")
            
            # Check Python version
            if sys.version_info < (3, 7):
                if self.logger:
                    self.logger.error("❌ Python 3.7+ required")
                else:
                    print("❌ Python 3.7+ required")
                return False
            
            # Check required packages
            required_packages = [
                'psutil', 'requests', 'yaml', 'socketio',
                'watchdog', 'win32api', 'win32gui', 'win32con'
            ]
            
            missing_packages = []
            for package in required_packages:
                try:
                    __import__(package)
                except ImportError:
                    missing_packages.append(package)
            
            if missing_packages:
                error_msg = f"❌ Missing required packages: {', '.join(missing_packages)}"
                if self.logger:
                    self.logger.error(error_msg)
                    self.logger.info("💡 Run: pip install -r requirements.txt")
                else:
                    print(error_msg)
                    print("💡 Run: pip install -r requirements.txt")
                return False
            
            # Check Windows version
            if not sys.platform.startswith('win'):
                error_msg = "❌ This agent is designed for Windows only"
                if self.logger:
                    self.logger.error(error_msg)
                else:
                    print(error_msg)
                return False
            
            if self.logger:
                self.logger.info("✅ All requirements satisfied")
            else:
                print("✅ All requirements satisfied")
            return True
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Error checking requirements: {e}")
            else:
                print(f"❌ Error checking requirements: {e}")
            return False
    
    def create_directories(self):
        """Create necessary directories"""
        try:
            directories = [
                "logs", "data", "data/cache", "data/temp", 
                "data/quarantine", "resources", "resources/icons",
                "config"
            ]
            
            for directory in directories:
                Path(directory).mkdir(parents=True, exist_ok=True)
            
            if self.logger:
                self.logger.info("✅ Directory structure verified")
            else:
                print("✅ Directory structure verified")
        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Error creating directories: {e}")
            else:
                print(f"❌ Error creating directories: {e}")
    
    def start_agent(self, debug=False, no_ui=False, server_url=None, config_file=None):
        """Start the EDR agent with enhanced features"""
        try:
            # Load configuration
            config_file = config_file if config_file else 'agent_config.yaml'
            config = AgentConfig(config_file)
            if server_url:
                config.SERVER_URL = server_url
            
            # Create enhanced agent
            self.agent = EnhancedEDRAgent(config)
            
            # Start agent
            if not self.agent.start():
                self.logger.error("❌ Failed to start enhanced agent")
                return False
            
            self.running = True
            self.logger.info("✅ Enhanced EDR Agent started successfully")
            
            # Start system tray if not in console mode
            if not no_ui:
                self._start_system_tray()
            
            # FIXED: Start main application loop to keep alive
            self._start_main_loop(no_ui)
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error starting enhanced agent: {e}")
            return False
    
    def _start_system_tray(self):
        """Start system tray icon with better error handling"""
        try:
            from ui.tray_icon import SystemTrayIcon
            self.tray_icon = SystemTrayIcon(self.agent)
            # FIXED: Start tray in separate thread to avoid blocking
            tray_thread = threading.Thread(target=self.tray_icon.start, daemon=True)
            tray_thread.start()
            if self.logger:
                self.logger.info("✅ System tray icon started")
        except ImportError:
            if self.logger:
                self.logger.warning("⚠️ System tray not available (missing dependencies)")
            else:
                print("⚠️ System tray not available (missing dependencies)")
        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Failed to start system tray: {e}")
            else:
                print(f"❌ Failed to start system tray: {e}")
            # Don't fail the entire agent if tray fails
            self.tray_icon = None
    
    def _start_main_loop(self, no_ui=False):
        """FIXED: Start main application loop to keep app alive"""
        try:
            self.main_loop_running = True
            self.app_lifecycle_event.clear()
            
            if no_ui:
                self.logger.info("🖥️ Starting console mode main loop...")
                print("\n" + "="*60)
                print("🖥️  EDR WINDOWS AGENT - CONSOLE MODE")
                print("="*60)
                print("✅ Agent is running and monitoring your system")
                print("📊 Check logs in 'logs/' directory for details")
                print("🔗 Connection status will be logged periodically")
                print("⚠️  Press Ctrl+C to stop the agent")
                print("="*60 + "\n")
                
                self._run_console_main_loop()
            else:
                self.logger.info("🎮 Starting GUI mode main loop...")
                print("✅ EDR Agent is running with system tray icon")
                print("🔍 Right-click the tray icon for options")
                print("⚠️  Press Ctrl+C to stop the agent")
                
                self._run_gui_main_loop()
                        
        except KeyboardInterrupt:
            self.logger.info("⚠️ Received keyboard interrupt in main loop")
        except Exception as e:
            self.logger.error(f"❌ Error in main loop: {e}")
        finally:
            self.main_loop_running = False
    
    def _run_console_main_loop(self):
        """FIXED: Console mode main loop with proper lifecycle"""
        last_status_time = 0
        status_interval = 300  # 5 minutes
        
        while self.running and not self.shutdown_event.is_set():
            try:
                current_time = time.time()
                
                # Show periodic status updates
                if current_time - last_status_time > status_interval:
                    self._show_console_status()
                    last_status_time = current_time
                
                # FIXED: Keep main thread alive with interruptible sleep
                if self.shutdown_event.wait(timeout=1):
                    break
                    
                # Check agent health
                if self.agent and hasattr(self.agent, 'get_status'):
                    try:
                        status = self.agent.get_status()
                        if not status.get('running', False):
                            self.logger.warning("⚠️ Agent health check failed")
                            break
                    except Exception as e:
                        self.logger.debug(f"Health check error: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error in console main loop: {e}")
                time.sleep(1)
    
    def _run_gui_main_loop(self):
        """FIXED: GUI mode main loop with proper lifecycle"""
        while self.running and not self.shutdown_event.is_set():
            try:
                # FIXED: Keep main thread alive for GUI
                if self.shutdown_event.wait(timeout=1):
                    break
                
                # Periodic health check
                if self.agent and hasattr(self.agent, 'get_status'):
                    try:
                        status = self.agent.get_status()
                        if not status.get('running', False):
                            self.logger.warning("⚠️ Agent health check failed")
                            break
                            
                        # Update tray icon status
                        if self.tray_icon:
                            self.tray_icon.update_icon_status(status)
                    except Exception as e:
                        self.logger.debug(f"Health check error: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error in GUI main loop: {e}")
                time.sleep(1)
    
    def _show_console_status(self):
        """Show status information in console"""
        try:
            if not self.agent:
                return
                
            status = self.agent.get_status()
            
            print("\n" + "="*50)
            print(f"📊 EDR AGENT STATUS - {datetime.now().strftime('%H:%M:%S')}")
            print("="*50)
            
            # Connection status
            connected = status.get('connected', False)
            print(f"🔗 Server Connection: {'✅ Connected' if connected else '❌ Disconnected'}")
            
            # Monitoring status
            monitors = status.get('monitors', {})
            print(f"👁️  Process Monitor: {'✅ Active' if monitors.get('process') else '❌ Inactive'}")
            print(f"📁 File Monitor: {'✅ Active' if monitors.get('file') else '❌ Inactive'}")
            print(f"🌐 Network Monitor: {'✅ Active' if monitors.get('network') else '❌ Inactive'}")
            
            # Statistics
            stats = status.get('statistics', {})
            print(f"📈 Events Processed: {stats.get('events_processed', 0)}")
            print(f"🚨 Alerts Generated: {stats.get('alerts_generated', 0)}")
            
            # System metrics
            sys_info = status.get('system_info', {})
            print(f"💾 Memory Usage: {sys_info.get('memory_usage', 0):.1f}%")
            print(f"🔄 CPU Usage: {sys_info.get('cpu_usage', 0):.1f}%")
            
            print("="*50)
        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Error showing console status: {e}")
    
    def stop_agent(self):
        """Stop the EDR agent gracefully - FIXED"""
        if self.graceful_shutdown:
            return  # Already shutting down
            
        self.graceful_shutdown = True
        
        try:
            if self.logger:
                self.logger.info("🛑 Starting graceful shutdown...")
            else:
                print("🛑 Starting graceful shutdown...")
            
            # FIXED: Set shutdown flags first
            self.running = False
            self.main_loop_running = False
            self.shutdown_event.set()
            self.app_lifecycle_event.set()
            
            # Stop tray icon first (in separate thread to avoid blocking)
            if self.tray_icon:
                try:
                    def stop_tray():
                        try:
                            self.tray_icon.stop()
                        except Exception as e:
                            if self.logger:
                                self.logger.debug(f"Tray stop error: {e}")
                    
                    tray_stop_thread = threading.Thread(target=stop_tray, daemon=True)
                    tray_stop_thread.start()
                    tray_stop_thread.join(timeout=2.0)  # 2 second timeout
                    
                    if self.logger:
                        self.logger.info("✅ System tray stopped")
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"Tray icon stop warning: {e}")
                finally:
                    self.tray_icon = None
            
            # Stop agent core
            if self.agent:
                try:
                    self.agent.stop()
                    if self.logger:
                        self.logger.info("✅ Agent core stopped")
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"❌ Error stopping agent: {e}")
            
            if self.logger:
                self.logger.info("✅ EDR Agent stopped successfully")
            else:
                print("✅ EDR Agent stopped successfully")
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Error in graceful shutdown: {e}")
            else:
                print(f"❌ Error stopping agent: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully - FIXED"""
        signal_names = {
            signal.SIGINT: "SIGINT (Ctrl+C)",
            signal.SIGTERM: "SIGTERM",
        }
        
        if hasattr(signal, 'SIGBREAK'):
            signal_names[signal.SIGBREAK] = "SIGBREAK"
        
        signal_name = signal_names.get(signum, f"Signal {signum}")
        
        try:
            if self.logger:
                self.logger.info(f"📡 Received {signal_name}, initiating graceful shutdown...")
            else:
                print(f"\n📡 Received {signal_name}, shutting down...")
            
            # Stop the agent gracefully
            self.stop_agent()
            
            # Give some time for cleanup
            time.sleep(0.5)
            
            if self.logger:
                self.logger.info("👋 Graceful shutdown completed")
            else:
                print("👋 Shutdown completed")
        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Error in shutdown: {e}")
            else:
                print(f"❌ Error in shutdown: {e}")
        finally:
            # Force exit if needed
            sys.exit(0)
    
    def install_service(self):
        """Install as Windows service"""
        try:
            if self.logger:
                self.logger.info("📦 Installing EDR Agent as Windows service...")
            
            from installer.service import install_service
            success = install_service()
            
            if success:
                if self.logger:
                    self.logger.info("✅ Service installed successfully")
                print("✅ EDR Agent installed as Windows service")
                print("🔧 Use 'sc start EDRAgent' to start the service")
                return True
            else:
                if self.logger:
                    self.logger.error("❌ Service installation failed")
                print("❌ Service installation failed")
                return False
        except ImportError:
            error_msg = "❌ Service installer not available"
            if self.logger:
                self.logger.error(error_msg)
            print(error_msg)
            return False
        except Exception as e:
            error_msg = f"❌ Service installation error: {e}"
            if self.logger:
                self.logger.error(error_msg)
            print(error_msg)
            return False
    
    def uninstall_service(self):
        """Uninstall Windows service"""
        try:
            if self.logger:
                self.logger.info("🗑️ Uninstalling EDR Agent Windows service...")
            
            from installer.service import uninstall_service
            success = uninstall_service()
            
            if success:
                if self.logger:
                    self.logger.info("✅ Service uninstalled successfully")
                print("✅ EDR Agent service uninstalled successfully")
                return True
            else:
                if self.logger:
                    self.logger.error("❌ Service uninstallation failed")
                print("❌ Service uninstallation failed")
                return False
        except ImportError:
            error_msg = "❌ Service installer not available"
            if self.logger:
                self.logger.error(error_msg)
            print(error_msg)
            return False
        except Exception as e:
            error_msg = f"❌ Service uninstallation error: {e}"
            if self.logger:
                self.logger.error(error_msg)
            print(error_msg)
            return False
    
    def run_service_mode(self):
        """Run in Windows service mode"""
        try:
            # This is called when running as a Windows service
            if self.logger:
                self.logger.info("🔧 Starting in Windows service mode...")
            
            # Start agent without UI
            success = self.start_agent(debug=False, no_ui=True)
            
            return success
        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Error in service mode: {e}")
            return False
    
    def get_agent_status(self) -> dict:
        """Get current agent status"""
        try:
            if self.agent:
                return self.agent.get_status()
            else:
                return {
                    'running': False,
                    'error': 'Agent not initialized'
                }
        except Exception as e:
            return {
                'running': False,
                'error': str(e)
            }
    
    def restart_agent(self):
        """Restart the agent"""
        try:
            if self.logger:
                self.logger.info("🔄 Restarting EDR Agent...")
            
            # Stop current agent
            if self.agent:
                self.agent.stop()
                time.sleep(2)
            
            # Create new agent instance
            config = self.agent.config if self.agent else AgentConfig()
            self.agent = EDRAgent(config)
            
            # Start agent
            success = self.agent.start()
            
            if success:
                if self.logger:
                    self.logger.info("✅ Agent restarted successfully")
                else:
                    print("✅ Agent restarted successfully")
            else:
                if self.logger:
                    self.logger.error("❌ Agent restart failed")
                else:
                    print("❌ Agent restart failed")
            
            return success
        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Error restarting agent: {e}")
            else:
                print(f"❌ Error restarting agent: {e}")
            return False

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='EDR Windows Agent - Endpoint Detection and Response',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Run with default settings
  python main.py --debug            # Run with debug logging
  python main.py --no-ui            # Run without system tray
  python main.py --server http://server:5000  # Use custom server
  python main.py --install          # Install as Windows service
  python main.py --uninstall        # Remove Windows service
  python main.py --check            # Check requirements and configuration
        """
    )
    
    # Basic options
    parser.add_argument('--debug', action='store_true',
                      help='Enable debug logging')
    parser.add_argument('--no-ui', action='store_true',
                      help='Run without UI (console mode only)')
    parser.add_argument('--server', type=str, metavar='URL',
                      help='EDR Server URL (overrides config)')
    parser.add_argument('--config', type=str, metavar='FILE',
                      help='Configuration file path')
    parser.add_argument('--log-file', type=str, metavar='FILE',
                      help='Log file path')
    
    # Service management
    parser.add_argument('--install', action='store_true',
                      help='Install as Windows service')
    parser.add_argument('--uninstall', action='store_true',
                      help='Uninstall Windows service')
    parser.add_argument('--service', action='store_true',
                      help='Run as Windows service (internal use)')
    
    # Utility options
    parser.add_argument('--check', action='store_true',
                      help='Check requirements and configuration')
    parser.add_argument('--status', action='store_true',
                      help='Show agent status and exit')
    parser.add_argument('--version', action='version', version='EDR Agent 2.0.0')
    
    return parser.parse_args()

def main():
    """FIXED: Main entry point with proper application lifecycle"""
    # Print banner
    print("\n🖥️ EDR Windows Agent v2.0.0")
    print("=" * 50)
    print("🛡️  Endpoint Detection and Response System")
    print("🏢 Advanced threat monitoring and response")
    print("=" * 50)
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Create main application instance
    app = EDRAgentMain()
    
    try:
        # Setup logging first
        if not app.setup_logging(debug=args.debug, log_file=args.log_file):
            print("❌ Failed to setup logging system")
            return 1
        
        app.logger.info("🚀 EDR Windows Agent starting...")
        app.logger.info(f"📋 Arguments: {vars(args)}")
        
        # Check requirements
        if not app.check_requirements():
            app.logger.error("❌ System requirements not met")
            return 1
        
        if args.check:
            print("✅ All requirements satisfied")
            print("✅ System check completed successfully")
            return 0
        
        # Create necessary directories
        app.create_directories()
        
        # Handle service operations
        if args.install:
            if not WindowsUtils.is_admin():
                print("❌ Administrator privileges required for service installation")
                return 1
            return 0 if app.install_service() else 1
        
        if args.uninstall:
            if not WindowsUtils.is_admin():
                print("❌ Administrator privileges required for service removal")
                return 1
            return 0 if app.uninstall_service() else 1
        
        if args.service:
            # Running as Windows service
            return 0 if app.run_service_mode() else 1
        
        # Handle status request
        if args.status:
            status = app.get_agent_status()
            print(f"Agent Status: {status}")
            return 0
        
        # Check admin privileges warning
        if not WindowsUtils.is_admin():
            app.logger.warning("⚠️ Running without administrator privileges")
            app.logger.warning("💡 Some monitoring features may be limited")
            print("⚠️ Warning: Running without administrator privileges")
            print("💡 Some monitoring features may be limited")
            
            # Offer to elevate privileges
            if not args.no_ui:
                try:
                    import win32gui
                    import win32con
                    result = win32gui.MessageBox(0, 
                        "EDR Agent works best with administrator privileges.\n\n" +
                        "Some monitoring features may be limited without admin rights.\n\n" +
                        "Continue anyway?",
                        "EDR Agent - Privilege Warning", 
                        win32con.MB_YESNO | win32con.MB_ICONWARNING)
                    
                    if result == win32con.IDNO:
                        app.logger.info("👤 User chose not to continue without admin rights")
                        return 0
                        
                except ImportError:
                    # Ask via console if GUI not available
                    response = input("Continue without admin privileges? (y/N): ")
                    if response.lower() not in ['y', 'yes']:
                        return 0
                except Exception as e:
                    app.logger.debug(f"MessageBox error: {e}")
                    # Fall back to console input
                    response = input("Continue without admin privileges? (y/N): ")
                    if response.lower() not in ['y', 'yes']:
                        return 0
        
#!/usr/bin/env python3
"""
EDR Windows Agent - Main Entry Point (FIXED APPLICATION LIFECYCLE)
Fixed main loop to keep application alive
"""

import sys
import os
import argparse
import logging
import signal
import time
import threading
from pathlib import Path
from datetime import datetime

# Add current directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import modules
from config import AgentConfig
from core.agent import EDRAgent
from core.enhanced_agent_core import EnhancedEDRAgent
from utils.windows_utils import WindowsUtils

class EDRAgentMain:
    """Main application class for EDR Agent - FIXED"""
    
    def __init__(self):
        """Initialize main application"""
        self.agent = None
        self.tray_icon = None
        self.running = False
        self.shutdown_event = threading.Event()
        self.logger = None
        self.graceful_shutdown = False
        
        # FIXED: Add application lifecycle control
        self.app_lifecycle_event = threading.Event()
        self.main_loop_running = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # For Windows service compatibility
        if hasattr(signal, 'SIGBREAK'):
            signal.signal(signal.SIGBREAK, self.signal_handler)
    
    def setup_logging(self, debug=False, log_file=None):
        """Setup comprehensive logging with better error handling"""
        try:
            # Create logs directory
            logs_dir = Path("logs")
            logs_dir.mkdir(exist_ok=True)
            
            # Determine log level
            log_level = logging.DEBUG if debug else logging.INFO
            
            # Create formatters
            detailed_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
            )
            simple_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            
            # Setup root logger
            root_logger = logging.getLogger()
            root_logger.setLevel(log_level)
            
            # Remove existing handlers
            for handler in root_logger.handlers[:]:
                try:
                    handler.close()
                    root_logger.removeHandler(handler)
                except:
                    pass
            
            # File handler for detailed logs
            if not log_file:
                log_file = logs_dir / f"agent_{datetime.now().strftime('%Y%m%d')}.log"
            
            try:
                file_handler = logging.FileHandler(log_file, encoding='utf-8')
                file_handler.setLevel(log_level)
                file_handler.setFormatter(detailed_formatter)
                root_logger.addHandler(file_handler)
        except Exception as e:
                print(f"Warning: Could not create file handler: {e}")
            
            # Console handler for immediate feedback
            try:
                console_handler = logging.StreamHandler(sys.stdout)
                console_handler.setLevel(logging.INFO if not debug else logging.DEBUG)
                console_handler.setFormatter(simple_formatter)
                root_logger.addHandler(console_handler)
        except Exception as e:
                print(f"Warning: Could not create console handler: {e}")
            
            # Error file handler
            try:
                error_handler = logging.FileHandler(logs_dir / "errors.log", encoding='utf-8')
                error_handler.setLevel(logging.ERROR)
                error_handler.setFormatter(detailed_formatter)
                root_logger.addHandler(error_handler)
        except Exception as e:
                print(f"Warning: Could not create error handler: {e}")
            
            # Create main logger
            self.logger = logging.getLogger(__name__)
            self.logger.info("✅ Logging system initialized")
            self.logger.info(f"📁 Log file: {log_file}")
            
            # Log system information
            self._log_system_info()
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to setup logging: {e}")
            # Create basic console logger as fallback
            try:
                logging.basicConfig(
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)]
                )
                self.logger = logging.getLogger(__name__)
                self.logger.error(f"Fallback logging active due to error: {e}")
                return True
            except:
                return False
    
    def _log_system_info(self):
        """Log system information at startup"""
        try:
            import platform
            import psutil
            
            self.logger.info("=" * 50)
            self.logger.info("EDR WINDOWS AGENT STARTUP")
            self.logger.info("=" * 50)
            self.logger.info(f"🖥️ System: {platform.platform()}")
            self.logger.info(f"🏠 Hostname: {platform.node()}")
            self.logger.info(f"👤 User: {os.environ.get('USERNAME', 'Unknown')}")
            self.logger.info(f"🔧 Python: {sys.version}")
            self.logger.info(f"📁 Working Directory: {os.getcwd()}")
            self.logger.info(f"🔑 Admin Rights: {WindowsUtils.is_admin()}")
            
            # Memory and CPU info
            try:
                memory = psutil.virtual_memory()
                self.logger.info(f"💾 Memory: {memory.total // (1024**3)}GB total, {memory.percent}% used")
                self.logger.info(f"🔄 CPU: {psutil.cpu_count()} cores, {psutil.cpu_percent()}% usage")
            except Exception as e:
                self.logger.warning(f"Could not get system metrics: {e}")
            
            self.logger.info("=" * 50)
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error logging system info: {e}")
    
    def check_requirements(self) -> bool:
        """Check system requirements and dependencies"""
        try:
            if self.logger:
                self.logger.info("🔍 Checking system requirements...")
            
            # Check Python version
            if sys.version_info < (3, 7):
                if self.logger:
                    self.logger.error("❌ Python 3.7+ required")
                else:
                    print("❌ Python 3.7+ required")
                return False
            
            # Check required packages
            required_packages = [
                'psutil', 'requests', 'yaml', 'socketio',
                'watchdog', 'win32api', 'win32gui', 'win32con'
            ]
            
            missing_packages = []
            for package in required_packages:
                try:
                    __import__(package)
                except ImportError:
                    missing_packages.append(package)
            
            if missing_packages:
                error_msg = f"❌ Missing required packages: {', '.join(missing_packages)}"
                if self.logger:
                    self.logger.error(error_msg)
                    self.logger.info("💡 Run: pip install -r requirements.txt")
                else:
                    print(error_msg)
                    print("💡 Run: pip install -r requirements.txt")
                return False
            
            # Check Windows version
            if not sys.platform.startswith('win'):
                error_msg = "❌ This agent is designed for Windows only"
                if self.logger:
                    self.logger.error(error_msg)
                else:
                    print(error_msg)
                return False
            
            if self.logger:
                self.logger.info("✅ All requirements satisfied")
            else:
                print("✅ All requirements satisfied")
            return True
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Error checking requirements: {e}")
            else:
                print(f"❌ Error checking requirements: {e}")
            return False
    
    def create_directories(self):
        """Create necessary directories"""
        try:
            directories = [
                "logs", "data", "data/cache", "data/temp", 
                "data/quarantine", "resources", "resources/icons",
                "config"
            ]
            
            for directory in directories:
                Path(directory).mkdir(parents=True, exist_ok=True)
            
            if self.logger:
                self.logger.info("✅ Directory structure verified")
            else:
                print("✅ Directory structure verified")
    except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Error creating directories: {e}")
            else:
                print(f"❌ Error creating directories: {e}")
    
    def start_agent(self, debug=False, no_ui=False, server_url=None, config_file=None):
        """Start the EDR agent with enhanced features"""
        try:
            # Load configuration
            config_file = config_file if config_file else 'agent_config.yaml'
            config = AgentConfig(config_file)
            if server_url:
                config.SERVER_URL = server_url
            
            # Create enhanced agent
            self.agent = EnhancedEDRAgent(config)
            
            # Start agent
            if not self.agent.start():
                self.logger.error("❌ Failed to start enhanced agent")
                return False
            
            self.running = True
            self.logger.info("✅ Enhanced EDR Agent started successfully")
            
            # Start system tray if not in console mode
            if not no_ui:
                self._start_system_tray()
            
            # FIXED: Start main application loop to keep alive
            self._start_main_loop(no_ui)
            
            return True
            
    except Exception as e:
            self.logger.error(f"❌ Error starting enhanced agent: {e}")
            return False
    
    def _start_system_tray(self):
        """Start system tray icon with better error handling"""
        try:
            from ui.tray_icon import SystemTrayIcon
            self.tray_icon = SystemTrayIcon(self.agent)
            # FIXED: Start tray in separate thread to avoid blocking
            tray_thread = threading.Thread(target=self.tray_icon.start, daemon=True)
            tray_thread.start()
            if self.logger:
            self.logger.info("✅ System tray icon started")
        except ImportError:
            if self.logger:
            self.logger.warning("⚠️ System tray not available (missing dependencies)")
            else:
                print("⚠️ System tray not available (missing dependencies)")
        except Exception as e:
            if self.logger:
            self.logger.error(f"❌ Failed to start system tray: {e}")
            else:
                print(f"❌ Failed to start system tray: {e}")
            # Don't fail the entire agent if tray fails
            self.tray_icon = None
    
    def _start_main_loop(self, no_ui=False):
        """FIXED: Start main application loop to keep app alive"""
        try:
            self.main_loop_running = True
            self.app_lifecycle_event.clear()
            
            if no_ui:
                self.logger.info("🖥️ Starting console mode main loop...")
                print("\n" + "="*60)
                print("🖥️  EDR WINDOWS AGENT - CONSOLE MODE")
                print("="*60)
                print("✅ Agent is running and monitoring your system")
                print("📊 Check logs in 'logs/' directory for details")
                print("🔗 Connection status will be logged periodically")
                print("⚠️  Press Ctrl+C to stop the agent")
                print("="*60 + "\n")
                
                self._run_console_main_loop()
            else:
                self.logger.info("🎮 Starting GUI mode main loop...")
                print("✅ EDR Agent is running with system tray icon")
                print("🔍 Right-click the tray icon for options")
                print("⚠️  Press Ctrl+C to stop the agent")
                
                self._run_gui_main_loop()
                        
        except KeyboardInterrupt:
            self.logger.info("⚠️ Received keyboard interrupt in main loop")
        except Exception as e:
            self.logger.error(f"❌ Error in main loop: {e}")
        finally:
            self.main_loop_running = False
    
    def _run_console_main_loop(self):
        """FIXED: Console mode main loop with proper lifecycle"""
            last_status_time = 0
            status_interval = 300  # 5 minutes
            
            while self.running and not self.shutdown_event.is_set():
            try:
                current_time = time.time()
                
                # Show periodic status updates
                if current_time - last_status_time > status_interval:
                    self._show_console_status()
                    last_status_time = current_time
                
                # FIXED: Keep main thread alive with interruptible sleep
                if self.shutdown_event.wait(timeout=1):
                    break
                    
                # Check agent health
                if self.agent and hasattr(self.agent, 'get_status'):
                    try:
                        status = self.agent.get_status()
                        if not status.get('running', False):
                            self.logger.warning("⚠️ Agent health check failed")
                            break
                    except Exception as e:
                        self.logger.debug(f"Health check error: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error in console main loop: {e}")
                time.sleep(1)
    
    def _run_gui_main_loop(self):
        """FIXED: GUI mode main loop with proper lifecycle"""
        while self.running and not self.shutdown_event.is_set():
            try:
                # FIXED: Keep main thread alive for GUI
                if self.shutdown_event.wait(timeout=1):
                    break
                
                # Periodic health check
                if self.agent and hasattr(self.agent, 'get_status'):
                    try:
                        status = self.agent.get_status()
                        if not status.get('running', False):
                            self.logger.warning("⚠️ Agent health check failed")
                            break
                            
                        # Update tray icon status
                        if self.tray_icon:
                            self.tray_icon.update_icon_status(status)
                    except Exception as e:
                        self.logger.debug(f"Health check error: {e}")
                        
            except Exception as e:
                self.logger.error(f"Error in GUI main loop: {e}")
                time.sleep(1)
    
    def _show_console_status(self):
        """Show status information in console"""
        try:
            if not self.agent:
                return
                
            status = self.agent.get_status()
            
            print("\n" + "="*50)
            print(f"📊 EDR AGENT STATUS - {datetime.now().strftime('%H:%M:%S')}")
            print("="*50)
            
            # Connection status
            connected = status.get('connected', False)
            print(f"🔗 Server Connection: {'✅ Connected' if connected else '❌ Disconnected'}")
            
            # Monitoring status
            monitors = status.get('monitors', {})
            print(f"👁️  Process Monitor: {'✅ Active' if monitors.get('process') else '❌ Inactive'}")
            print(f"📁 File Monitor: {'✅ Active' if monitors.get('file') else '❌ Inactive'}")
            print(f"🌐 Network Monitor: {'✅ Active' if monitors.get('network') else '❌ Inactive'}")
            
            # Statistics
            stats = status.get('statistics', {})
            print(f"📈 Events Processed: {stats.get('events_processed', 0)}")
            print(f"🚨 Alerts Generated: {stats.get('alerts_generated', 0)}")
            
            # System metrics
            sys_info = status.get('system_info', {})
            print(f"💾 Memory Usage: {sys_info.get('memory_usage', 0):.1f}%")
            print(f"🔄 CPU Usage: {sys_info.get('cpu_usage', 0):.1f}%")
            
            print("="*50)
        except Exception as e:
            if self.logger:
            self.logger.error(f"❌ Error showing console status: {e}")
    
    def stop_agent(self):
        """Stop the EDR agent gracefully - FIXED"""
        if self.graceful_shutdown:
            return  # Already shutting down
            
        self.graceful_shutdown = True
        
        try:
            if self.logger:
                self.logger.info("🛑 Starting graceful shutdown...")
            else:
                print("🛑 Starting graceful shutdown...")
            
            # FIXED: Set shutdown flags first
            self.running = False
            self.main_loop_running = False
            self.shutdown_event.set()
            self.app_lifecycle_event.set()
            
            # Stop tray icon first (in separate thread to avoid blocking)
            if self.tray_icon:
                try:
                    def stop_tray():
                try:
                    self.tray_icon.stop()
                        except Exception as e:
                            if self.logger:
                                self.logger.debug(f"Tray stop error: {e}")
                    
                    tray_stop_thread = threading.Thread(target=stop_tray, daemon=True)
                    tray_stop_thread.start()
                    tray_stop_thread.join(timeout=2.0)  # 2 second timeout
                    
                    if self.logger:
                    self.logger.info("✅ System tray stopped")
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"Tray icon stop warning: {e}")
                finally:
                    self.tray_icon = None
            
            # Stop agent core
            if self.agent:
                try:
                    self.agent.stop()
                    if self.logger:
                    self.logger.info("✅ Agent core stopped")
                except Exception as e:
                    if self.logger:
                    self.logger.error(f"❌ Error stopping agent: {e}")
            
            if self.logger:
            self.logger.info("✅ EDR Agent stopped successfully")
            else:
                print("✅ EDR Agent stopped successfully")
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Error in graceful shutdown: {e}")
            else:
                print(f"❌ Error stopping agent: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully - FIXED"""
        signal_names = {
            signal.SIGINT: "SIGINT (Ctrl+C)",
            signal.SIGTERM: "SIGTERM",
        }
        
        if hasattr(signal, 'SIGBREAK'):
            signal_names[signal.SIGBREAK] = "SIGBREAK"
        
        signal_name = signal_names.get(signum, f"Signal {signum}")
        
        try:
        if self.logger:
            self.logger.info(f"📡 Received {signal_name}, initiating graceful shutdown...")
        else:
            print(f"\n📡 Received {signal_name}, shutting down...")
        
            # Stop the agent gracefully
            self.stop_agent()
            
            # Give some time for cleanup
            time.sleep(0.5)
            
            if self.logger:
                self.logger.info("👋 Graceful shutdown completed")
            else:
                print("👋 Shutdown completed")
        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Error in shutdown: {e}")
            else:
                print(f"❌ Error in shutdown: {e}")
        finally:
            # Force exit if needed
            sys.exit(0)
    
    def install_service(self):
        """Install as Windows service"""
        try:
            if self.logger:
            self.logger.info("📦 Installing EDR Agent as Windows service...")
            
            from installer.service import install_service
            success = install_service()
            
            if success:
                if self.logger:
                self.logger.info("✅ Service installed successfully")
                print("✅ EDR Agent installed as Windows service")
                print("🔧 Use 'sc start EDRAgent' to start the service")
                return True
            else:
                if self.logger:
                self.logger.error("❌ Service installation failed")
                print("❌ Service installation failed")
                return False
        except ImportError:
            error_msg = "❌ Service installer not available"
            if self.logger:
                self.logger.error(error_msg)
            print(error_msg)
            return False
        except Exception as e:
            error_msg = f"❌ Service installation error: {e}"
            if self.logger:
                self.logger.error(error_msg)
            print(error_msg)
            return False
    
    def uninstall_service(self):
        """Uninstall Windows service"""
        try:
            if self.logger:
            self.logger.info("🗑️ Uninstalling EDR Agent Windows service...")
            
            from installer.service import uninstall_service
            success = uninstall_service()
            
            if success:
                if self.logger:
                self.logger.info("✅ Service uninstalled successfully")
                print("✅ EDR Agent service uninstalled successfully")
                return True
            else:
                if self.logger:
                self.logger.error("❌ Service uninstallation failed")
                print("❌ Service uninstallation failed")
                return False
        except ImportError:
            error_msg = "❌ Service installer not available"
            if self.logger:
                self.logger.error(error_msg)
            print(error_msg)
            return False
        except Exception as e:
            error_msg = f"❌ Service uninstallation error: {e}"
            if self.logger:
                self.logger.error(error_msg)
            print(error_msg)
            return False
    
    def run_service_mode(self):
        """Run in Windows service mode"""
        try:
            # This is called when running as a Windows service
            if self.logger:
            self.logger.info("🔧 Starting in Windows service mode...")
            
            # Start agent without UI
            success = self.start_agent(debug=False, no_ui=True)
            
            return success
        except Exception as e:
            if self.logger:
            self.logger.error(f"❌ Error in service mode: {e}")
            return False
    
    def get_agent_status(self) -> dict:
        """Get current agent status"""
        try:
            if self.agent:
                return self.agent.get_status()
            else:
                return {
                    'running': False,
                    'error': 'Agent not initialized'
                }
        except Exception as e:
            return {
                'running': False,
                'error': str(e)
            }
    
    def restart_agent(self):
        """Restart the agent"""
        try:
            if self.logger:
            self.logger.info("🔄 Restarting EDR Agent...")
            
            # Stop current agent
            if self.agent:
                self.agent.stop()
                time.sleep(2)
            
            # Create new agent instance
            config = self.agent.config if self.agent else AgentConfig()
            self.agent = EDRAgent(config)
            
            # Start agent
            success = self.agent.start()
            
            if success:
                if self.logger:
                self.logger.info("✅ Agent restarted successfully")
            else:
                if self.logger:
                self.logger.error("❌ Agent restart failed")
            
            return success
        except Exception as e:
            if self.logger:
            self.logger.error(f"❌ Error restarting agent: {e}")
            return False

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='EDR Windows Agent - Endpoint Detection and Response',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Run with default settings
  python main.py --debug            # Run with debug logging
  python main.py --no-ui            # Run without system tray
  python main.py --server http://server:5000  # Use custom server
  python main.py --install          # Install as Windows service
  python main.py --uninstall        # Remove Windows service
  python main.py --check            # Check requirements and configuration
        """
    )
    
    # Basic options
    parser.add_argument('--debug', action='store_true',
                      help='Enable debug logging')
    parser.add_argument('--no-ui', action='store_true',
                      help='Run without UI (console mode only)')
    parser.add_argument('--server', type=str, metavar='URL',
                      help='EDR Server URL (overrides config)')
    parser.add_argument('--config', type=str, metavar='FILE',
                      help='Configuration file path')
    parser.add_argument('--log-file', type=str, metavar='FILE',
                      help='Log file path')
    
    # Service management
    parser.add_argument('--install', action='store_true',
                      help='Install as Windows service')
    parser.add_argument('--uninstall', action='store_true',
                      help='Uninstall Windows service')
    parser.add_argument('--service', action='store_true',
                      help='Run as Windows service (internal use)')
    
    # Utility options
    parser.add_argument('--check', action='store_true',
                      help='Check requirements and configuration')
    parser.add_argument('--status', action='store_true',
                      help='Show agent status and exit')
    parser.add_argument('--version', action='version', version='EDR Agent 2.0.0')
    
    return parser.parse_args()

def main():
    """FIXED: Main entry point with proper application lifecycle"""
    # Print banner
    print("\n🖥️ EDR Windows Agent v2.0.0")
    print("=" * 50)
    print("🛡️  Endpoint Detection and Response System")
    print("🏢 Advanced threat monitoring and response")
    print("=" * 50)
    
        # Parse command line arguments
        args = parse_arguments()
        
        # Create main application instance
        app = EDRAgentMain()
        
    try:
        # Setup logging first
        if not app.setup_logging(debug=args.debug, log_file=args.log_file):
            print("❌ Failed to setup logging system")
            return 1
        
        app.logger.info("🚀 EDR Windows Agent starting...")
        app.logger.info(f"📋 Arguments: {vars(args)}")
        
        # Check requirements
        if not app.check_requirements():
            app.logger.error("❌ System requirements not met")
            return 1
        
        if args.check:
            print("✅ All requirements satisfied")
            print("✅ System check completed successfully")
            return 0
        
        # Create necessary directories
        app.create_directories()
        
        # Handle service operations
        if args.install:
            if not WindowsUtils.is_admin():
                print("❌ Administrator privileges required for service installation")
                return 1
            return 0 if app.install_service() else 1
        
        if args.uninstall:
            if not WindowsUtils.is_admin():
                print("❌ Administrator privileges required for service removal")
                return 1
            return 0 if app.uninstall_service() else 1
        
        if args.service:
            # Running as Windows service
            return 0 if app.run_service_mode() else 1
        
        # Handle status request
        if args.status:
            status = app.get_agent_status()
            print(f"Agent Status: {status}")
            return 0
        
        # Check admin privileges warning
        if not WindowsUtils.is_admin():
            app.logger.warning("⚠️ Running without administrator privileges")
            app.logger.warning("💡 Some monitoring features may be limited")
            print("⚠️ Warning: Running without administrator privileges")
            print("💡 Some monitoring features may be limited")
            
            # Offer to elevate privileges
            if not args.no_ui:
                try:
                    import win32gui
                    import win32con
                    result = win32gui.MessageBox(0, 
                        "EDR Agent works best with administrator privileges.\n\n" +
                        "Some monitoring features may be limited without admin rights.\n\n" +
                        "Continue anyway?",
                        "EDR Agent - Privilege Warning", 
                        win32con.MB_YESNO | win32con.MB_ICONWARNING)
                    
                    if result == win32con.IDNO:
                        app.logger.info("👤 User chose not to continue without admin rights")
                        return 0
                        
                except ImportError:
                    # Ask via console if GUI not available
                    response = input("Continue without admin privileges? (y/N): ")
                    if response.lower() not in ['y', 'yes']:
                        return 0
                except Exception as e:
                    app.logger.debug(f"MessageBox error: {e}")
                    # Fall back to console input
                    response = input("Continue without admin privileges? (y/N): ")
                    if response.lower() not in ['y', 'yes']:
                        return 0
        
        # Start the agent and run main loop
            success = app.start_agent(
                debug=args.debug,
                no_ui=args.no_ui,
                server_url=args.server,
                config_file=args.config
            )
            
            if success:
                app.logger.info("✅ EDR Agent started successfully")
            # Application will run until interrupted
                return 0
            else:
                app.logger.error("❌ Failed to start EDR Agent")
                return 1
                
        except KeyboardInterrupt:
            app.logger.info("⚠️ Agent interrupted by user")
            print("\n👋 Agent stopped by user")
            return 0
        except Exception as e:
            app.logger.error(f"💥 Unexpected error: {e}")
            print(f"💥 Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    main()