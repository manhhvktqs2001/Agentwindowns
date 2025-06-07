#!/usr/bin/env python3
"""
EDR Windows Agent - Main Entry Point (FIXED)
"""

import sys
import os
import argparse
import logging
import signal
import time
from pathlib import Path

# Add current directory to path to fix relative imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Now import modules with absolute imports
from config import AgentConfig
from core.agent import EDRAgent
from utils.windows_utils import is_admin, elevate_privileges

class EDRAgentMain:
    def __init__(self):
        self.agent = None
        self.tray_icon = None
        self.running = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def setup_logging(self, debug=False):
        """Setup logging configuration"""
        try:
            # Create logs directory
            logs_dir = Path("logs")
            logs_dir.mkdir(exist_ok=True)
            
            # Configure logging
            log_level = logging.DEBUG if debug else logging.INFO
            logging.basicConfig(
                level=log_level,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler('logs/agent.log', encoding='utf-8'),
                    logging.StreamHandler(sys.stdout)
                ]
            )
            
            logger = logging.getLogger(__name__)
            logger.info("EDR Agent logging initialized")
            return True
            
        except Exception as e:
            print(f"Failed to setup logging: {e}")
            return False
    
    def check_requirements(self):
        """Check system requirements"""
        try:
            import psutil
            import win32api
            import win32gui
            import socketio
            print("✅ All required packages available")
            return True
        except ImportError as e:
            print(f"❌ Missing required package: {e}")
            print("💡 Run: pip install -r requirements.txt")
            return False
    
    def create_directories(self):
        """Create necessary directories"""
        directories = ["logs", "data", "data/cache", "data/temp", "resources", "resources/icons"]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
        
        print("✅ Directories created/verified")
    
    def start_agent(self, debug=False, no_ui=False, server_url=None):
        """Start the EDR agent"""
        try:
            # Setup logging
            if not self.setup_logging(debug):
                return False
            
            logger = logging.getLogger(__name__)
            logger.info("🚀 Starting EDR Windows Agent...")
            
            # Load configuration
            config = AgentConfig()
            if server_url:
                config.SERVER_URL = server_url
            
            logger.info(f"Server URL: {config.SERVER_URL}")
            
            # Create and start agent
            self.agent = EDRAgent(config)
            
            # Start agent in background thread
            agent_thread = self.agent.start()
            
            if not no_ui:
                # Start system tray UI
                try:
                    from ui.tray_icon import SystemTrayIcon
                    self.tray_icon = SystemTrayIcon(self.agent)
                    self.tray_icon.start()
                    logger.info("✅ System tray started")
                except ImportError:
                    logger.warning("⚠️ UI components not available, running in console mode")
                    no_ui = True
            
            if no_ui:
                # Console mode
                logger.info("✅ Agent started in console mode")
                print("EDR Agent is running. Press Ctrl+C to stop.")
                
                # Keep main thread alive
                self.running = True
                while self.running:
                    time.sleep(1)
            
            return True
            
        except Exception as e:
            if 'logger' in locals():
                logger.error(f"Failed to start agent: {e}")
            else:
                print(f"Failed to start agent: {e}")
            return False
    
    def stop_agent(self):
        """Stop the EDR agent"""
        try:
            logger = logging.getLogger(__name__)
            logger.info("🛑 Stopping EDR Agent...")
            
            self.running = False
            
            if self.tray_icon:
                self.tray_icon.stop()
            
            if self.agent:
                self.agent.stop()
            
            logger.info("✅ Agent stopped successfully")
            
        except Exception as e:
            print(f"Error stopping agent: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\nReceived signal {signum}, shutting down...")
        self.stop_agent()
        sys.exit(0)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='EDR Windows Agent')
    
    parser.add_argument('--debug', action='store_true',
                      help='Enable debug logging')
    parser.add_argument('--no-ui', action='store_true',
                      help='Run without UI (console mode)')
    parser.add_argument('--server', type=str,
                      help='EDR Server URL (overrides config)')
    parser.add_argument('--install', action='store_true',
                      help='Install as Windows service')
    parser.add_argument('--uninstall', action='store_true',
                      help='Uninstall Windows service')
    parser.add_argument('--service', action='store_true',
                      help='Run as Windows service (internal use)')
    parser.add_argument('--check', action='store_true',
                      help='Check requirements and exit')
    
    return parser.parse_args()

def main():
    """Main entry point"""
    try:
        # Initialize logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logger = logging.getLogger(__name__)
        logger.info("EDR Agent logging initialized")
        
        # Print banner
        print("🖥️ EDR Windows Agent v2.0")
        print("========================================")
        
        # Check requirements
        agent_main = EDRAgentMain()
        if not agent_main.check_requirements():
            sys.exit(1)
        
        if args.check:
            print("✅ All requirements satisfied")
            sys.exit(0)
        
        # Create directories
        agent_main.create_directories()
        
        # Load configuration
        config = AgentConfig()
        if args.server:
            config.SERVER_URL = args.server
        logger.info(f"Server URL: {config.SERVER_URL}")
        
        # Initialize agent
        agent_main.agent = EDRAgent(config)
        logger.info("✅ EDR Agent initialized")
        
        # Start agent
        logger.info("🚀 Starting EDR Agent...")
        agent_thread = agent_main.agent.start()
        
        # Start system tray
        if not args.no_ui:
            try:
                from ui.tray_icon import SystemTrayIcon
                agent_main.tray_icon = SystemTrayIcon(agent_main.agent)
                agent_main.tray_icon.start()
                logger.info("✅ System tray started")
    print("🖥️ EDR Windows Agent v2.0")
    print("=" * 40)
    
    args = parse_arguments()
    
    # Check requirements
    agent_main = EDRAgentMain()
    if not agent_main.check_requirements():
        sys.exit(1)
    
    if args.check:
        print("✅ All requirements satisfied")
        sys.exit(0)
    
    # Create directories
    agent_main.create_directories()
    
    # Handle service installation
    if args.install:
        try:
            from installer.service import install_service
            if install_service():
                print("✅ Service installed successfully")
            else:
                print("❌ Service installation failed")
        except ImportError:
            print("❌ Service installer not available")
        sys.exit(0)
    
    if args.uninstall:
        try:
            from installer.service import uninstall_service
            if uninstall_service():
                print("✅ Service uninstalled successfully")
            else:
                print("❌ Service uninstallation failed")
        except ImportError:
            print("❌ Service installer not available")
        sys.exit(0)
    
    # Check admin privileges for certain operations
    if not is_admin():
        print("⚠️ Warning: Running without administrator privileges")
        print("💡 Some monitoring features may be limited")
        
        # Offer to elevate privileges
        if not args.no_ui:
            try:
                import win32gui
                result = win32gui.MessageBox(0, 
                    "EDR Agent works best with administrator privileges.\n\nRestart as administrator?",
                    "EDR Agent", 4)  # MB_YESNO
                if result == 6:  # IDYES
                    elevate_privileges()
                    sys.exit(0)
            except:
                pass
    
    # Start agent
    try:
        success = agent_main.start_agent(
            debug=args.debug,
            no_ui=args.no_ui,
            server_url=args.server
        )
        
        if not success:
            print("❌ Failed to start EDR Agent")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n👋 Agent stopped by user")
    except Exception as e:
        print(f"💥 Unexpected error: {e}")
        sys.exit(1)
    finally:
        agent_main.stop_agent()

if __name__ == "__main__":
    main()