"""
EDR Windows Agent - Windows Service Wrapper
"""

import sys
import os
import time
import logging
import threading
import servicemanager
import win32serviceutil
import win32service
import win32event

# Add the installation directory to path
if hasattr(sys, 'frozen'):
    # Running as compiled executable
    install_dir = os.path.dirname(sys.executable)
else:
    # Running as script
    install_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

sys.path.insert(0, install_dir)

try:
    from config import AgentConfig
    from core.agent import EDRAgent
except ImportError as e:
    # Fallback for service environment
    sys.path.insert(0, os.path.join(install_dir, 'config'))
    sys.path.insert(0, os.path.join(install_dir, 'core'))

class EDRAgentService(win32serviceutil.ServiceFramework):
    """Windows service wrapper for EDR Agent"""
    
    _svc_name_ = "EDRAgent"
    _svc_display_name_ = "EDR Windows Agent"
    _svc_description_ = "Endpoint Detection and Response Agent for Windows"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        
        # Create stop event
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        
        # Initialize logging for service
        self.setup_service_logging()
        
        # Agent instance
        self.agent = None
        self.agent_thread = None
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("EDR Agent Service initialized")
    
    def setup_service_logging(self):
        """Setup logging for Windows service"""
        try:
            # Create logs directory in installation path
            logs_dir = os.path.join(install_dir, 'logs')
            os.makedirs(logs_dir, exist_ok=True)
            
            # Configure logging
            log_file = os.path.join(logs_dir, 'service.log')
            
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_file),
                    logging.StreamHandler()
                ]
            )
            
            # Also log to Windows Event Log
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, "Logging initialized")
            )
            
        except Exception as e:
            # Fallback to event log only
            servicemanager.LogErrorMsg(f"Failed to setup file logging: {e}")
    
    def SvcStop(self):
        """Called when service is stopped"""
        try:
            self.logger.info("Service stop requested")
            
            # Report to Service Control Manager
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            
            # Stop the agent
            if self.agent:
                self.agent.stop()
            
            # Signal stop event
            win32event.SetEvent(self.hWaitStop)
            
            # Log to event log
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, "Service stopped")
            )
            
            self.logger.info("Service stopped successfully")
            
        except Exception as e:
            error_msg = f"Error stopping service: {e}"
            self.logger.error(error_msg)
            servicemanager.LogErrorMsg(error_msg)
    
    def SvcDoRun(self):
        """Main service entry point"""
        try:
            # Log service start
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, "Service starting")
            )
            
            self.logger.info("EDR Agent Service starting...")
            
            # Start the agent
            self.start_agent()
            
            # Wait for stop event
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            
        except Exception as e:
            error_msg = f"Service error: {e}"
            self.logger.error(error_msg)
            servicemanager.LogErrorMsg(error_msg)
            
            # Report service stopped due to error
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)
    
    def start_agent(self):
        """Start the EDR agent"""
        try:
            # Load configuration
            config_file = os.path.join(install_dir, 'config', 'agent_config.yaml')
            if not os.path.exists(config_file):
                config_file = os.path.join(install_dir, 'agent_config.yaml')
            
            if os.path.exists(config_file):
                config = AgentConfig(config_file)
            else:
                config = AgentConfig()  # Use defaults
                self.logger.warning("No config file found, using defaults")
            
            # Create and start agent
            self.agent = EDRAgent(config)
            
            # Start agent in separate thread
            self.agent_thread = threading.Thread(target=self.run_agent, daemon=True)
            self.agent_thread.start()
            
            # Report service running
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, "EDR Agent started successfully")
            )
            
            self.logger.info("EDR Agent started successfully")
            
        except Exception as e:
            error_msg = f"Failed to start EDR Agent: {e}"
            self.logger.error(error_msg)
            servicemanager.LogErrorMsg(error_msg)
            raise
    
    def run_agent(self):
        """Run the agent in a separate thread"""
        try:
            # Start the agent
            agent_thread = self.agent.start()
            
            # Keep the thread alive while service is running
            while not win32event.WaitForSingleObject(self.hWaitStop, 1000) == win32event.WAIT_OBJECT_0:
                # Check if agent is still running
                if not self.agent.running:
                    self.logger.warning("Agent stopped unexpectedly, restarting...")
                    
                    try:
                        # Try to restart the agent
                        self.agent = EDRAgent(self.agent.config)
                        agent_thread = self.agent.start()
                        
                        servicemanager.LogMsg(
                            servicemanager.EVENTLOG_WARNING_TYPE,
                            servicemanager.PYS_SERVICE_STARTED,
                            (self._svc_name_, "Agent restarted after unexpected stop")
                        )
                        
                    except Exception as restart_error:
                        error_msg = f"Failed to restart agent: {restart_error}"
                        self.logger.error(error_msg)
                        servicemanager.LogErrorMsg(error_msg)
                        break
            
        except Exception as e:
            error_msg = f"Agent thread error: {e}"
            self.logger.error(error_msg)
            servicemanager.LogErrorMsg(error_msg)

def install_service():
    """Install the Windows service"""
    try:
        # Install service
        win32serviceutil.InstallService(
            EDRAgentService,
            EDRAgentService._svc_name_,
            EDRAgentService._svc_display_name_,
            description=EDRAgentService._svc_description_
        )
        
        print(f"✅ Service '{EDRAgentService._svc_display_name_}' installed successfully")
        
        # Set service to start automatically
        import win32service
        import win32con
        
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
        try:
            service = win32service.OpenService(scm, EDRAgentService._svc_name_, win32service.SERVICE_ALL_ACCESS)
            try:
                win32service.ChangeServiceConfig(
                    service,
                    win32service.SERVICE_NO_CHANGE,
                    win32service.SERVICE_AUTO_START,  # Start automatically
                    win32service.SERVICE_NO_CHANGE,
                    None, None, 0, None, None, None, None
                )
                print("✅ Service configured to start automatically")
            finally:
                win32service.CloseServiceHandle(service)
        finally:
            win32service.CloseServiceHandle(scm)
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to install service: {e}")
        return False

def uninstall_service():
    """Uninstall the Windows service"""
    try:
        # Stop service first
        try:
            win32serviceutil.StopService(EDRAgentService._svc_name_)
            print("✅ Service stopped")
        except Exception:
            pass  # Service might not be running
        
        # Remove service
        win32serviceutil.RemoveService(EDRAgentService._svc_name_)
        print(f"✅ Service '{EDRAgentService._svc_display_name_}' removed successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to uninstall service: {e}")
        return False

def start_service():
    """Start the Windows service"""
    try:
        win32serviceutil.StartService(EDRAgentService._svc_name_)
        print(f"✅ Service '{EDRAgentService._svc_display_name_}' started")
        return True
    except Exception as e:
        print(f"❌ Failed to start service: {e}")
        return False

def stop_service():
    """Stop the Windows service"""
    try:
        win32serviceutil.StopService(EDRAgentService._svc_name_)
        print(f"✅ Service '{EDRAgentService._svc_display_name_}' stopped")
        return True
    except Exception as e:
        print(f"❌ Failed to stop service: {e}")
        return False

def service_status():
    """Get service status"""
    try:
        import win32service
        
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        try:
            service = win32service.OpenService(scm, EDRAgentService._svc_name_, win32service.SERVICE_QUERY_STATUS)
            try:
                status = win32service.QueryServiceStatus(service)
                
                status_map = {
                    win32service.SERVICE_STOPPED: "Stopped",
                    win32service.SERVICE_START_PENDING: "Start Pending",
                    win32service.SERVICE_STOP_PENDING: "Stop Pending", 
                    win32service.SERVICE_RUNNING: "Running",
                    win32service.SERVICE_CONTINUE_PENDING: "Continue Pending",
                    win32service.SERVICE_PAUSE_PENDING: "Pause Pending",
                    win32service.SERVICE_PAUSED: "Paused"
                }
                
                status_text = status_map.get(status[1], f"Unknown ({status[1]})")
                print(f"Service Status: {status_text}")
                return status[1]
                
            finally:
                win32service.CloseServiceHandle(service)
        finally:
            win32service.CloseServiceHandle(scm)
            
    except Exception as e:
        print(f"❌ Failed to get service status: {e}")
        return None

if __name__ == '__main__':
    if len(sys.argv) == 1:
        # Run as service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(EDRAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Handle command line arguments
        win32serviceutil.HandleCommandLine(EDRAgentService)