"""
EDR Windows Agent - Installation Script
"""

import os
import sys
import shutil
import subprocess
import logging
from pathlib import Path
import winreg
from typing import Dict, Any

class EDRAgentInstaller:
    """Installer for EDR Windows Agent"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Installation paths
        self.install_dir = r"C:\Program Files\EDR Agent"
        self.config_dir = os.path.join(self.install_dir, "config")
        self.data_dir = os.path.join(self.install_dir, "data")
        self.logs_dir = os.path.join(self.install_dir, "logs")
        self.resources_dir = os.path.join(self.install_dir, "resources")
        
        # Current script directory
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Service configuration
        self.service_name = "EDRAgent"
        self.service_display_name = "EDR Windows Agent"
        self.service_description = "Endpoint Detection and Response Agent for Windows"
        
    def install(self) -> bool:
        """Install EDR Agent"""
        try:
            print("🚀 Starting EDR Agent installation...")
            
            # Check admin privileges
            if not self._is_admin():
                print("❌ Administrator privileges required for installation")
                return False
            
            # Create directories
            if not self._create_directories():
                return False
            
            # Copy files
            if not self._copy_files():
                return False
            
            # Install Windows service
            if not self._install_service():
                return False
            
            # Create uninstaller
            if not self._create_uninstaller():
                return False
            
            # Add to registry
            if not self._add_to_registry():
                return False
            
            # Create desktop shortcut
            self._create_shortcuts()
            
            print("✅ EDR Agent installed successfully!")
            print(f"📁 Installation directory: {self.install_dir}")
            print("🔧 Service will start automatically on boot")
            print("🎯 Configure server URL in config/agent_config.yaml")
            
            return True
            
        except Exception as e:
            print(f"❌ Installation failed: {e}")
            self.logger.error(f"Installation error: {e}")
            return False
    
    def uninstall(self) -> bool:
        """Uninstall EDR Agent"""
        try:
            print("🗑️ Uninstalling EDR Agent...")
            
            # Check admin privileges
            if not self._is_admin():
                print("❌ Administrator privileges required for uninstallation")
                return False
            
            # Stop and remove service
            if not self._remove_service():
                print("⚠️ Warning: Failed to remove service")
            
            # Remove from registry
            self._remove_from_registry()
            
            # Remove shortcuts
            self._remove_shortcuts()
            
            # Remove installation directory
            if os.path.exists(self.install_dir):
                try:
                    shutil.rmtree(self.install_dir)
                    print(f"✅ Removed installation directory: {self.install_dir}")
                except Exception as e:
                    print(f"⚠️ Warning: Could not remove {self.install_dir}: {e}")
            
            print("✅ EDR Agent uninstalled successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Uninstallation failed: {e}")
            self.logger.error(f"Uninstallation error: {e}")
            return False
    
    def _is_admin(self) -> bool:
        """Check if running with admin privileges"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def _create_directories(self) -> bool:
        """Create installation directories"""
        try:
            directories = [
                self.install_dir,
                self.config_dir,
                self.data_dir,
                self.logs_dir,
                self.resources_dir,
                os.path.join(self.data_dir, "cache"),
                os.path.join(self.data_dir, "temp"),
                os.path.join(self.data_dir, "quarantine"),
                os.path.join(self.resources_dir, "icons")
            ]
            
            for directory in directories:
                os.makedirs(directory, exist_ok=True)
                print(f"📁 Created directory: {directory}")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to create directories: {e}")
            return False
    
    def _copy_files(self) -> bool:
        """Copy agent files to installation directory"""
        try:
            # Find the executable
            possible_exe_paths = [
                os.path.join(self.script_dir, "EDR_Agent.exe"),
                os.path.join(self.script_dir, "..", "dist", "EDR_Agent.exe"),
                os.path.join(self.script_dir, "..", "EDR_Agent.exe")
            ]
            
            exe_path = None
            for path in possible_exe_paths:
                if os.path.exists(path):
                    exe_path = path
                    break
            
            if not exe_path:
                print("❌ Could not find EDR_Agent.exe")
                return False
            
            # Copy executable
            dest_exe = os.path.join(self.install_dir, "EDR_Agent.exe")
            shutil.copy2(exe_path, dest_exe)
            print(f"📄 Copied executable: {dest_exe}")
            
            # Copy configuration
            config_files = [
                "agent_config.yaml",
                "requirements.txt"
            ]
            
            for config_file in config_files:
                src_paths = [
                    os.path.join(self.script_dir, config_file),
                    os.path.join(self.script_dir, "..", config_file),
                    os.path.join(self.script_dir, "config", config_file)
                ]
                
                src_path = None
                for path in src_paths:
                    if os.path.exists(path):
                        src_path = path
                        break
                
                if src_path:
                    dest_path = os.path.join(self.config_dir, config_file)
                    shutil.copy2(src_path, dest_path)
                    print(f"📄 Copied config: {dest_path}")
            
            # Copy resources
            src_resources = os.path.join(self.script_dir, "resources")
            if not os.path.exists(src_resources):
                src_resources = os.path.join(self.script_dir, "..", "resources")
            
            if os.path.exists(src_resources):
                for item in os.listdir(src_resources):
                    src_item = os.path.join(src_resources, item)
                    dest_item = os.path.join(self.resources_dir, item)
                    
                    if os.path.isdir(src_item):
                        shutil.copytree(src_item, dest_item, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src_item, dest_item)
                
                print(f"📁 Copied resources: {self.resources_dir}")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to copy files: {e}")
            return False
    
    def _install_service(self) -> bool:
        """Install Windows service"""
        try:
            exe_path = os.path.join(self.install_dir, "EDR_Agent.exe")
            
            # Create service using sc command
            cmd = [
                'sc', 'create', self.service_name,
                f'binPath={exe_path} --service',
                f'DisplayName={self.service_display_name}',
                'start=auto',
                'type=own'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ Service '{self.service_name}' created")
                
                # Set service description
                desc_cmd = ['sc', 'description', self.service_name, self.service_description]
                subprocess.run(desc_cmd, capture_output=True, text=True)
                
                # Set recovery options
                recovery_cmd = [
                    'sc', 'failure', self.service_name,
                    'reset=0',
                    'actions=restart/5000/restart/5000/restart/5000'
                ]
                subprocess.run(recovery_cmd, capture_output=True, text=True)
                
                return True
            else:
                print(f"❌ Failed to create service: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Service installation failed: {e}")
            return False
    
    def _remove_service(self) -> bool:
        """Remove Windows service"""
        try:
            # Stop service first
            stop_cmd = ['sc', 'stop', self.service_name]
            subprocess.run(stop_cmd, capture_output=True, text=True)
            
            # Delete service
            delete_cmd = ['sc', 'delete', self.service_name]
            result = subprocess.run(delete_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ Service '{self.service_name}' removed")
                return True
            else:
                print(f"⚠️ Service removal warning: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Service removal failed: {e}")
            return False
    
    def _add_to_registry(self) -> bool:
        """Add to Windows registry"""
        try:
            # Add to installed programs
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\EDRAgent"
            
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "EDR Windows Agent")
                winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, "2.0.0")
                winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "EDR System")
                winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, self.install_dir)
                winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, 
                                os.path.join(self.install_dir, "uninstall.exe"))
                winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
            
            print("✅ Added to registry")
            return True
            
        except Exception as e:
            print(f"⚠️ Registry warning: {e}")
            return True  # Non-critical
    
    def _remove_from_registry(self):
        """Remove from Windows registry"""
        try:
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\EDRAgent"
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            print("✅ Removed from registry")
        except Exception as e:
            print(f"⚠️ Registry cleanup warning: {e}")
    
    def _create_shortcuts(self):
        """Create desktop and start menu shortcuts"""
        try:
            # This would create shortcuts using win32com.shell
            # Simplified implementation
            print("✅ Shortcuts would be created here")
        except Exception as e:
            print(f"⚠️ Shortcut creation warning: {e}")
    
    def _remove_shortcuts(self):
        """Remove shortcuts"""
        try:
            # Remove shortcuts
            print("✅ Shortcuts would be removed here")
        except Exception as e:
            print(f"⚠️ Shortcut removal warning: {e}")
    
    def _create_uninstaller(self) -> bool:
        """Create uninstaller executable"""
        try:
            uninstall_script = f'''
import sys
import os
sys.path.insert(0, r"{self.install_dir}")

from installer.install import EDRAgentInstaller

if __name__ == "__main__":
    installer = EDRAgentInstaller()
    success = installer.uninstall()
    
    if success:
        print("\\nPress any key to exit...")
        input()
    else:
        print("\\nUninstallation failed. Press any key to exit...")
        input()
        sys.exit(1)
'''
            
            uninstall_path = os.path.join(self.install_dir, "uninstall.py")
            with open(uninstall_path, 'w') as f:
                f.write(uninstall_script)
            
            print("✅ Created uninstaller")
            return True
            
        except Exception as e:
            print(f"⚠️ Uninstaller creation warning: {e}")
            return True  # Non-critical

def install_agent():
    """Install EDR Agent"""
    installer = EDRAgentInstaller()
    return installer.install()

def uninstall_agent():
    """Uninstall EDR Agent"""
    installer = EDRAgentInstaller()
    return installer.uninstall()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--uninstall":
        success = uninstall_agent()
    else:
        success = install_agent()
    
    if not success:
        sys.exit(1)