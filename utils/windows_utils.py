"""
EDR Windows Agent - Windows Utilities
"""

import os
import sys
import ctypes
import subprocess
import logging
from typing import Dict, List, Any, Optional, Tuple
import win32api
import win32con
import win32security
import win32process
import win32service
import win32serviceutil

class WindowsUtils:
    """Utility class for Windows-specific operations"""
    
    @staticmethod
    def is_admin() -> bool:
        """Check if current process has administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

    @staticmethod
    def elevate_privileges():
        """Elevate to administrator privileges"""
        try:
            if WindowsUtils.is_admin():
                return True
            
            # Re-run the program with admin rights
            ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas", 
                sys.executable, 
                " ".join(sys.argv), 
                None, 
                1
            )
            return True
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to elevate privileges: {e}")
            return False

    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """Get detailed Windows system information"""
        try:
            import platform
            import socket
            import uuid
            import psutil
            
            # Basic system info
            info = {
                'hostname': socket.gethostname(),
                'os_type': 'Windows',
                'os_version': platform.platform(),
                'os_release': platform.release(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'machine': platform.machine(),
                'python_version': platform.python_version()
            }
            
            # Memory information
            memory = psutil.virtual_memory()
            info.update({
                'total_memory': memory.total,
                'available_memory': memory.available,
                'memory_percent': memory.percent
            })
            
            # Disk information
            try:
                import string
                disk_drives = []
                total_disk = free_disk = used_disk = disk_percent = 0
                for drive_letter in string.ascii_uppercase:
                    drive = f"{drive_letter}:\\"
                    if os.path.exists(drive):
                        try:
                            disk = psutil.disk_usage(drive)
                            disk_drives.append({
                                'drive': drive,
                                'total': disk.total,
                                'free': disk.free,
                                'used': disk.used,
                                'percent': disk.percent
                            })
                            total_disk += disk.total
                            free_disk += disk.free
                            used_disk += disk.used
                        except Exception as e:
                            disk_drives.append({
                                'drive': drive,
                                'error': str(e)
                            })
                if disk_drives:
                    disk_percent = (used_disk / total_disk) * 100 if total_disk else 0
                    info.update({
                        'total_disk': total_disk,
                        'free_disk': free_disk,
                        'used_disk': used_disk,
                        'disk_percent': disk_percent,
                        'disk_drives': disk_drives
                    })
                else:
                    info.update({
                        'total_disk': 0,
                        'free_disk': 0,
                        'used_disk': 0,
                        'disk_percent': 0,
                        'disk_drives': [],
                        'disk_error': 'No valid disk drives found.'
                    })
            except Exception as e:
                info.update({
                    'total_disk': 0,
                    'free_disk': 0,
                    'used_disk': 0,
                    'disk_percent': 0,
                    'disk_drives': [],
                    'disk_error': str(e)
                })
            
            # Network information
            info.update({
                'ip_address': WindowsUtils.get_local_ip(),
                'mac_address': WindowsUtils.get_mac_address(),
                'network_interfaces': WindowsUtils.get_network_interfaces()
            })
            
            # Windows specific
            info.update({
                'domain': os.environ.get('USERDOMAIN', 'WORKGROUP'),
                'username': os.environ.get('USERNAME', 'Unknown'),
                'computer_name': os.environ.get('COMPUTERNAME', 'Unknown'),
                'user_profile': os.environ.get('USERPROFILE', ''),
                'system_drive': os.environ.get('SYSTEMDRIVE', 'C:'),
                'program_files': os.environ.get('PROGRAMFILES', ''),
                'is_admin': WindowsUtils.is_admin()
            })
            
            # Windows version details
            try:
                win_info = WindowsUtils.get_windows_version()
                info.update(win_info)
            except Exception:
                pass
            
            return info
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error getting system info: {e}")
            return {'hostname': socket.gethostname(), 'error': str(e)}

    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                return s.getsockname()[0]
        except Exception:
            return '127.0.0.1'

    @staticmethod
    def get_mac_address() -> str:
        """Get MAC address"""
        try:
            import uuid
            mac = uuid.getnode()
            return ':'.join(['{:02x}'.format((mac >> elements) & 0xff) 
                           for elements in range(0, 2*6, 2)][::-1])
        except Exception:
            return '00:00:00:00:00:00'

    @staticmethod
    def get_network_interfaces() -> List[Dict[str, Any]]:
        """Get network interface information"""
        try:
            import psutil
            interfaces = []
            
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    'name': interface,
                    'addresses': []
                }
                
                for addr in addrs:
                    if addr.family == 2:  # AF_INET (IPv4)
                        interface_info['addresses'].append({
                            'type': 'IPv4',
                            'address': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast
                        })
                    elif addr.family == 23:  # AF_INET6 (IPv6)
                        interface_info['addresses'].append({
                            'type': 'IPv6',
                            'address': addr.address,
                            'netmask': addr.netmask
                        })
                    elif addr.family == -1:  # AF_LINK (MAC)
                        interface_info['mac_address'] = addr.address
                
                if interface_info['addresses']:
                    interfaces.append(interface_info)
            
            return interfaces
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error getting network interfaces: {e}")
            return []

    @staticmethod
    def get_windows_version() -> Dict[str, Any]:
        """Get detailed Windows version information"""
        try:
            import winreg
            
            version_info = {}
            
            # Open Windows version registry key
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            
            # Read version information
            try:
                version_info['product_name'] = winreg.QueryValueEx(key, "ProductName")[0]
            except FileNotFoundError:
                pass
                
            try:
                version_info['current_build'] = winreg.QueryValueEx(key, "CurrentBuild")[0]
            except FileNotFoundError:
                pass
                
            try:
                version_info['release_id'] = winreg.QueryValueEx(key, "ReleaseId")[0]
            except FileNotFoundError:
                pass
                
            try:
                version_info['display_version'] = winreg.QueryValueEx(key, "DisplayVersion")[0]
            except FileNotFoundError:
                pass
            
            winreg.CloseKey(key)
            
            return version_info
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error getting Windows version: {e}")
            return {}

    @staticmethod
    def run_as_system(command: str) -> Tuple[bool, str]:
        """Run command with SYSTEM privileges"""
        try:
            if not WindowsUtils.is_admin():
                return False, "Administrator privileges required"
            
            # Use PsExec-like functionality (simplified)
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0, result.stdout + result.stderr
            
        except Exception as e:
            return False, str(e)

    @staticmethod
    def create_scheduled_task(task_name: str, executable_path: str, arguments: str = "") -> bool:
        """Create Windows scheduled task"""
        try:
            command = [
                'schtasks', '/create',
                '/tn', task_name,
                '/tr', f'"{executable_path}" {arguments}',
                '/sc', 'onlogon',
                '/rl', 'highest',
                '/f'  # Force overwrite
            ]
            
            result = subprocess.run(command, capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error creating scheduled task: {e}")
            return False

    @staticmethod
    def add_to_startup(name: str, executable_path: str) -> bool:
        """Add program to Windows startup"""
        try:
            import winreg
            
            # Open registry key
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE
            )
            
            # Add program
            winreg.SetValueEx(
                key,
                name,
                0,
                winreg.REG_SZ,
                executable_path
            )
            
            winreg.CloseKey(key)
            return True
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error adding to startup: {e}")
            return False

    @staticmethod
    def remove_from_startup(name: str) -> bool:
        """Remove program from Windows startup"""
        try:
            import winreg
            
            # Open registry key
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE
            )
            
            # Remove program
            winreg.DeleteValue(key, name)
            
            winreg.CloseKey(key)
            return True
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error removing from startup: {e}")
            return False

    @staticmethod
    def create_firewall_rule(rule_name: str, program_path: str, action: str = "block") -> bool:
        """Create Windows Firewall rule"""
        try:
            command = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name="{rule_name}"',
                f'program="{program_path}"',
                'enable=yes',
                f'action={action}',
                'profile=any'
            ]
            
            result = subprocess.run(command, capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error creating firewall rule: {e}")
            return False

    @staticmethod
    def delete_firewall_rule(rule_name: str) -> bool:
        """Delete Windows Firewall rule"""
        try:
            command = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name="{rule_name}"'
            ]
            
            result = subprocess.run(command, capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error deleting firewall rule: {e}")
            return False

    @staticmethod
    def get_installed_software() -> List[Dict[str, str]]:
        """Get list of installed software"""
        try:
            import winreg
            
            software_list = []
            
            # Open registry key
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            )
            
            # Enumerate subkeys
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    
                    try:
                        name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                        publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                        
                        software_list.append({
                            'name': name,
                            'version': version,
                            'publisher': publisher
                        })
                    except FileNotFoundError:
                        pass
                        
                    winreg.CloseKey(subkey)
                    
                except Exception:
                    continue
            
            winreg.CloseKey(key)
            return software_list
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error getting installed software: {e}")
            return []

    @staticmethod
    def get_windows_services() -> List[Dict[str, Any]]:
        """Get list of Windows services"""
        try:
            services = []
            
            for service in win32serviceutil.EnumServices(None, None, win32service.SERVICE_WIN32):
                try:
                    name = service[0]
                    display_name = service[1]
                    status = service[2]
                    
                    services.append({
                        'name': name,
                        'display_name': display_name,
                        'status': status
                    })
                except Exception:
                    continue
            
            return services
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error getting Windows services: {e}")
            return []

    @staticmethod
    def get_startup_programs() -> List[Dict[str, str]]:
        """Get list of startup programs"""
        try:
            startup_list = []
            
            # Check registry startup locations
            registry_locations = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
            ]
            
            for hkey, key_path in registry_locations:
                try:
                    key = winreg.OpenKey(hkey, key_path, 0, winreg.KEY_READ)
                    
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            startup_list.append({
                                'name': name,
                                'command': value,
                                'location': 'Registry'
                            })
                        except Exception:
                            continue
                            
                    winreg.CloseKey(key)
                    
                except Exception:
                    continue
            
            # Check startup folders
            startup_folders = [
                os.path.join(os.environ['APPDATA'], r'Microsoft\Windows\Start Menu\Programs\Startup'),
                os.path.join(os.environ['PROGRAMDATA'], r'Microsoft\Windows\Start Menu\Programs\StartUp')
            ]
            
            for folder in startup_folders:
                if os.path.exists(folder):
                    for file in os.listdir(folder):
                        if file.endswith('.lnk'):
                            try:
                                import win32com.client
                                shell = win32com.client.Dispatch("WScript.Shell")
                                shortcut = shell.CreateShortCut(os.path.join(folder, file))
                                
                                startup_list.append({
                                    'name': os.path.splitext(file)[0],
                                    'command': shortcut.Targetpath,
                                    'location': 'Startup Folder'
                                })
                            except Exception:
                                continue
            
            return startup_list
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error getting startup programs: {e}")
            return []

    @staticmethod
    def check_windows_defender_status() -> Dict[str, Any]:
        """Check Windows Defender status"""
        try:
            import winreg
            
            status = {
                'enabled': False,
                'real_time_protection': False,
                'antivirus_enabled': False,
                'antispyware_enabled': False
            }
            
            # Check Windows Defender status
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows Defender",
                0,
                winreg.KEY_READ
            )
            
            try:
                status['enabled'] = bool(winreg.QueryValueEx(key, "DisableAntiSpyware")[0] == 0)
            except FileNotFoundError:
                status['enabled'] = True
            
            winreg.CloseKey(key)
            
            # Check real-time protection
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
                0,
                winreg.KEY_READ
            )
            
            try:
                status['real_time_protection'] = bool(winreg.QueryValueEx(key, "DisableBehaviorMonitoring")[0] == 0)
            except FileNotFoundError:
                status['real_time_protection'] = True
            
            winreg.CloseKey(key)
            
            # Check antivirus and antispyware
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows Defender\Features",
                0,
                winreg.KEY_READ
            )
            
            try:
                status['antivirus_enabled'] = bool(winreg.QueryValueEx(key, "AntivirusEnabled")[0] == 1)
            except FileNotFoundError:
                status['antivirus_enabled'] = True
                
            try:
                status['antispyware_enabled'] = bool(winreg.QueryValueEx(key, "AntispywareEnabled")[0] == 1)
            except FileNotFoundError:
                status['antispyware_enabled'] = True
            
            winreg.CloseKey(key)
            
            return status
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Error checking Windows Defender status: {e}")
            return {
                'enabled': False,
                'real_time_protection': False,
                'antivirus_enabled': False,
                'antispyware_enabled': False,
                'error': str(e)
            }