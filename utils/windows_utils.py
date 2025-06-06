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

def is_admin() -> bool:
    """Check if current process has administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def elevate_privileges():
    """Elevate to administrator privileges"""
    try:
        if is_admin():
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
        disk = psutil.disk_usage('C:')
        info.update({
            'total_disk': disk.total,
            'free_disk': disk.free,
            'used_disk': disk.used,
            'disk_percent': (disk.used / disk.total) * 100
        })
        
        # Network information
        info.update({
            'ip_address': get_local_ip(),
            'mac_address': get_mac_address(),
            'network_interfaces': get_network_interfaces()
        })
        
        # Windows specific
        info.update({
            'domain': os.environ.get('USERDOMAIN', 'WORKGROUP'),
            'username': os.environ.get('USERNAME', 'Unknown'),
            'computer_name': os.environ.get('COMPUTERNAME', 'Unknown'),
            'user_profile': os.environ.get('USERPROFILE', ''),
            'system_drive': os.environ.get('SYSTEMDRIVE', 'C:'),
            'program_files': os.environ.get('PROGRAMFILES', ''),
            'is_admin': is_admin()
        })
        
        # Windows version details
        try:
            win_info = get_windows_version()
            info.update(win_info)
        except Exception:
            pass
        
        return info
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error getting system info: {e}")
        return {'hostname': socket.gethostname(), 'error': str(e)}

def get_local_ip() -> str:
    """Get local IP address"""
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'

def get_mac_address() -> str:
    """Get MAC address"""
    try:
        import uuid
        mac = uuid.getnode()
        return ':'.join(['{:02x}'.format((mac >> elements) & 0xff) 
                       for elements in range(0, 2*6, 2)][::-1])
    except Exception:
        return '00:00:00:00:00:00'

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

def run_as_system(command: str) -> Tuple[bool, str]:
    """Run command with SYSTEM privileges"""
    try:
        if not is_admin():
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

def delete_scheduled_task(task_name: str) -> bool:
    """Delete Windows scheduled task"""
    try:
        command = ['schtasks', '/delete', '/tn', task_name, '/f']
        result = subprocess.run(command, capture_output=True, text=True)
        return result.returncode == 0
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error deleting scheduled task: {e}")
        return False

def add_to_startup(name: str, executable_path: str) -> bool:
    """Add program to Windows startup"""
    try:
        import winreg
        
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, executable_path)
        winreg.CloseKey(key)
        
        return True
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error adding to startup: {e}")
        return False

def remove_from_startup(name: str) -> bool:
    """Remove program from Windows startup"""
    try:
        import winreg
        
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        
        winreg.DeleteValue(key, name)
        winreg.CloseKey(key)
        
        return True
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error removing from startup: {e}")
        return False

def create_firewall_rule(rule_name: str, program_path: str, action: str = "block") -> bool:
    """Create Windows Firewall rule"""
    try:
        command = [
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name={rule_name}',
            'dir=out',
            f'action={action}',
            f'program={program_path}',
            'enable=yes'
        ]
        
        result = subprocess.run(command, capture_output=True, text=True)
        return result.returncode == 0
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error creating firewall rule: {e}")
        return False

def delete_firewall_rule(rule_name: str) -> bool:
    """Delete Windows Firewall rule"""
    try:
        command = [
            'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
            f'name={rule_name}'
        ]
        
        result = subprocess.run(command, capture_output=True, text=True)
        return result.returncode == 0
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error deleting firewall rule: {e}")
        return False

def get_installed_software() -> List[Dict[str, str]]:
    """Get list of installed software"""
    try:
        import winreg
        
        software_list = []
        
        # Check both 32-bit and 64-bit software
        registry_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]
        
        for registry_path in registry_paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
                
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        
                        software_info = {}
                        
                        try:
                            software_info['name'] = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        except FileNotFoundError:
                            continue
                        
                        try:
                            software_info['version'] = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                        except FileNotFoundError:
                            software_info['version'] = "Unknown"
                        
                        try:
                            software_info['publisher'] = winreg.QueryValueEx(subkey, "Publisher")[0]
                        except FileNotFoundError:
                            software_info['publisher'] = "Unknown"
                        
                        try:
                            software_info['install_date'] = winreg.QueryValueEx(subkey, "InstallDate")[0]
                        except FileNotFoundError:
                            software_info['install_date'] = "Unknown"
                        
                        software_list.append(software_info)
                        winreg.CloseKey(subkey)
                        
                    except Exception:
                        continue
                
                winreg.CloseKey(key)
                
            except Exception:
                continue
        
        return software_list
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error getting installed software: {e}")
        return []

def get_windows_services() -> List[Dict[str, Any]]:
    """Get list of Windows services"""
    try:
        import psutil
        
        services = []
        
        for service in psutil.win_service_iter():
            try:
                service_info = service.as_dict()
                services.append({
                    'name': service_info.get('name'),
                    'display_name': service_info.get('display_name'),
                    'status': service_info.get('status'),
                    'start_type': service_info.get('start_type'),
                    'pid': service_info.get('pid'),
                    'binpath': service_info.get('binpath'),
                    'username': service_info.get('username'),
                    'description': service_info.get('description')
                })
            except Exception:
                continue
        
        return services
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error getting Windows services: {e}")
        return []

def get_startup_programs() -> List[Dict[str, str]]:
    """Get list of startup programs"""
    try:
        import winreg
        
        startup_programs = []
        
        # Check multiple startup locations
        startup_locations = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
        ]
        
        for hive, subkey_path in startup_locations:
            try:
                key = winreg.OpenKey(hive, subkey_path)
                
                for i in range(winreg.QueryInfoKey(key)[1]):  # Number of values
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        startup_programs.append({
                            'name': name,
                            'command': value,
                            'location': f"{hive}\\{subkey_path}"
                        })
                    except Exception:
                        continue
                
                winreg.CloseKey(key)
                
            except Exception:
                continue
        
        return startup_programs
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error getting startup programs: {e}")
        return []

def check_windows_defender_status() -> Dict[str, Any]:
    """Check Windows Defender status"""
    try:
        # Use PowerShell to check Defender status
        powershell_command = """
        Get-MpComputerStatus | Select-Object -Property 
        AntivirusEnabled, RealTimeProtectionEnabled, 
        BehaviorMonitorEnabled, IoavProtectionEnabled,
        NISEnabled, OnAccessProtectionEnabled,
        QuickScanAge, FullScanAge
        """
        
        result = subprocess.run(
            ['powershell', '-Command', powershell_command],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            # Parse PowerShell output
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:  # Header + data
                headers = [h.strip() for h in lines[0].split()]
                values = [v.strip() for v in lines[1].split()]
                
                if len(headers) == len(values):
                    status = dict(zip(headers, values))
                    return {
                        'success': True,
                        'status': status,
                        'antivirus_enabled': status.get('AntivirusEnabled', 'False').lower() == 'true',
                        'realtime_protection': status.get('RealTimeProtectionEnabled', 'False').lower() == 'true',
                        'behavior_monitor': status.get('BehaviorMonitorEnabled', 'False').lower() == 'true',
                        'ioav_protection': status.get('IoavProtectionEnabled', 'False').lower() == 'true',
                        'nis_enabled': status.get('NISEnabled', 'False').lower() == 'true',
                        'on_access_protection': status.get('OnAccessProtectionEnabled', 'False').lower() == 'true',
                        'quick_scan_age': int(status.get('QuickScanAge', '0')),
                        'full_scan_age': int(status.get('FullScanAge', '0'))
                    }
        
        return {
            'success': False,
            'error': 'Failed to get Windows Defender status',
            'details': result.stderr if result.stderr else 'Unknown error'
        }
        
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'Command timed out',
            'details': 'PowerShell command took too long to execute'
        }
    except Exception as e:
        return {
            'success': False,
            'error': 'Error checking Windows Defender status',
            'details': str(e)
        }