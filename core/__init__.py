"""
EDR Windows Agent - Core Package
"""

from .agent import EDRAgent
from .enhanced_agent_core import EnhancedEDRAgent
from .connection import ServerConnection
from .scheduler import TaskScheduler

__version__ = "2.0.0"
__author__ = "EDR System"

__all__ = [
    'EDRAgent',
    'EnhancedEDRAgent',
    'ServerConnection',
    'TaskScheduler'
]