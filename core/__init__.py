"""
EDR Windows Agent - Core Module
"""

from .agent import EDRAgent
from .connection import ServerConnection
from .scheduler import TaskScheduler

__version__ = "2.0.0"
__author__ = "EDR System"

__all__ = [
    'EDRAgent',
    'ServerConnection', 
    'TaskScheduler'
]