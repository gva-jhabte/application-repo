"""
Trigger Termination

Used to signal the Trigger should Terminate
"""

from .caffael_exception import CaffaelException


class StopTrigger(CaffaelException):
    pass
