"""
Toxic Combination

Trigger/Dispatcher combinations that should never be seen,
even in development and test environments.
"""

from .caffael_exception import CaffaelException


class ToxicCombinationError(CaffaelException):
    pass
