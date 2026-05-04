"""
AuthFlaw AI Attack Modules
"""

from .jwt_attacks import JWTAttacks
from .sqli_bypass import SQLiBypass
from .mass_assignment import MassAssignment

__all__ = ['JWTAttacks', 'SQLiBypass', 'MassAssignment']
