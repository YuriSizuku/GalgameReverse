#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script tools library
"""

__version__ = '0.1.1'
__date__    = '2023-08-12'
__author__  = 'Robert Jordan, devseed'
__credits__ = '''Original C# implementation by AtomCrafty - 2021
Converted to Python library by Robert Jordan - 2021
'''

#######################################################################################

from .opcodes import Opcode
from .script import Instruction, MjoScript
from .analysis import ControlFlowGraph

from . import crypt
from . import flags
from . import opcodes
from . import script
from . import analysis

