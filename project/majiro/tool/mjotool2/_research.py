#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script research

Personal script used in __main__ for programmatically searching mjo scripts for
instructions of interest. This script changes often, so it may be excluded from commits.

__main__ will run fine, even if this module is missing
"""

__version__ = '0.0.1'
__date__    = '2021-04-09'
__author__  = 'Robert Jordan'

#######################################################################################

import argparse, os, struct
from ._util import DummyColors, Colors
from .script import Instruction, MjoScript, Function, ILFormat
from .analysis import ControlFlowGraph


## RESEARCH HANDLING ##

def _init_parser(parser:argparse.ArgumentParser):
    """Add any extra arguments to the parser
    """
    pass

def _init_args(args):
    """Do any initial setup after parser.parse_args() is run
    """
    pass

# do whatever we need to with any input files
def do_research(args, filename:str, *, options:ILFormat=ILFormat.DEFAULT):
    """Do whatever we need to with input script files
    """
    #script:MjoScript = read_script(filename)
    #cfg:ControlFlowGraph = analyze_script(script)
    pass


## READ / ANALYZE SCRIPT ##

def read_script(filename:str) -> MjoScript:
    """Read and return a MjoScript from file
    """
    with open(filename, 'rb') as f:
        return MjoScript.disassemble_script(f)

def analyze_script(script:MjoScript) -> ControlFlowGraph:
    """Return the analysis of a script's control flow, blocks, functions, etc.

    argument can also be a filename
    """
    if isinstance(script, str):  # is argument filename?
        script = read_script(script)
    return ControlFlowGraph.build_from_script(script)


#######################################################################################

## RESEARCH FUNCTIONS ##

#...
