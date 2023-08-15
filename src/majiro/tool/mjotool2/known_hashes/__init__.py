#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Known syscall, usercall, and variable hashes, and callbacks and group names.
"""

__version__ = '1.0.0'
__date__    = '2021-05-04'
__author__  = 'Robert Jordan'

__all__ = ['LOCAL_VARS', 'LOCAL_VARS_LOOKUP', 'THREAD_VARS', 'THREAD_VARS_LOOKUP', 'SAVEFILE_VARS', 'SAVEFILE_VARS_LOOKUP', 'PERSISTENT_VARS', 'PERSISTENT_VARS_LOOKUP', 'FUNCTIONS', 'FUNCTIONS_LOOKUP', 'SYSCALLS', 'SYSCALLS_LOOKUP', 'GROUPS', 'GROUPS_LOOKUP', 'CALLBACKS', 'CALLBACKS_LOOKUP', 'SYSCALLS_LIST', 'VARIABLES', 'VARIABLES_LOOKUP']

#######################################################################################

## runtime imports:
# from ..crypt import hash32  # used in find_group()

from itertools import chain
from typing import Dict, Optional

from ._hashes import *


# combine all variable type hashes into one dictionary for easy lookup,
#  since this isn't handled by the auto-generated file
VARIABLES:Dict[int,str] = dict(chain(LOCAL_VARS.items(), THREAD_VARS.items(), SAVEFILE_VARS.items(), PERSISTENT_VARS.items()))
VARIABLES_LOOKUP:Dict[str,int] = dict((v,k) for k,v in VARIABLES.items())

# function name used calculate hashes in GROUPS lookup dictionary
GROUP_HASHNAME:str = '$main'

def find_group(hashvalue:int, name:str=GROUP_HASHNAME) -> Optional[str]:
    """find_group(0x1d128f30, '$main') -> 'GLOBAL'

    search for a group name that matches the hash value when combined into `name@GROUP`.
    """
    if name is GROUP_HASHNAME: # this is built into _hashes.GROUPS dict
        return GROUPS.get(hashvalue, None)

    from ..crypt import hash32
    init = hash32(f'{name}@')
    for group in GROUPS:
        if hash32(group, init) == hashvalue:
            return group
    return None


del chain, Dict, Optional  # cleanup declaration-only imports
