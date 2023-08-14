#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""
"""

__version__ = '0.1.0'
__date__    = '2021-05-03'
__author__  = 'Robert Jordan'

__all__ = ['MajiroData', 'MajiroData_Syscalls', 'MajiroData_Groups', 'MajiroData_Functions', 'MajiroData_Variables', 'MajiroData_Locals', 'MajiroData_Callbacks', 'MajiroData_Games', 'SheetSyscalls', 'SheetGroups', 'SheetFunctions', 'SheetVariables', 'SheetLocals', 'SheetCallbacks', 'SheetGames']

#######################################################################################

from .googlesheets import GoogleSheet
from .rowtypes import RowSyscall, RowGroup, RowFunction, RowVariable, RowLocal, RowCallback, RowGame
from .csvsheet import CsvSheet

#######################################################################################

#region ## GOOGLE SHEET IDS ##

MajiroData:GoogleSheet = GoogleSheet(r"1p03_q6VTfYQEjlDhpypgoPdLQREhXwXz2ObTUkz5dlY")
## Hash|Address|Return|Name|Arguments|Status|Notes
MajiroData_Syscalls:GoogleSheet = MajiroData.with_gid(0)
## Hash|Source|Name|Status|Notes
MajiroData_Groups:GoogleSheet = MajiroData.with_gid(1562764366)
## Hash|Source|Return|Name|Group|Arguments|Status|Notes
MajiroData_Functions:GoogleSheet = MajiroData.with_gid(72122782)
## Hash|Source|Scope|Type|Name|Group|Status|Notes
MajiroData_Variables:GoogleSheet = MajiroData.with_gid(380736744)
## Hash|Type|Name|Status|Notes
MajiroData_Locals:GoogleSheet = MajiroData.with_gid(1596196937)
## Hash|Invoked by|Name|Status|Notes
MajiroData_Callbacks:GoogleSheet = MajiroData.with_gid(750354284)
## Release|Developer|Name|Engine Build Date|Notes
MajiroData_Games:GoogleSheet = MajiroData.with_gid(2017266804)

#endregion

class SheetSyscalls(CsvSheet, sheetname='Syscalls', sheetid=MajiroData_Syscalls, rowtype=RowSyscall):
    pass

class SheetGroups(CsvSheet, sheetname='Groups', sheetid=MajiroData_Groups, rowtype=RowGroup):
    pass

class SheetFunctions(CsvSheet, sheetname='Functions', sheetid=MajiroData_Functions, rowtype=RowFunction):
    pass

class SheetVariables(CsvSheet, sheetname='Variables', sheetid=MajiroData_Variables, rowtype=RowVariable):
    pass

class SheetLocals(CsvSheet, sheetname='Locals', sheetid=MajiroData_Locals, rowtype=RowLocal):
    pass

class SheetCallbacks(CsvSheet, sheetname='Callbacks', sheetid=MajiroData_Callbacks, rowtype=RowCallback):
    pass

class SheetGames(CsvSheet, sheetname='Games', sheetid=MajiroData_Games, rowtype=RowGame):
    pass

