#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script IL disassembler tool
"""

__version__ = '0.1.1'
__date__    = '2023-08-12'
__author__  = 'Robert Jordan, devseed'
__credits__ = '''Original C# implementation by AtomCrafty - 2021
Converted to Python library by Robert Jordan - 2021
'''

#######################################################################################

import copy, csv, os
from ._util import DummyColors, Colors
from .script import MjoScript, ILFormat
from .analysis import ControlFlowGraph
from .assembler import MjILAssembler
from . import known_hashes

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

def parse_script(filename:str) -> MjILAssembler:
    """Returns an assembler after parsing an .mjil assembler language file
    """
    return MjILAssembler(filename)

## PRINT SCRIPT ##

def print_script(filename:str, script:MjoScript, *, options:ILFormat=ILFormat.DEFAULT):
    """Print analyzed script IL instructions and blocks to console (PRINTS A LOT OF LINE)
    """
    cfg:ControlFlowGraph = analyze_script(script)
    options.set_address_len(script.bytecode_size)
    colors = options.colors

    # include extra indentation formatting for an easier time reading
    print('{BRIGHT}{WHITE}/// {}{RESET_ALL}'.format(os.path.basename(filename), **colors))
    script.print_readmark(options=options)
    # print()

    for function in cfg.functions:
        print()
        function.print_function(options=options)
        for i,basic_block in enumerate(function.basic_blocks):
            print(' ', end='')
            basic_block.print_basic_block(options=options)
            for instruction in basic_block.instructions:
                reskey = script.get_resource_key(instruction, options=options)
                print('  ', end='')
                instruction.print_instruction(options=options, resource_key=reskey)
            if i + 1 < len(function.basic_blocks):
                print(' ')
        function.print_function_close(options=options)
        # print()


## WRITE SCRIPT ##

def disassemble_script(filename:str, script:MjoScript, outfilename:str, *, options:ILFormat=ILFormat.DEFAULT):
    """Write analyzed script IL instructions and blocks to .mjil file
    """
    options.color = False
    options.set_address_len(script.bytecode_size)
    cfg:ControlFlowGraph = analyze_script(script)

    resfile = reswriter = None
    with open(outfilename, 'wt+', encoding='utf-8') as writer:
      try:
        if options.resfile_directive is not None:
            #respath = os.path.join(os.path.dirname(filename), options.resfile_directive)
            res_f = open(options._resfile_path or options.resfile_directive, 'wt+', encoding='utf-8')
            # sigh, no way to force quotes for one line
            # lineterminator='\n' is required to stop double-line termination caused by default behavior of "\r\n" on Windows
            reswriter = csv.writer(res_f, quoting=csv.QUOTE_MINIMAL, delimiter=',', quotechar='"', lineterminator='\n')
            reswriter.writerow(['Key','Value'])
        # include extra indentation formatting for language grammar VSCode extension
        writer.write('/// {}\n'.format(os.path.basename(filename)))
        writer.write(script.format_readmark(options=options) + '\n')
        # writer.write('\n')

        for function in cfg.functions:
            writer.write('\n')
            writer.write(function.format_function(options=options) + '\n')
            for i,basic_block in enumerate(function.basic_blocks):
                writer.write(' ' + basic_block.format_basic_block(options=options) + '\n')
                for instruction in basic_block.instructions:
                    reskey = script.get_resource_key(instruction, options=options) if reswriter is not None else None
                    if reskey is not None:
                        reswriter.writerow([reskey, instruction.string])
                    writer.write('  ' + instruction.format_instruction(options=options, resource_key=reskey) + '\n')
                if i + 1 < len(function.basic_blocks):
                    writer.write(' \n')
            writer.write(function.format_function_close(options=options) + '\n')
            # writer.write('\n')
        writer.flush()
        if resfile is not None:
            resfile.flush()
      finally:
        if resfile is not None:
            reswriter = None
            #reswriter.close()
            resfile.close()

def assemble_script(script:MjoScript, outfilename:str):
    """Write script to .mjo file
    """
    with open(outfilename, 'wb+') as writer:
        script.signature = MjoScript.SIGNATURE_DECRYPTED
        script.assemble_script(writer)


## MAIN FUNCTION ##

def main(argv:list=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog='python -m mjotool',
        description='Majiro script IL disassembler and assembler tool, support multi encoding asm, such as marked line by [[cp936]]',
        add_help=True,
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Disassembler Options:
[-G|--group] group directive
--------------------------------------------
"NAME" : strip group name from hash names that contain provided group

on|off [-H|--hash]  hashing options
--------------------------------------------
>k| K  : known_hashes  (enable all functionality below)
>a| A  : annotations   (';' comments for known hashes or hash values)
>i| I  : inline_hash   (inline hash function $name for known names)
 e|>E  : explicit_inline_hash  (explicit inline hash function ${name})
>s| S  : syscall_inline_hash   (inline hashing for syscalls - which work by lookup)
>l| L  : int_inline_hash       (inline hashing for matching int literals)
>h| H  : annotate_hex          (hex annotations when inline hash is used)
>g| G  : implicit_local_groups (strip empty @ group names from locals)

on|off [-A|--alias] aliasing/shorthand options
--------------------------------------------
 v|>V  : explicit_varoffset (remove -1 var offset for non-locals)
 m|>M  : modifier_aliases   (modifier flags: inc.x, dec.x, x.inc, x.dec)
 s|>S  : scope_aliases      (scope flags: persist, save, -, loc)
 t|>T  : vartype_aliases    (var type flags: i, r, s, iarr, rarr, sarr)
 l|>L  : typelist_aliases   (type list:      i, r, s, iarr, rarr, sarr)
 f|>F  : functype_aliases   (func arg types: i, r, s, iarr, rarr, sarr)
 d|>D  : explicit_dim0      (always include dimension flag: dim0)

on|off [-F|--format] formatting options
--------------------------------------------
>a| A  : address_labels     (show bytecode addresses before opcodes)
>r| R  : explicit_inline_resource (explicit inline resource function %{name})
""")
    #~~ i|>I  : invert_aliases~~

    class NArgs1or2AppendAction(argparse._AppendAction):
        def __call__(self, parser, args, values, option_string=None):
            #source: <https://stackoverflow.com/a/4195302/7517185>
            if not (1 <= len(values) <= 2):
                raise argparse.ArgumentError(self, 'requires between 1 and 2 arguments')
            if len(values) == 1:
                values.append(None)
                # values = [values[0], values[0]]
            super().__call__(parser, args, values, option_string)

    parser.add_argument('-p','--print', metavar='MJO', action='append',
        help='print mjo script file/directory to the console')
    parser.add_argument('-d','--disasm', metavar=('MJO','MJIL'), nargs='+', action=NArgs1or2AppendAction,
        help='disassemble mjo script file/directory to output file/directory')
    parser.add_argument('-a','--asm', metavar=('MJIL','MJO'), nargs='+', action=NArgs1or2AppendAction,
        help='assemble mjil script file/directory to output file/directory')

    parser.add_argument('-r', '--resfile', metavar='MJRESFILE', dest='resfile', action='store', default=None,
        required=False, help='output resfile directive option (\'*\' expands to mjil name, no ext)')
    parser.add_argument('-G', '--group', metavar='NAME', dest='group', action='store', default=None,
        required=False, help='group name directive disassembler option')
    parser.add_argument('-O', '--opcode-pad', metavar='PADDING', dest='opcode_pad', type=int, action='store', default=None,
        required=False, help='spacing between opcodes and operands')
    parser.add_argument('-H', '--hash', metavar='FLGS', dest='hash_flags', action='store', default='',
        required=False, help='unhashing disassembler options')
    parser.add_argument('-A', '--alias', metavar='FLGS', dest='alias_flags', action='store', default='',
        required=False, help='alias naming disassembler options')
    parser.add_argument('-F', '--format', metavar='FLGS', dest='format_flags', action='store', default='',
        required=False, help='formatting disassembler options')
    parser.add_argument('-C', '--no-color', dest='color', action='store_false', default=True,
        required=False, help='disable color printing')
    parser.add_argument('--text-encoding', dest='text_encoding', type=str, default='cp932', 
        required=False, help='text encoding for asm')

    HASH_FLAGNAMES:dict = {
        'a': 'annotations',
        'k': 'known_hashes',
        'i': 'inline_hash',
        'e': 'explicit_inline_hash',
        's': 'syscall_inline_hash',
        'l': 'int_inline_hash',
        'h': 'annotate_hex',
        'g': 'implicit_local_groups',
    }
    ALIAS_FLAGNAMES:dict = {
        'v': 'explicit_varoffset',
        'm': 'modifier_aliases',
        's': 'scope_aliases',
        't': 'vartype_aliases',
        'l': 'typelist_aliases',
        'f': 'functype_aliases',
        'd': 'explicit_dim0',
    }
    FORMAT_FLAGNAMES:dict = {
        'a': 'address_labels',
        'r': 'explicit_inline_resource',
    }

    HASH_FLAGNAME_LEN:int = max(len(n) for n in HASH_FLAGNAMES.values())
    ALIAS_FLAGNAME_LEN:int = max(len(n) for n in ALIAS_FLAGNAMES.values())
    FORMAT_FLAGNAME_LEN:int = max(len(n) for n in FORMAT_FLAGNAMES.values())
    FLAGNAME_LEN:int = max(HASH_FLAGNAME_LEN, ALIAS_FLAGNAME_LEN, FORMAT_FLAGNAME_LEN)
    
    try:  # try adding research module
        from ._research import _init_parser, _init_args, do_research
        parser.add_argument('-R', '--research', action='store_true', default=False,
        required=False, help='run custom research functions that are not intended for use')
        _init_parser(parser)  # add any custom arguments needed for research
    except ImportError:
        pass  # no _research.py, no problem

    args = parser.parse_args(argv)
    os.environ["TEXT_ENCODING"] = args.text_encoding # for share

    # print(args)
    # return 0

    options:ILFormat = ILFormat()

    ###########################################################################

    options.color  = args.color  # color, disabled by __main__.disassemble_script() when outputting to file
    options.braces = True  # function braces
    options.annotations  = True  # annotations that describe either known hash names, or original hashed values
    options.known_hashes = True  # check for known hash values
    options.inline_hash  = True  # inline hash function $name / ${name} for known hash values
    options.syscall_inline_hash  = True
    options.int_inline_hash      = True   # ldc.i with a known hash value will use inline hash
    options.explicit_inline_hash = False  # always use ${name} over $name
    options.annotate_hex         = True  # hex annotations when inline hash is used
    options.implicit_local_groups= True  # always exclude empty group name from known local names

    options.explicit_varoffset   = False  # exclude -1 offset for non-locals
    options.modifier_aliases     = False  # inc.x, dec.x, x.inc...
    options.invert_aliases       = False  # (there are no aliases)
    options.scope_aliases        = False  # persist, save (shorthands)
    options.vartype_aliases      = False  # i, r, s, iarr... for variable type flags
    options.functype_aliases     = False  # i, r, s, iarr... for function signatures
    options.typelist_aliases     = False  # i, r, s, iarr... for type list operands
    options.explicit_dim0        = False  # a useless feature (but it's legal)

    options.address_labels       = True   # print bytecode address offset labels before opcodes
    options.opcode_padding       = 13     # number of absolute padding added from start of opcode (always adds one space after)
    
    options.explicit_inline_resource = True  # always use %{name} over %name
    options.resfile_directive    = None   # output all `text` opcode string operands to csv resource file
    options.group_directive      = None   # removes @GROUP for that matching this setting (DO NOT INCLUDE "@" in NAME)
    # options.group_directive      = "CONSOLE"
    ###########################################################################
    
    colors = Colors if args.color else DummyColors

    if args.group is not None:
        if '@' in args.group:
            raise argparse.ArgumentError('--group', f'"@" character cannot be present in name : {args.group!r}')
        if args.group == 'GROUP':  # special warning just for me :)
            print('{DIM}{YELLOW}[WARNING]{RESET_ALL} {BRIGHT}{RED}specified group name {DIM}{GREEN}{!r}{BRIGHT}{RED}, did you mean {DIM}{GREEN}{!r}{BRIGHT}{RED}?{RESET_ALL}'.format(args.group, 'GLOBAL', **colors))
        options.group_directive = args.group
        print('{DIM}{CYAN}group name:{RESET_ALL}'.format(**colors), '{DIM}{GREEN}{!r}{RESET_ALL}'.format(args.group, **colors))

    if args.resfile is not None:
        if not args.resfile:
            raise argparse.ArgumentError('--resfile', f'resfile name is empty : {args.resfile!r}')
        options.resfile_directive = args.resfile
        resfile_fmt = repr(args.resfile).replace('*', '{BRIGHT}{CYAN}*{DIM}{GREEN}'.format(**colors))
        print('{DIM}{CYAN}rsrc  file:{RESET_ALL}'.format(**colors), '{DIM}{GREEN}{}{RESET_ALL}'.format(resfile_fmt, **colors))

    if args.opcode_pad is not None:
        if args.opcode_pad < 0:
            raise argparse.ArgumentError('--opcode-pad', f'padding less than zero : {args.opcode_pad!r}')
        options.opcode_padding = args.opcode_pad
        print('{DIM}{CYAN}opcode pad:{RESET_ALL}'.format(**colors), '{BRIGHT}{WHITE}{!r}{RESET_ALL}'.format(args.opcode_pad, **colors))
    
    CONSUMED_HASH_FLAGS:set = set()
    CONSUMED_ALIAS_FLAGS:set = set()
    CONSUMED_FORMAT_FLAGS:set = set()

    # visual names for flag on/off modes
    ONOFF:dict = {
        False: '{BRIGHT}{RED}off{RESET_ALL}'.format(**colors),
        True:  '{BRIGHT}{GREEN}on{RESET_ALL}'.format(**colors),
    }

    for f in args.hash_flags:
        if f.lower() not in HASH_FLAGNAMES:
            raise argparse.ArgumentError('--hash', f'unknown flag {f!r}')
        if f.lower() in CONSUMED_HASH_FLAGS:
            raise argparse.ArgumentError('--hash', f'flag {f!r} already used')
        CONSUMED_HASH_FLAGS.add(f.lower())
        opt_name = HASH_FLAGNAMES[f.lower()]
        opt_on = f == f.lower()
        setattr(options, opt_name, opt_on)  # lower=True
        print('{BRIGHT}{YELLOW}hash   opt:{RESET_ALL}'.format(**colors), opt_name.ljust(FLAGNAME_LEN), '=', ONOFF[opt_on])

    for f in args.alias_flags:
        if f.lower() not in ALIAS_FLAGNAMES:
            raise argparse.ArgumentError('--alias', f'unknown flag {f!r}')
        if f.lower() in CONSUMED_ALIAS_FLAGS:
            raise argparse.ArgumentError('--alias', f'flag {f!r} already used')
        CONSUMED_ALIAS_FLAGS.add(f.lower())
        opt_name = ALIAS_FLAGNAMES[f.lower()]
        opt_on = f == f.lower()
        setattr(options, opt_name, opt_on)  # lower=True
        print('{BRIGHT}{BLUE}alias  opt:{RESET_ALL}'.format(**colors), opt_name.ljust(FLAGNAME_LEN), '=', ONOFF[opt_on])

    for f in args.format_flags:
        if f.lower() not in FORMAT_FLAGNAMES:
            raise argparse.ArgumentError('--format', f'unknown flag {f!r}')
        if f.lower() in CONSUMED_FORMAT_FLAGS:
            raise argparse.ArgumentError('--format', f'flag {f!r} already used')
        CONSUMED_FORMAT_FLAGS.add(f.lower())
        opt_name = FORMAT_FLAGNAMES[f.lower()]
        opt_on = f == f.lower()
        setattr(options, opt_name, opt_on)  # lower=True
        print('{BRIGHT}{MAGENTA}format opt:{RESET_ALL}'.format(**colors), opt_name.ljust(FLAGNAME_LEN), '=', ONOFF[opt_on])


    research:bool = getattr(args, 'research', False)
    if research:
        _init_args(args)  # research one-time setup

    base_options = options

    def prepare_options(base_options, filename:str=None, *, color:bool=...):
        new_options = copy.copy(base_options)
        if color is not Ellipsis:
            new_options.color = color
        if new_options.resfile_directive and filename is not None:
            new_options.resfile_directive = new_options.resfile_directive.replace('*', os.path.splitext(os.path.basename(filename))[0])
            new_options._resfile_path = os.path.join(os.path.dirname(filename), new_options.resfile_directive)
        return new_options


    # [--print]  loop through input files/directories
    for infile in (args.print or []):
        options = prepare_options(base_options, infile)
        if not research:
            print('Printing:', infile)
        if os.path.isdir(infile):  # directory of .mjo files
            for name in os.listdir(infile):
                path = os.path.join(infile, name)
                if not os.path.isfile(path) or not os.path.splitext(path)[1].lower() == '.mjo':
                    continue
                
                if research:
                    do_research(args, path, options=options)
                else:
                    script = read_script(path)
                    print_script(path, script, options=options)
        else:  # single file
            if research:
                do_research(args, infile, options=options)
            else:
                script = read_script(infile)
                print_script(infile, script, options=options)
        if not research:
            print()

    # [--disasm]  loop through input files/directories
    for infile,outfile in (args.disasm or []):
        if not research:
            print('Disassembling:', infile)
        if os.path.isdir(infile):  # directory of .mjo files
            if outfile is None:
                outfile = infile
            elif os.path.isfile(outfile):
                raise Exception('Cannot use output "{!s}" because it is not a directory'.format(outfile))
            elif not os.path.exists(outfile):
                raise Exception('Output directory "{!s}" does not exist'.format(outfile))

            last_name = ''
            for name in os.listdir(infile):
                options = prepare_options(base_options, name)

                path = os.path.join(infile, name)
                if not os.path.isfile(path) or not os.path.splitext(path)[1].lower() == '.mjo':
                    continue
                print('Disassembling:', name.ljust(len(last_name)*2), end='\r')  #HACK: *2 to handle double-width CJK
                last_name = name

                outpath = os.path.join(outfile, os.path.splitext(name)[0] + '.mjil')
                script = read_script(path)
                disassemble_script(path, script, outpath, options=options)
            print('Done'.ljust(len(f'Disassembling: ') + len(last_name)*2))  #HACK: *2 to handle double-width CJK
        else:  # single file
            options = prepare_options(base_options, outfile)

            outpath = outfile
            if outfile is None:
                if os.path.splitext(infile)[1].lower() == '.mjil':  # avoid overwriting input file by accident
                    raise Exception(f'--disasm file {infile!r} has \'.mjil\' extension, with no output file passed')
                outpath = os.path.splitext(infile)[0] + '.mjil'
            elif os.path.isdir(outfile):  # write to outfile/infilename.mjil
                name = os.path.basename(infile)
                outpath = os.path.join(outfile, os.path.splitext(name)[0] + '.mjil')
            script = read_script(infile)
            disassemble_script(infile, script, outpath, options=options)
        if not research:
            print()

    # [--asm]  loop through input files/directories
    for infile,outfile in (args.asm or []):
        if not research:
            print('Assembling:', infile)
        if os.path.isdir(infile):  # directory of .mjil files
            if outfile is None:
                outfile = infile
            elif os.path.isfile(outfile):
                raise Exception('Cannot use output "{!s}" because it is not a directory'.format(outfile))
            elif not os.path.exists(outfile):
                raise Exception('Output directory "{!s}" does not exist'.format(outfile))

            last_name = ''
            for name in os.listdir(infile):
                options = prepare_options(base_options, name)

                path = os.path.join(infile, name)
                if not os.path.isfile(path) or not os.path.splitext(path)[1].lower() == '.mjil':
                    continue
                print('Assembling:', name.ljust(len(last_name)*2), end='\r')  #HACK: *2 to handle double-width CJK
                last_name = name
                
                outpath = os.path.join(outfile, os.path.splitext(name)[0] + '.mjo')
                assembler = parse_script(path)
                assembler.read()
                assemble_script(assembler.script, outpath)
            print('Done'.ljust(len('Assembling: ') + len(last_name)*2))  #HACK: *2 to handle double-width CJK
        else:  # single file
            options = prepare_options(base_options, infile)

            outpath = outfile
            if outfile is None:
                if os.path.splitext(infile)[1].lower() == '.mjo':  # avoid overwriting input file by accident
                    raise Exception(f'--asm file {infile!r} has \'.mjo\' extension, with no output file passed')
                outpath = os.path.splitext(infile)[0] + '.mjo'
            elif os.path.isdir(outfile):  # write to outfile/infilename.mjil
                name = os.path.basename(infile)
                outpath = os.path.join(outfile, os.path.splitext(name)[0] + '.mjo')
            assembler = parse_script(infile)
            assembler.read()
            assemble_script(assembler.script, outpath)
        if not research:
            print()

    return 0


## MAIN CONDITION ##

if __name__ == '__main__':
    exit(main())

