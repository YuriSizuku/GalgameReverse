# mjotool2

A python module program for disassembling Majiro `.mjo` scripts, and outputting analyzed instruction blocks. Multi encoding asm support by devseed.  You can use `--text-encoding` option for default text and `[[cp936]]` at the start of the string in seperate.  

Default behavior is to print an input script to the console, **which is VERY VERBOSE**.

## Usage

```
usage: python -m mjotool [-h] [-p MJO] [-d MJO MJILE] [-a MJILE MJO]
                         [-G NAME] [-H FLGS] [-A FLGS] [-C] [-R]

Majiro script IL disassembler and assembler tool

optional arguments:
  -h, --help            show this help message and exit
  -p, --print MJO       print mjo script file/directory to the console
  -d, --disasm MJO MJIL disassemble mjo script file/directory to output file/directory
  -a, --asm MJIL MJO    assemble mjil script file/directory to output file/directory
  -G, --group NAME      group name directive disassembler option
  -H, --hash FLGS       unhashing disassembler options
  -A, --alias FLGS      alias naming disassembler options
  -C, --no-color        disable color printing
  --text_encoding       asm text encoding default cp932 

internal arguments:
  -R, --research        run custom research functions that are not intended
                        for use

Disassembler Options:
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
```
