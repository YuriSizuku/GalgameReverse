"""
export or import text from global-metadata.dat
  v0.2, developed by devseed

refer:
  https://github.com/JeremieCHN/MetaDataStringEditor
  https://github.com/Kasuromi/libil2cpp
"""

import os
import sys
import cffi
import argparse
from io import BytesIO

__VERSION__ = 200

# ftext functions
from typing import List, Union, Tuple, Dict
from dataclasses import dataclass

@dataclass
class ftext_t:
    addr: int = 0
    size: int = 0
    text: str = ""

def save_ftext(ftexts1: List[ftext_t], ftexts2: List[ftext_t], 
        outpath: str = None, *, encoding="utf-8", width_index = (5, 6, 3)) -> List[str]:
    """
    format text, such as ●num|addr|size● text
    :param ftexts1[]: text dict array in '○' line, 
    :param ftexts2[]: text dict array in '●' line
    :return: ftext lines
    """

    width_num, width_addr, width_size = width_index
    if width_num==0: width_num = len(str(len(ftexts1)))
    if width_addr==0: width_addr = len(hex(max(t.addr for t in ftexts1))) - 2
    if width_size==0: width_size = len(hex(max(t.size for t in ftexts1))) - 2

    lines = []
    fstr1 = "○{num:0%dd}|{addr:0%dX}|{size:0%dX}○ {text}\n" \
            % (width_num, width_addr, width_size)
    fstr2 = fstr1.replace('○', '●')
    if not ftexts1: ftexts1 = [None] * len(ftexts2)
    if not ftexts2: ftexts2 = [None] * len(ftexts1)
    for i, (t1, t2) in enumerate(zip(ftexts1, ftexts2)):
        if t1: lines.append(fstr1.format(num=i, addr=t1.addr, size=t1.size, text=t1.text))
        if t2: lines.append(fstr2.format(num=i, addr=t2.addr, size=t2.size, text=t2.text))
        lines.append("\n")

    if outpath:
        with open(outpath, "wt", encoding="utf-8") as fp:
            fp.writelines(lines)

    return lines 

def load_ftext(inpath: str, *, encoding="utf-8") -> Tuple[List[ftext_t], List[ftext_t]]:
    """
    format text, such as ●num|addr|size● text
    :param inobj: can be path, or lines[], in the end, no \r \n
    :return: ftexts1[]: text dict array in '○' line, 
             ftexts2[]: text dict array in '●' line
    """

    ftexts1, ftexts2 = [], []
    with open(inpath, "rt", encoding="utf-8") as fp:
        lines: List[str] = fp.readlines()

    if len(lines) > 0: lines[0] = lines[0].lstrip("\ufeff") # remove bom
    for line in lines:
        line = line.rstrip("\n").rstrip("\r") # must remove CR LF
        if len(line) <= 0: continue
        indicator = line[0]
        if indicator == "#": continue
        if indicator not in {"○", "●"}: continue
        _, t1, *t2 = line.split(indicator)
        t2 = "".join(t2)
        ftext = ftext_t(-1, 0, t2[1:])
        try: 
            _, t12, t13 = t1.split('|')
            ftext.addr, ftext.size = int(t12, 16), int(t13, 16)
        except ValueError: pass 
        if indicator=='○': ftexts1.append(ftext)
        else: ftexts2.append(ftext)

    return ftexts1, ftexts2

# il2cpp functions
ffi = cffi.FFI()
ffi.cdef("""
typedef struct Il2CppGlobalMetadataHeader
{
    uint32_t sanity;
    int32_t version;
    int32_t stringLiteralOffset; // string data for managed code
    int32_t stringLiteralCount;
    int32_t stringLiteralDataOffset;
    int32_t stringLiteralDataCount;
    int32_t stringOffset; // string data for metadata
    int32_t stringCount;
    int32_t eventsOffset; // Il2CppEventDefinition
    int32_t eventsCount;
    int32_t propertiesOffset; // Il2CppPropertyDefinition
    int32_t propertiesCount;
    int32_t methodsOffset; // Il2CppMethodDefinition
    int32_t methodsCount;
    int32_t parameterDefaultValuesOffset; // Il2CppParameterDefaultValue
    int32_t parameterDefaultValuesCount;
    int32_t fieldDefaultValuesOffset; // Il2CppFieldDefaultValue
    int32_t fieldDefaultValuesCount;
    int32_t fieldAndParameterDefaultValueDataOffset; // uint8_t
    int32_t fieldAndParameterDefaultValueDataCount;
    int32_t fieldMarshaledSizesOffset; // Il2CppFieldMarshaledSize
    int32_t fieldMarshaledSizesCount;
    int32_t parametersOffset; // Il2CppParameterDefinition
    int32_t parametersCount;
    int32_t fieldsOffset; // Il2CppFieldDefinition
    int32_t fieldsCount;
    int32_t genericParametersOffset; // Il2CppGenericParameter
    int32_t genericParametersCount;
    int32_t genericParameterConstraintsOffset; // TypeIndex
    int32_t genericParameterConstraintsCount;
    int32_t genericContainersOffset; // Il2CppGenericContainer
    int32_t genericContainersCount;
    int32_t nestedTypesOffset; // TypeDefinitionIndex
    int32_t nestedTypesCount;
    int32_t interfacesOffset; // TypeIndex
    int32_t interfacesCount;
    int32_t vtableMethodsOffset; // EncodedMethodIndex
    int32_t vtableMethodsCount;
    int32_t interfaceOffsetsOffset; // Il2CppInterfaceOffsetPair
    int32_t interfaceOffsetsCount;
    int32_t typeDefinitionsOffset; // Il2CppTypeDefinition
    int32_t typeDefinitionsCount;
    int32_t imagesOffset; // Il2CppImageDefinition
    int32_t imagesCount;
    int32_t assembliesOffset; // Il2CppAssemblyDefinition
    int32_t assembliesCount;
    int32_t metadataUsageListsOffset; // Il2CppMetadataUsageList
    int32_t metadataUsageListsCount;
    int32_t metadataUsagePairsOffset; // Il2CppMetadataUsagePair
    int32_t metadataUsagePairsCount;
    int32_t fieldRefsOffset; // Il2CppFieldRef
    int32_t fieldRefsCount;
    int32_t referencedAssembliesOffset; // int32_t
    int32_t referencedAssembliesCount;
    int32_t attributesInfoOffset; // Il2CppCustomAttributeTypeRange
    int32_t attributesInfoCount;
    int32_t attributeTypesOffset; // TypeIndex
    int32_t attributeTypesCount;
    int32_t unresolvedVirtualCallParameterTypesOffset; // TypeIndex
    int32_t unresolvedVirtualCallParameterTypesCount;
    int32_t unresolvedVirtualCallParameterRangesOffset; // Il2CppRange
    int32_t unresolvedVirtualCallParameterRangesCount;
    int32_t windowsRuntimeTypeNamesOffset; // Il2CppWindowsRuntimeTypeNamePair
    int32_t windowsRuntimeTypeNamesSize;
    int32_t exportedTypeDefinitionsOffset; // TypeDefinitionIndex
    int32_t exportedTypeDefinitionsCount;
} Il2CppGlobalMetadataHeader;

typedef int32_t StringLiteralIndex;
typedef struct Il2CppStringLiteral
{
    uint32_t length;
    StringLiteralIndex dataIndex;
} Il2CppStringLiteral;

""", pack=4)

def export_globalmeata_text(inpath, outpath=None):
    with open(inpath, "rb") as fp:
        data = memoryview(fp.read())
    header = ffi.from_buffer("struct Il2CppGlobalMetadataHeader*", data)
    assert header.sanity == 0xFAB11BAF, "il2cpp_header sanity wrong"
    ftexts: List[ftext_t] = []
    n = header.stringLiteralCount // ffi.sizeof("struct Il2CppStringLiteral")
    print(f"[export_globalmeata_text] contains {n} stringLiteral")
    
    stringliteral = ffi.from_buffer("struct Il2CppStringLiteral*", data[header.stringLiteralOffset:])
    for i in range(n):
        offset = (stringliteral + i).dataIndex + header.stringLiteralDataOffset
        length = (stringliteral + i).length
        if length == 0: continue
        textdata = bytes(data[offset: offset+length])
        if len(list(filter(
            lambda x: x < 0x20 and x not in {ord("\n"), ord("\r"), ord("\t")}, 
            textdata))) > 0 : continue
        text = textdata.decode("utf8")
        text = text.replace('\n', r'[\n]').replace('\r', r'[\r]')
        ftexts.append(ftext_t(offset, length, text))
    
    save_ftext(ftexts, ftexts, outpath)

    return ftexts

def import_globalmeta_text(inpath, ftextpath, outpath=None, keepoffset=False):
    with open(inpath, "rb") as fp:
        data = memoryview(bytearray(fp.read()))
    header = ffi.from_buffer("struct Il2CppGlobalMetadataHeader*", data)
    assert header.sanity == 0xFAB11BAF, "il2cpp_header sanity wrong"
    ftexts: List[ftext_t] = []
    n = header.stringLiteralCount // ffi.sizeof("struct Il2CppStringLiteral")
    print(f"[import_globalmeta_text] contains {n} stringLiteral")

    bufio = BytesIO()
    ftexts1, ftexts2 = load_ftext(ftextpath)
    addrmap: Dict[int, ftext_t] = {t.addr: t for t in ftexts2}
    stringliteral = ffi.from_buffer("struct Il2CppStringLiteral*", data[header.stringLiteralOffset:])
    for i in range(n):
        offset = (stringliteral + i).dataIndex + header.stringLiteralDataOffset
        length = (stringliteral + i).length
        if length == 0: 
            (stringliteral + i).dataIndex = bufio.tell()
            continue
        if offset not in addrmap: 
            textdata = bytes(data[offset: offset+length])
        else: 
            text = addrmap[offset].text.replace(r'[\n]','\n').replace(r'[\r]', '\r')
            textdata = text.encode("utf8")
        
        if keepoffset:
            targetsize = (stringliteral + i).length
            if len(textdata) >= targetsize: 
                textdata = textdata[:targetsize]
            else:
                (stringliteral + i).length = len(textdata)
                textdata += b"\x00" * (targetsize - len(textdata))
        else: 
            (stringliteral + i).length = len(textdata)
            (stringliteral + i).dataIndex = bufio.tell()

        bufio.write(textdata)
    
    if bufio.tell() % 4: bufio.write(b"\x00" * (4 - bufio.tell()%4))
    
    print(f"[import_globalmeta_text] oldsize=0x{header.stringLiteralDataCount:x}, newsize=0x{bufio.tell():x}")
    if bufio.tell() <= header.stringLiteralDataCount:
        offset = header.stringLiteralDataOffset
        data[offset: offset + bufio.tell()] = bufio.getbuffer()
        data2 = data
    else: # append in file
        header.stringLiteralDataOffset = len(data)
        data2 = bytes(data) + bufio.getvalue()
    header.stringLiteralDataCount = bufio.tell()

    if outpath:
        with open(outpath, "wb") as fp:
            fp.write(data2)

    return data2

def debug():
    pass

def cli(cmdstr=None):
    parser = argparse.ArgumentParser(description=
            "Unity global-metadata cli tools"
            "\n  v0.2, developed by devseed")
    parser.add_argument("method", choices=["export_text", "import_text"], help="operation method")
    parser.add_argument("globalmetapath", help="global-metadata.dat path")
    parser.add_argument("-o", "--outpath", default=None)
    parser.add_argument("-i", "--inpath", help="ftextpath", default=None)
    parser.add_argument("--keepoffset", help="keep the origin offset", action="store_true")
    args = parser.parse_args(cmdstr.split(" ") if cmdstr else None)

    method = args.method
    globalmetapath, outpath = args.globalmetapath, args.outpath
    keepoffset = args.keepoffset

    if method == 'export_text': 
        export_globalmeata_text(globalmetapath, outpath)
    elif method == 'import_text':
        ftextpath = args.inpath
        if ftextpath == None:
            raise ValueError(f"need to specific --inpath (ftextpath)")
        import_globalmeta_text(globalmetapath, ftextpath, outpath, keepoffset=keepoffset)
    else: raise ValueError(f"{method} not support!")

if __name__ == "__main__":
    cli()

"""
history:
v0.1, initial version
v0.1.1, use 0x4 align (actually this doesn't cause switch crash, even origin file makes crash)
v0.2, change command line to argparser
"""