/**
 * dump wamsoft hxv4 keys (hx decrypt index, cx decrypt index)
 *   v0.1, developed by devseed
 * 
 * usage:
 *    npm i  @types/frida-gum --save
 *    frida -l krkr_hxv4_dumpkey.js -f dc5ph.exe
 *    (the key will show on console, block will dump to control_block.bin)
 * 
 * tested games:
 *   D.C.5 Plus Happiness ～ダ・カーポ5～プラスハピネス
 *   エッチで一途なド田舎兄さまと、古式ゆかしい病弱妹
 * 
 * refer: 
 *   https://github.com/crskycode/GARbro/blob/master/ArcFormats/KiriKiri/HxCrypt.cs
 */

'use strict'

/**
 * @param {ArrayBuffer} buf 
 */
function buf2hexstr(buf, sep="") {
    const arr = new Uint8Array(buf);
    const hexs = [];
    for(let i=0; i<arr.length; i++) {
        let hex = arr[i].toString(16);
        hex = ('00' + hex).slice(-2);
        hexs.push(hex);
    }
    return hexs.join(sep);
}

var dllpath;
var cxtpm_load_flag = false;
const LoadLibraryW = Module.getExportByName('kernel32.dll', 'LoadLibraryW');
Interceptor.attach(LoadLibraryW, {
    onEnter(args) {
        dllpath = args[0].readUtf16String();
        if(dllpath.search("krkr_") > 0) cxtpm_load_flag = true;
    },
    onLeave(retval) {
        if(cxtpm_load_flag==false) return;
        cxtpm_load_flag = false;

        let m;
        var hmod = Process.findModuleByAddress(retval.toUInt32())
        console.log(`load ${dllpath} at 0x${hmod.base.toString(16)}`);
        
        // .text:1001F0B0 55                push    ebp
        // .text:1001F0B1 8B EC             mov     ebp, esp
        // .text:1001F0B3 81 EC D4 00 00 00 sub     esp, 0D4h
        // .text:1001F0B9 A1 48 B2 0A 10    mov     eax, ___security_cookie
        // .text:1001F0BE 33 C5             xor     eax, ebp
        // .text:1001F0C0 89 45 FC          mov     [ebp+var_4], eax
        // .text:1001F0C3 8B 45 14          mov     eax, [ebp+key] // [ebp+14h] key, [ebp+18h] nonce
        // .text:1001F0C6 53                push    ebx
        // .text:1001F0C7 56                push    esi
        // .text:1001F0C8 8B 75 08          mov     esi, [ebp+this]
        // .text:1001F0CB 57                push    edi
        // .text:1001F0CC 50                push    eax
        // .text:1001F0CD 8D 85 7C FF FF FF lea     eax, [ebp+state0]
        var hxpoint = 0; // decrypt hx index
        m = Memory.scanSync(hmod.base, hmod.size, "8B 45 14 53 56 8B 75 08 57 50");
        if(m.length == 1) hxpoint = m[0].address;
        console.log(`hxpoint at 0x${hxpoint.toUInt32().toString(16)}`);
        Interceptor.attach(hxpoint, {
            onEnter(args){
                if(!hxpoint) return;
                let key = this.context.ebp.add(0x14).readPointer().readByteArray(32);
                let nonce = this.context.ebp.add(0x18).readPointer().readByteArray(16);
                console.log(`* key ${buf2hexstr(key)}`);
                console.log(`* nonce ${buf2hexstr(nonce)}`);
                hxpoint = 0;
        }});


        // 7B5B3C60 | 55                 | push ebp                                |
        // 7B5B3C61 | 8BEC               | mov ebp,esp                             |
        // 7B5B3C63 | 83EC 34            | sub esp,34                              |
        // 7B5B3C66 | A1 48B2647B        | mov eax,dword ptr ds:[7B64B248]         |
        // 7B5B3C6B | 33C5               | xor eax,ebp                             |
        // 7B5B3C6D | 8945 FC            | mov dword ptr ss:[ebp-4],eax            |
        // 7B5B3C70 | 807D 10 00         | cmp byte ptr ss:[ebp+10],0              |
        // 7B5B3C74 | 53                 | push ebx                                |
        // 7B5B3C75 | 56                 | push esi                                |
        // 7B5B3C76 | 8B75 08            | mov esi,dword ptr ss:[ebp+8]            |
        // 7B5B3C79 | 57                 | push edi                                |
        // 7B5B3C7A | 8B7D 0C            | mov edi,dword ptr ss:[ebp+C]            |
        // 7B5B3C7D | 8BD9               | mov ebx,ecx                             | ecx:"ﾂ0"
        var cxpoint = 0; // decrypt cx content
        m = Memory.scanSync(hmod.base, hmod.size, "89 45 fc 80 7D 10 00");
        if(m.length == 1) cxpoint = m[0].address;
        console.log(`cxpoint at 0x${cxpoint.toUInt32().toString(16)}`);
        Interceptor.attach(cxpoint, {
            onEnter(args){
                if(!cxpoint) return;
                let filterkey = this.context.ecx.add(0x8).readByteArray(8);
                let mask = this.context.ecx.add(0x10).readU32();
                let offset = this.context.ecx.add(0x14).readU32();
                let randtype = this.context.ecx.add(0x18).readU8();
                let block = this.context.ecx.add(0x20).readByteArray(4096);
                let order = this.context.ecx.add(0x3020).readByteArray(0x11);
                console.log(`* filterkey : ${buf2hexstr(filterkey)}`);
                console.log(`* mask : 0x${mask.toString(16)}`);
                console.log(`* offset : 0x${offset.toString(16)}`);
                console.log(`* randtype : ${randtype.toString()}`);
                console.log(`* order : ${buf2hexstr(order, " ")}`);
                File.writeAllBytes("control_block.bin", block);
                  
                // order compatible for garbro
                const O = new Uint8Array(order);
                const S3 = [0, 1, 2];
                const S6 = [2, 5, 3, 4, 1, 0];
                const S8 = [0, 2, 3, 1, 5, 6, 7, 4];
                let O3 = [0, 1, 2];
                let O6 = [0, 1, 2, 3, 4, 5];
                let O8 = [0, 1, 2, 3, 4, 5, 6, 7];
                for (let i=0; i<3; i++) O3[O[14+i]]=S3[i];
                for (let i=0; i<6; i++) O6[O[8+i]]=S6[i];
                for (let i=0; i<8; i++) O8[O[i]]=S8[i];
                console.log(`* PrologOrder (garbro) : ${O3[0]}, ${O3[1]}, ${O3[2]}`);
                console.log(`* OddBranchOrder (garbro) : ${O6[0]}, ${O6[1]}, ${O6[2]}, ${O6[3]}, ${O6[4]}, ${O6[5]}`);
                console.log(`* EvenBranchOrder (garbro) : ${O8[0]}, ${O8[1]}, ${O8[2]}, ${O8[3]}, ${O8[4]}, ${O8[5]}, ${O8[6]}, ${O8[7]}`);
                cxpoint = 0;
        }});
    }
});
