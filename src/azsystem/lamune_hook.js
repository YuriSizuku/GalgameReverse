/// <reference path="frida-gum.d.ts" />
/*
	for lamune.exe v1.0
	open the game to title, then
	frida -l lamune_hook.js -n lamune.exe
	next go to the prologue to dump all asbs
*/
function install_decompress_hook(outdir='./dump')
{
       // hook decompress function to dump
       const addr_decompress = ptr(0x40AB65);
       var raw_asbname = "";
       var raw_asbdata = ptr(0);
       var raw_asbsize = 0;
       Interceptor.attach(addr_decompress, {
           onEnter: function(args)
           {
               raw_asbdata = ptr(args[2]);
               raw_asbsize = args[3].toUInt32();
               raw_asbname = ptr(this.context.ebp).add(8).
                               readPointer().readAnsiString();
           }, 
           onLeave: function(retval)
           {
               //var asbname = asbname_buf.readAnsiString();
               var asbname = raw_asbname;
               console.log(asbname, 
                   ", raw_asbdata addr at", raw_asbdata, 
                   ", raw_asbsize ", raw_asbsize)
               try{
                   var fp = new File(outdir+"/"+asbname, 'wb');
                   fp.write(raw_asbdata.readByteArray(raw_asbsize));
                   fp.close();
               }
               catch(e)
               {
                   console.log("file error!", e);
               }
   
           }
       }) 
}

function dump_asbs(names, outdir="./dump")
{
    const addr_loadscript = ptr(0x43112A);
    const load_script = new NativeFunction(addr_loadscript,  
        'void', ['pointer', "pointer"], 'thiscall');
    console.log("load_script at:", load_script)

    // use this to store c++ context
    var pthis = ptr(0)
    Interceptor.attach(addr_loadscript, {
        onEnter: function(args)
        {
            pthis = ptr(this.context.ecx)
        }
    })
    install_decompress_hook(outdir)

    // wait for c++ context
    while(!pthis.toInt32())
    {
        Thread.sleep(0.2);
    }

    // dump all scripts
    var name_buf = Memory.alloc(0x100);
    for(var i=0;i<names.length;i++)
    {
        console.log("try to dump", names[i], ", this=",pthis);
        name_buf.writeAnsiString(names[i]);
        load_script(pthis, name_buf);
    }
    console.log("dump asbs finished!\n");
}

function dump_tbls(names, outdir="./dump")
{
    const addr_decompressfile = ptr(0x4213F3);
    const decompressfile = new NativeFunction(addr_decompressfile,  
        'pointer', ['pointer', "pointer"], 'stdcall');
    console.log("decompressfile at:", decompressfile)

    install_decompress_hook(outdir)

    // dump all tbls
    var raw_size = Memory.alloc(0x4);
    var name_buf = Memory.alloc(0x100);
    for(var i=0;i<names.length;i++)
    {
        console.log("try to dump", names[i]);
        name_buf.writeAnsiString(names[i]);
        decompressfile(name_buf, raw_size);
    }
    console.log("dump tbls finished!\n");
}

function dump_scenario()
{
    var names_v100 = ["00plorogue.asb", "00suzuk.asb", "00suzuk1_01.asb", "00suzuk1_02.asb", "00suzuk2_01.asb", "00suzuk2_02.asb", "00suzuk2_02_0.asb", "00suzuk2_02_0_1.asb", "00suzuk2_02_1.asb", "00suzuk3.asb", "00suzuk3_0.asb", "00suzuk3_1.asb", "00suzuk3_2.asb", "00suzuk4.asb", "00suzuk4_1.asb", "00suzuk4_2.asb", "00suzuk5.asb", "01ko.asb", "01nana01_01.asb", "01nana01_01_01.asb", "01nana01_02.asb", "01nana01_02_00.asb", "01nana01_02_01.asb", "01nana01_03.asb", "01nana01_04.asb", "01nana01_04_01.asb", "01nana01_04_02.asb", "01nana01_05.asb", "01nana01_05_01.asb", "01nana01_06.asb", "01nana02_01.asb", "01nana02_01_01.asb", "01nana02_01_02.asb", "01nana02_01_02_01.asb", "01nana02_01_02_02.asb", "01nana02_02.asb", "01nana02_03.asb", "01nana02_04.asb", "01nana03_01.asb", "01nana03_01_01.asb", "01nana03_01_02.asb", "01nana03_01_02_01.asb", "01nana03_02.asb", "01nana03_02_01.asb", "01nana03_02_02.asb", "01nana03_03.asb", "01nana03_03_00.asb", "01nana03_03_01.asb", "01nana03_03_02.asb", "01nana03_04.asb", "01nana03_05.asb", "01nana03_06.asb", "01nana03_06_0.asb", "01nana03_06_01.asb", "01nana03_06_02.asb", "01nana03_07.asb", "01nana04_01.asb", "01nana04_01_01.asb", "01nana04_01_02.asb", "01nana04_02.asb", "01nana04_03.asb", "01nana04_04.asb", "01nana04_05.asb", "01nana04_05_00.asb", "01nana04_06.asb", "01nana05_01.asb", "01nana05_02.asb", "01nana06_01.asb", "01nana06_01_01.asb", "01nana06_01_02.asb", "01nana06_02.asb", "01nana07_01.asb", "01nana07_01_01.asb", "01nana07_01_02.asb", "01nana07_02.asb", "01nana08_01.asb", "01nana08_02.asb", "01nana10_01.asb", "01nana10_02.asb", "01nana20_01.asb", "01nana22_01.asb", "01nana25_01.asb", "01suzug.asb", "01suzug01.asb", "01suzug02.asb", "01suzug02_01.asb", "01suzug03.asb", "01suzug03_01.asb", "01suzug03_02.asb", "01suzug04.asb", "01suzug05.asb", "01suzug06.asb", "02gen.asb", "02suzug01.asb", "02suzug01_01.asb", "02suzug01_02.asb", "02suzug02.asb", "02suzug03.asb", "02suzug04.asb", "03omake.asb", "03suzug01.asb", "03suzug01_00.asb", "03suzug01_01.asb", "03suzug01_02.asb", "03suzug02.asb", "03suzug03.asb", "04suzug01.asb", "04suzug01_01.asb", "04suzug01_02.asb", "04suzug02.asb", "04suzug02_01.asb", "04suzug02_02.asb", "04suzug03.asb", "04suzug04.asb", "05suzug01.asb", "05suzug01_01.asb", "05suzug01_02.asb", "05suzug02.asb", "05suzug02_00.asb", "05suzug02_01.asb", "05suzug02_02.asb", "05suzug03.asb", "06suzug01.asb", "06suzug01_01.asb", "06suzug01_02.asb", "06suzug02.asb", "07suzug01.asb", "07suzug01_01.asb", "07suzug01_02.asb", "07suzug02.asb", "08suzug01.asb", "08suzug01_01.asb", "08suzug01_02.asb", "08suzug02.asb", "09suzug01.asb", "09suzug01_01.asb", "09suzug01_02.asb", "09suzug02.asb", "09suzug02_01.asb", "09suzug02_02.asb", "09suzug03.asb", "09suzug04.asb", "0hika_01.asb", "0hika_01_01.asb", "0hika_01_02.asb", "0nana.asb", "0nana_00.asb", "0nana_00_01.asb", "0nana_00_02.asb", "0nana_01.asb", "0nana_02.asb", "0nana_03.asb", "10suzug01.asb", "10suzug01_01.asb", "10suzug01_02.asb", "10suzug02.asb", "11suzug02_ero.asb", "11suzug03_eroa.asb", "11suzug_01.asb", "11suzug_01_01.asb", "11suzug_01_02.asb", "11suzug_02.asb", "11suzug_02_01.asb", "11suzug_02_02.asb", "11suzug_03.asb", "12suzug.asb", "12suzug2.asb", "12suzug_01.asb", "12suzug_02.asb", "13suzug_e.asb", "13suzug_e2.asb", "14suzug.asb", "17suzu_oero1.asb", "17suzu_oero1_01.asb", "17suzu_oero1_02.asb", "17suzu_oero1_1.asb", "17suzu_oero1_2.asb", "1nana_03.asb", "1nana_03_1.asb", "1nana_04.asb", "1nana_04_1.asb", "3nana_0.asb", "boss.asb", "boss_01.asb", "ed_test.asb", "ed_test2.asb", "garasu0.asb", "hero.asb", "hika_01_01.asb", "hika_01_01a.asb", "hika_01_01b.asb", "hika_01_02.asb", "hika_02_01.asb", "hika_02_015.asb", "hika_02_015e.asb", "hika_02_02.asb", "hika_02_03.asb", "hika_02_04.asb", "hika_03_01.asb", "hika_03_01a.asb", "hika_03_01b.asb", "hika_03_02.asb", "hika_03_02a.asb", "hika_03_02b.asb", "hika_03_03.asb", "hika_03_03a.asb", "hika_03_03b.asb", "hika_03_04.asb", "hika_04_01.asb", "hika_04_02.asb", "hika_04_02a.asb", "hika_04_02b.asb", "hika_04_03.asb", "hika_04_04.asb", "hika_04_04a.asb", "hika_04_04b.asb", "hika_04_05.asb", "hika_04_05a.asb", "hika_04_05b.asb", "hika_04_06.asb", "hika_04_07.asb", "hika_05_01.asb", "hika_05_01a.asb", "hika_05_01b.asb", "hika_05_02.asb", "hika_05_02a.asb", "hika_05_02b.asb", "hika_05_03.asb", "hika_05_04.asb", "hika_06_01.asb", "hika_06_02.asb", "hika_06_03.asb", "hika_06_03a.asb", "hika_06_03b.asb", "hika_06_04.asb", "hika_06_05.asb", "hika_06_05a.asb", "hika_06_05b.asb", "hika_06_06.asb", "hika_07_01.asb", "hika_07_02.asb", "hika_08_01.asb", "hika_08_01a.asb", "hika_08_01b.asb", "hika_08_02.asb", "hika_09_01.asb", "hika_09_01a.asb", "hika_09_01b.asb", "hika_09_02.asb", "hika_10_01.asb", "hika_10_02.asb", "hika_10_03.asb", "hika_11_01.asb", "hika_11_02.asb", "hika_12_01.asb", "hika_13_01.asb", "hika_13_02.asb", "hika_13_03.asb", "hika_14_01.asb", "hika_14_02.asb", "hika_child_01.asb", "hika_child_01_01.asb", "hika_child_01_02.asb", "hika_ep_01.asb", "hika_h_01.asb", "hika_h_01a.asb", "hika_h_01b.asb", "hika_h_02.asb", "hika_h_03.asb", "hika_s01.asb", "hika_s02.asb", "hika_s03.asb", "hika_s04.asb", "hika_s05.asb", "hika_s06.asb", "hika_s07.asb", "hika_s08.asb", "hika_s09.asb", "hika_s10.asb", "hika_s11.asb", "hika_s12.asb", "hika_s13.asb", "hika_s14.asb", "hika_s15.asb", "hika_s16.asb", "mama_1st_01.asb", "mama_1st_01_a.asb", "mama_1st_01_b.asb", "mama_1st_02_a.asb", "mama_1st_02_b.asb", "mama_1st_03.asb", "mama_1st_03_a.asb", "mama_1st_03_b.asb", "mama_1st_04.asb", "mama_after_01.asb", "nana_s01.asb", "nana_s02.asb", "nana_s03.asb", "nana_s04.asb", "nana_s05.asb", "nana_s06.asb", "nana_s07.asb", "nana_s08.asb", "nana_s09.asb", "nana_s10.asb", "nana_s11.asb", "nana_s12.asb", "nana_s13.asb", "nana_s14.asb", "nana_s15.asb", "nana_s16.asb", "nendo0.asb", "nendo0_01.asb", "nendo0_02.asb", "nendo1.asb", "nero.asb", "om_01.asb", "om_02.asb", "om_03.asb", "om_04.asb", "om_04_11.asb", "om_04_12.asb", "om_04_2.asb", "om_04_3.asb", "om_04_4.asb", "om_04_5.asb", "om_04_6.asb", "om_04_7.asb", "om_04_8.asb", "om_04_9.asb", "sakura0.asb", "sero.asb", "sindou0.asb", "sindou0_a.asb", "sindou0_b.asb", "sindou1.asb", "start.asb", "stff_01.asb", "stff_02.asb", "stff_03.asb", "stff_04.asb", "stff_05.asb", "stff_06.asb", "stff_07.asb", "stff_08.asb", "stff_09.asb", "stff_10.asb", "stff_11.asb", "stff_12.asb", "stff_13.asb", "stff_14.asb", "stff_15.asb", "stff_16.asb", "stff_17.asb", "stff_18.asb", "stff_19.asb", "stff_20.asb", "stff_21.asb", "stff_22.asb", "suzu_s01.asb", "suzu_s02.asb", "suzu_s03.asb", "suzu_s04.asb", "suzu_s05.asb", "suzu_s06.asb", "suzu_s07.asb", "suzu_s08.asb", "suzu_s09.asb", "suzu_s10.asb", "suzu_s11.asb", "suzu_s12.asb", "suzu_s13.asb", "suzu_s14.asb", "suzu_s15.asb", "suzu_s16.asb", "tae_01day_01.asb", "tae_01day_02.asb", "tae_01day_025.asb", "tae_01day_03.asb", "tae_01day_03_a.asb", "tae_01day_03_b.asb", "tae_01day_04.asb", "tae_02day_01.asb", "tae_02day_01_a.asb", "tae_02day_01_b.asb", "tae_02day_02.asb", "tae_02day_02_a.asb", "tae_02day_02_b.asb", "tae_02day_03.asb", "tae_02day_03_a.asb", "tae_02day_03_b.asb", "tae_02day_04.asb", "tae_02day_05.asb", "tae_03day_01.asb", "tae_03day_02.asb", "tae_04day_01.asb", "tae_04day_01_a.asb", "tae_04day_01_b.asb", "tae_04day_02.asb", "tae_05day_01.asb", "tae_05day_01_a.asb", "tae_05day_01_b.asb", "tae_05day_02.asb", "tae_05day_02_a.asb", "tae_05day_02_b.asb", "tae_05day_02_c.asb", "tae_05day_02_d.asb", "tae_05day_03.asb", "tae_06day_01.asb", "tae_06day_02.asb", "tae_06day_02_a.asb", "tae_06day_02_b.asb", "tae_07day_01.asb", "tae_07day_02.asb", "tae_08day_01.asb", "tae_09day_01.asb", "tae_09day_01_a.asb", "tae_09day_01_b.asb", "tae_09day_02.asb", "tae_09day_03.asb", "tae_10day_01.asb", "tae_10day_01_a.asb", "tae_10day_01_b.asb", "tae_10day_02.asb", "tae_10day_02_a.asb", "tae_10day_02_b.asb", "tae_10day_02_c.asb", "tae_11day_01.asb", "tae_11day_01_a.asb", "tae_11day_01_b.asb", "tae_11day_01_c.asb", "tae_11day_02.asb", "tae_12day_01.asb", "tae_12day_02.asb", "tae_12day_02_a.asb", "tae_12day_02_b.asb", "tae_12day_02_c.asb", "tae_12day_02_d.asb", "tae_12day_03.asb", "tae_12day_03_a.asb", "tae_12day_03_b.asb", "tae_12day_03_c.asb", "tae_12day_03_d.asb", "tae_12day_04.asb", "tae_12day_04_a.asb", "tae_12day_04_b.asb", "tae_12day_04_c.asb", "tae_12day_04_d.asb", "tae_12day_05.asb", "tae_12day_05_a.asb", "tae_12day_05_b.asb", "tae_12day_05_c.asb", "tae_12day_05_d.asb", "tae_12day_06.asb", "tae_12day_06_a.asb", "tae_12day_06_b.asb", "tae_12day_07.asb", "tae_12day_07_a.asb", "tae_12day_07_b.asb", "tae_12day_08.asb", "tae_12day_09.asb", "tae_12day_10.asb", "tae_13day_01.asb", "tae_after_01.asb", "tae_after_01_a.asb", "tae_after_01_b.asb", "tae_after_02_a.asb", "tae_after_03_a.asb", "tae_after_04_a.asb", "tae_after_04_b.asb", "tae_after_05.asb", "tae_kako_01.asb", "tae_s01.asb", "tae_s02.asb", "tae_s03.asb", "tae_s04.asb", "tae_s05.asb", "tae_s06.asb", "tae_s07.asb", "tae_s08.asb", "tae_s09.asb", "tae_s10.asb", "tae_s11.asb", "tae_s12.asb", "tae_s13.asb", "tae_s14.asb", "tae_s15.asb", "tae_s16.asb", "tero.asb", "test1.asb", "test3.asb", ]

    var names_v103 = ["00suzuk.asb", "00suzuk1_01.asb", "00suzuk1_02.asb", "00suzuk2_01.asb", "00suzuk2_02.asb", "00suzuk2_02_0.asb", "00suzuk2_02_0_1.asb", "00suzuk2_02_1.asb", "00suzuk3.asb", "00suzuk3_0.asb", "00suzuk3_1.asb", "00suzuk3_2.asb", "00suzuk4.asb", "00suzuk4_1.asb", "00suzuk4_2.asb", "00suzuk5.asb", "01nana01_01.asb", "01nana01_01_01.asb", "01nana01_02.asb", "01nana01_02_00.asb", "01nana01_02_01.asb", "01nana01_03.asb", "01nana01_04.asb", "01nana01_04_01.asb", "01nana01_04_02.asb", "01nana01_05.asb", "01nana01_05_01.asb", "01nana01_06.asb", "01nana02_01.asb", "01nana02_01_01.asb", "01nana02_01_02.asb", "01nana02_01_02_01.asb", "01nana02_01_02_02.asb", "01nana02_02.asb", "01nana02_03.asb", "01nana02_04.asb", "01nana03_01.asb", "01nana03_01_01.asb", "01nana03_01_02.asb", "01nana03_01_02_01.asb", "01nana03_02.asb", "01nana03_02_01.asb", "01nana03_02_02.asb", "01nana03_03.asb", "01nana03_03_00.asb", "01nana03_03_01.asb", "01nana03_03_02.asb", "01nana03_04.asb", "01nana03_05.asb", "01nana03_06.asb", "01nana03_06_0.asb", "01nana03_06_01.asb", "01nana03_06_02.asb", "01nana03_07.asb", "01nana04_01.asb", "01nana04_01_01.asb", "01nana04_01_02.asb", "01nana04_02.asb", "01nana04_03.asb", "01nana04_04.asb", "01nana04_05.asb", "01nana04_05_00.asb", "01nana04_06.asb", "01nana05_01.asb", "01nana05_02.asb", "01nana06_01.asb", "01nana06_01_01.asb", "01nana06_01_02.asb", "01nana06_02.asb", "01nana07_01.asb", "01nana07_01_01.asb", "01nana07_01_02.asb", "01nana07_02.asb", "01nana08_01.asb", "01nana08_02.asb", "01nana10_01.asb", "01nana10_02.asb", "01nana20_01.asb", "01nana22_01.asb", "01nana25_01.asb", "01suzug.asb", "01suzug01.asb", "01suzug02.asb", "01suzug02_01.asb", "01suzug03.asb", "01suzug03_01.asb", "01suzug03_02.asb", "01suzug04.asb", "01suzug05.asb", "01suzug06.asb", "02suzug01.asb", "02suzug01_01.asb", "02suzug01_02.asb", "02suzug02.asb", "02suzug03.asb", "02suzug04.asb", "03omake.asb", "03suzug01.asb", "03suzug01_00.asb", "03suzug01_01.asb", "03suzug01_02.asb", "03suzug02.asb", "03suzug03.asb", "04suzug01.asb", "04suzug01_01.asb", "04suzug01_02.asb", "04suzug02.asb", "04suzug02_01.asb", "04suzug02_02.asb", "04suzug03.asb", "04suzug04.asb", "05suzug01.asb", "05suzug01_01.asb", "05suzug01_02.asb", "05suzug02.asb", "05suzug02_00.asb", "05suzug02_01.asb", "05suzug02_02.asb", "05suzug03.asb", "06suzug01.asb", "06suzug01_01.asb", "06suzug01_02.asb", "06suzug02.asb", "07suzug01.asb", "07suzug01_01.asb", "07suzug01_02.asb", "07suzug02.asb", "08suzug01.asb", "08suzug01_01.asb", "08suzug01_02.asb", "08suzug02.asb", "09suzug01.asb", "09suzug01_01.asb", "09suzug01_02.asb", "09suzug02.asb", "09suzug02_01.asb", "09suzug02_02.asb", "09suzug03.asb", "09suzug04.asb", "0hika_01.asb", "0hika_01_01.asb", "0hika_01_02.asb", "0nana.asb", "0nana_00.asb", "0nana_00_01.asb", "0nana_00_02.asb", "0nana_01.asb", "0nana_02.asb", "0nana_03.asb", "1.txt", "10suzug01.asb", "10suzug01_01.asb", "10suzug01_02.asb", "10suzug02.asb", "11suzug02_ero.asb", "11suzug03_eroa.asb", "11suzug_01.asb", "11suzug_01_01.asb", "11suzug_01_02.asb", "11suzug_02.asb", "11suzug_02_01.asb", "11suzug_02_02.asb", "11suzug_03.asb", "12suzug.asb", "12suzug2.asb", "12suzug_01.asb", "12suzug_02.asb", "13suzug_e.asb", "13suzug_e2.asb", "14suzug.asb", "17suzu_oero1.asb", "17suzu_oero1_01.asb", "17suzu_oero1_02.asb", "17suzu_oero1_1.asb", "17suzu_oero1_2.asb", "1nana_03.asb", "1nana_03_1.asb", "1nana_04.asb", "1nana_04_0.asb", "1nana_04_1.asb", "1nana_04_2.asb", "3nana_0.asb", "boss.asb", "boss_01.asb", "garasu0.asb", "hero.asb", "hika_01_01.asb", "hika_01_01a.asb", "hika_01_01b.asb", "hika_01_02.asb", "hika_02_01.asb", "hika_02_015.asb", "hika_02_015e.asb", "hika_02_02.asb", "hika_02_03.asb", "hika_02_04.asb", "hika_03_01.asb", "hika_03_01a.asb", "hika_03_01b.asb", "hika_03_02.asb", "hika_03_02a.asb", "hika_03_02b.asb", "hika_03_03.asb", "hika_03_03a.asb", "hika_03_03b.asb", "hika_03_04.asb", "hika_04_01.asb", "hika_04_02.asb", "hika_04_02a.asb", "hika_04_02b.asb", "hika_04_03.asb", "hika_04_04.asb", "hika_04_04a.asb", "hika_04_04b.asb", "hika_04_05.asb", "hika_04_05a.asb", "hika_04_05b.asb", "hika_04_06.asb", "hika_04_07.asb", "hika_05_01.asb", "hika_05_01a.asb", "hika_05_01b.asb", "hika_05_02.asb", "hika_05_02a.asb", "hika_05_02b.asb", "hika_05_03.asb", "hika_05_04.asb", "hika_06_01.asb", "hika_06_02.asb", "hika_06_03.asb", "hika_06_03a.asb", "hika_06_03b.asb", "hika_06_04.asb", "hika_06_05.asb", "hika_06_05a.asb", "hika_06_05b.asb", "hika_06_06.asb", "hika_07_01.asb", "hika_07_02.asb", "hika_08_01.asb", "hika_08_01a.asb", "hika_08_01b.asb", "hika_08_02.asb", "hika_09_01.asb", "hika_09_01a.asb", "hika_09_01b.asb", "hika_09_02.asb", "hika_10_01.asb", "hika_10_02.asb", "hika_10_03.asb", "hika_11_01.asb", "hika_11_02.asb", "hika_12_01.asb", "hika_13_01.asb", "hika_13_02.asb", "hika_13_03.asb", "hika_14_01.asb", "hika_14_02.asb", "hika_child_01.asb", "hika_child_01_01.asb", "hika_child_01_02.asb", "hika_ep_01.asb", "hika_h_01.asb", "hika_h_01a.asb", "hika_h_01b.asb", "hika_h_02.asb", "hika_h_03.asb", "hika_s01.asb", "hika_s02.asb", "hika_s03.asb", "hika_s04.asb", "hika_s05.asb", "hika_s06.asb", "hika_s07.asb", "hika_s08.asb", "hika_s09.asb", "hika_s10.asb", "hika_s11.asb", "hika_s12.asb", "hika_s13.asb", "hika_s14.asb", "hika_s15.asb", "hika_s16.asb", "mama_1st_01.asb", "mama_1st_01_a.asb", "mama_1st_01_b.asb", "mama_1st_02_a.asb", "mama_1st_02_b.asb", "mama_1st_03.asb", "mama_1st_03_a.asb", "mama_1st_03_b.asb", "mama_1st_04.asb", "mama_after_01.asb", "nana_s01.asb", "nana_s02.asb", "nana_s03.asb", "nana_s04.asb", "nana_s05.asb", "nana_s06.asb", "nana_s07.asb", "nana_s08.asb", "nana_s09.asb", "nana_s10.asb", "nana_s11.asb", "nana_s12.asb", "nana_s13.asb", "nana_s14.asb", "nana_s15.asb", "nana_s16.asb", "nendo0.asb", "nendo0_01.asb", "nendo0_02.asb", "nendo1.asb", "nero.asb", "om_01.asb", "om_02.asb", "om_03.asb", "om_04.asb", "om_04_11.asb", "om_04_12.asb", "om_04_13.asb", "om_04_14.asb", "om_04_2.asb", "om_04_3.asb", "om_04_4.asb", "om_04_5.asb", "om_04_6.asb", "om_04_7.asb", "om_04_8.asb", "om_04_9.asb", "sakura0.asb", "sero.asb", "sindou0.asb", "sindou0_a.asb", "sindou0_b.asb", "sindou1.asb", "start.asb", "stff_01.asb", "stff_02.asb", "stff_03.asb", "stff_04.asb", "stff_05.asb", "stff_06.asb", "stff_07.asb", "stff_08.asb", "stff_09.asb", "stff_10.asb", "stff_11.asb", "stff_12.asb", "stff_13.asb", "stff_14.asb", "stff_15.asb", "stff_16.asb", "stff_17.asb", "stff_18.asb", "stff_19.asb", "stff_20.asb", "stff_21.asb", "stff_22.asb", "suzu_s01.asb", "suzu_s02.asb", "suzu_s03.asb", "suzu_s04.asb", "suzu_s05.asb", "suzu_s06.asb", "suzu_s07.asb", "suzu_s08.asb", "suzu_s09.asb", "suzu_s10.asb", "suzu_s11.asb", "suzu_s12.asb", "suzu_s13.asb", "suzu_s14.asb", "suzu_s15.asb", "suzu_s16.asb", "tae_01day_01.asb", "tae_01day_02.asb", "tae_01day_025.asb", "tae_01day_03.asb", "tae_01day_03_a.asb", "tae_01day_03_b.asb", "tae_01day_04.asb", "tae_02day_01.asb", "tae_02day_01_a.asb", "tae_02day_01_b.asb", "tae_02day_02.asb", "tae_02day_02_a.asb", "tae_02day_02_b.asb", "tae_02day_03.asb", "tae_02day_03_a.asb", "tae_02day_03_b.asb", "tae_02day_04.asb", "tae_02day_05.asb", "tae_03day_01.asb", "tae_03day_02.asb", "tae_04day_01.asb", "tae_04day_01_a.asb", "tae_04day_01_b.asb", "tae_04day_02.asb", "tae_05day_01.asb", "tae_05day_01_a.asb", "tae_05day_01_b.asb", "tae_05day_02.asb", "tae_05day_02_a.asb", "tae_05day_02_b.asb", "tae_05day_02_c.asb", "tae_05day_02_d.asb", "tae_05day_03.asb", "tae_06day_01.asb", "tae_06day_02.asb", "tae_06day_02_a.asb", "tae_06day_02_b.asb", "tae_07day_01.asb", "tae_07day_02.asb", "tae_08day_01.asb", "tae_09day_01.asb", "tae_09day_01_a.asb", "tae_09day_01_b.asb", "tae_09day_02.asb", "tae_09day_03.asb", "tae_10day_01.asb", "tae_10day_01_a.asb", "tae_10day_01_b.asb", "tae_10day_02.asb", "tae_10day_02_a.asb", "tae_10day_02_b.asb", "tae_10day_02_c.asb", "tae_11day_01.asb", "tae_11day_01_a.asb", "tae_11day_01_b.asb", "tae_11day_01_c.asb", "tae_11day_02.asb", "tae_12day_01.asb", "tae_12day_02.asb", "tae_12day_02_a.asb", "tae_12day_02_b.asb", "tae_12day_02_c.asb", "tae_12day_02_d.asb", "tae_12day_03.asb", "tae_12day_03_a.asb", "tae_12day_03_b.asb", "tae_12day_03_c.asb", "tae_12day_03_d.asb", "tae_12day_04.asb", "tae_12day_04_a.asb", "tae_12day_04_b.asb", "tae_12day_04_c.asb", "tae_12day_04_d.asb", "tae_12day_05.asb", "tae_12day_05_a.asb", "tae_12day_05_b.asb", "tae_12day_05_c.asb", "tae_12day_05_d.asb", "tae_12day_06.asb", "tae_12day_06_a.asb", "tae_12day_06_b.asb", "tae_12day_07.asb", "tae_12day_07_a.asb", "tae_12day_07_b.asb", "tae_12day_08.asb", "tae_12day_09.asb", "tae_12day_10.asb", "tae_13day_01.asb", "tae_after_01.asb", "tae_after_01_a.asb", "tae_after_01_b.asb", "tae_after_02_a.asb", "tae_after_03_a.asb", "tae_after_04_a.asb", "tae_after_04_b.asb", "tae_after_05.asb", "tae_kako_01.asb", "tae_s01.asb", "tae_s02.asb", "tae_s03.asb", "tae_s04.asb", "tae_s05.asb", "tae_s06.asb", "tae_s07.asb", "tae_s08.asb", "tae_s09.asb", "tae_s10.asb", "tae_s11.asb", "tae_s12.asb", "tae_s13.asb", "tae_s14.asb", "tae_s15.asb", "tae_s16.asb", "tero.asb"]	
    dump_asbs(names_v103)

}

function dump_system()
{
    var names = ["scenario.tbl", "track.tbl", "cg.tbl"]
    dump_tbls(names)
}

//dump_system()
dump_scenario()