import frida, sys
jscode = """
console.log('on the start!')
Java.perform(function(){
    var MainActivity = Java.use("jp.tyrano.tyranoplayerframework.MainActivity");
    MainActivity.onPause.overload()
    .implementation = function() {
       try{
       var JString = Java.use("java.lang.String");
       var JFile = Java.use("java.io.File")
       var JFileInPutStream = Java.use("java.io.FileInputStream");
       var JFileOutPutStream = Java.use("java.io.FileOutputStream");

       var obbpath = this.getMountedObbPath();
       console.log("obb mounted at: " + obbpath);
       // no need to use this, mount directly to copy out in shell 
       //var outpath = "/sdcard/1.txt";
       //var inpath = obbpath + "/data/video/qbt.webm";
       /var fin = JFile.$new(outpath);
       //var fout = JFile.$new(inpath);
       //var out = JFileOutPutStream.$new(file);
       
       } catch (e) {
           console.log(e.message)
       }
       return this.onPause();
    }
});

"""

def on_message(message, data):
    print(message)

device = frida.get_usb_device(1) # make higher timeout
#pid = device.spawn('jp.q_bit.a01t')
session = device.attach('jp.q_bit.a01t')
#session = device.attach(pid)
script = session.create_script(jscode)
script.on('message', on_message)
script.load()
sys.stdin.read()