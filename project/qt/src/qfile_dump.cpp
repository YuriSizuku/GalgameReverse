/**
 * dynamic dump qt5 res vfs
 *   v0.1, devloped by devseed
 * 
 * usage: 
 *   put the compiled version.dll to game dir and run the game
 * 
 * tested games: 
 *   叙事曲1：难忘的回忆
 *   叙事曲2：星空下的诺言
 * 
 * acknowledgement:
 *   https://github.com/Dir-A
 */

#include <cstdio>
#include <windows.h>
#include <QtCore/QFile>
#include <QtCore/QDir>

#ifdef USECOMPAT
#include "winversion_v100.h"
#else
#include "winversion.h"
#endif

#define DUMP_DIR L"dump"

static DWORD WINAPI _dump_dir(QDir qdir, DWORD *pn)
{
    for(auto t: qdir.entryInfoList())
    {
        QString outpath = QString::fromStdWString(DUMP_DIR + t.absoluteFilePath().toStdWString().substr(1));
        if(t.isDir())
        {
            static wchar_t tmppathw[MAX_PATH];
            wcscpy(tmppathw, outpath.toStdWString().c_str());
            CreateDirectoryW(tmppathw, NULL);
            _dump_dir(t.absoluteFilePath(), pn);
        }
        else
        {
            // prepare data
            QFile infile(t.absoluteFilePath());
            LOGLi(L"%ld path=%ls size=0x%zx\n",  
                    ++(*pn), t.absoluteFilePath().toStdWString().c_str(), 
                    infile.size());
            infile.open(QIODevice::ReadOnly);
            auto data = infile.readAll();
            infile.close();
            
            // save data to file
            QFile outfile(outpath);
            outfile.open(QIODevice::WriteOnly);
            outfile.write(data);
            outfile.close();
        }
    }
    return *pn;
}

static DWORD WINAPI dump_dir(void *args)
{
    // Sleep(1000);
    DWORD count = 0;
    QDir qdir(":/");
    CreateDirectoryW(DUMP_DIR L"/", NULL);
    count = _dump_dir(qdir, &count);
    LOGi("dump finished with %d files \n", count);
    return 0;
}

static void init()
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    // system("chcp 936");
    // setlocale(LC_ALL, "chs");
    printf("qt5_dump res, v0.1, developed by devseed\n");
    DWORD winver = GetVersion();
    DWORD winver_major = (DWORD)(LOBYTE(LOWORD(winver)));
    DWORD winver_minor = (DWORD)(HIBYTE(LOWORD(winver)));
    LOGi("version NT=%lu.%lu\n", winver_major, winver_minor);
    #if defined(_MSC_VER)
    LOGi("compiler MSVC=%d\n", _MSC_VER)
    #elif defined(__GNUC__)
    LOGi("compiler GNUC=%d.%d\n", __GNUC__, __GNUC_MINOR__);
    #elif defined(__TINYC__)
    LOGi("compiler TCC\n");
    #endif

    CreateThread(NULL, 0, dump_dir, NULL, 0, NULL);
}

extern "C" EXPORT void dummy()
{

}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,  DWORD fdwReason,  LPVOID lpReserved )
{
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
            winversion_init();
            init();
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
