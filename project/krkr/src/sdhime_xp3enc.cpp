#include <windows.h>

int WINAPI DllEntryPoint(HINSTANCE hinst, unsigned long reason, void* lpReserved)
{
	// DLL エントリポイント
	return 1;
}

extern "C" void __stdcall XP3ArchiveAttractFilter_v2(
	unsigned __int32 hash,
	unsigned __int64 offset, void * buffer, long bufferlen)
{
	// バージョン 2 関数は以下の引数を受け取ります。
	// hash      : 入力ファイルの(暗号化解除時の)32bitハッシュです。
	// offset    : "buffer" 引数が示すデータが、ファイルの先頭から何バイト目
	//             であるか (ファイルが圧縮される場合、無圧縮の状態のバイト
	//             オフセットです )
	// buffer    : 対象となるデータです。ファイルが圧縮される場合は、圧縮され
	//             る前のデータです。
	//             ( ファイルが圧縮された後のデータにこの関数で変更を加えるこ
	//             とは出来ません )
	// bufferlen : "buffer" 引数が表すデータの長さです。

	// しかしここではサンプルとして、hash の最下位バイトを XOR する方法を
	// 示します。

	int i;
	for(i = 0; i < bufferlen; i++)
	{
		
		unsigned char k = (hash + 1) & 0xff;
		((unsigned char*)buffer)[i] = (~((unsigned char*)buffer)[i] ^ k);
	}
}