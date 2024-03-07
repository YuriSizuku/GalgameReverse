"""
encode or decode bip files (lzss compress), using pytcc
  v0.1, developed by devseed

  tested games:
  ULJM06002 想いのかけら －Close to－
"""

import sys
import struct
import pytcc # pip install pytcc=0.9.27.1.1
from mmap import mmap, ACCESS_READ, ACCESS_COPY
from ctypes import *
from typing import List


g_lzsscode = '''
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/**************************************************************
LZSS.C -- A Data Compression Program
***************************************************************
4/6/1989 Haruhiko Okumura
Use, distribute, and modify this program freely.
Please send me your improved versions.
PC-VAN      SCIENCE
NIFTY-Serve PAF01022
CompuServe  74050,1022
**************************************************************/
#define N         4096  /* size of ring buffer - must be power of 2 */
#define F         18    /* upper limit for match_length */
#define THRESHOLD 2     /* encode string into position and length
if match_length is greater than this */
#define NIL       N     /* index for root of binary search trees */

struct encode_state {
	/*
	* left & right children & parent. These constitute binary search trees.
	*/
	int lchild[N + 1], rchild[N + 257], parent[N + 1];

	/* ring buffer of size N, with extra F-1 bytes to aid string comparison */
	uint8_t text_buf[N + F - 1];

	/*
	* match_length of longest match.
	* These are set by the insert_node() procedure.
	*/
	int match_position, match_length;
};


__attribute__((dllexport)) 
int lzss_decode(uint8_t *dst, uint8_t *src, uint32_t srclen)
{
	/* ring buffer of size N, with extra F-1 bytes to aid string comparison */
	uint8_t text_buf[N + F - 1];
	uint8_t *dststart = dst;
	uint8_t *srcend = src + srclen;
	int  i, j, k, r, c;
	unsigned int flags;

	dst = dststart;
	srcend = src + srclen;
	r = N - F;
	memset(text_buf, 0, r);
	flags = 0;
	for (; ; ) {
		if (((flags >>= 1) & 0x100) == 0) {
			if (src < srcend) c = *src++; else break;
			flags = c | 0xFF00;  /* uses higher byte cleverly */
		}   /* to count eight */
		if (flags & 1) {
			if (src < srcend) c = *src++; else break;
			*dst++ = c;
			text_buf[r++] = c;
			r &= (N - 1);
		}
		else {
			if (src < srcend) i = *src++; else break;
			if (src < srcend) j = *src++; else break;
			i |= ((j & 0xF0) << 4);
			j = (j & 0x0F) + THRESHOLD;
			for (k = 0; k <= j; k++) {
				c = text_buf[(i + k) & (N - 1)];
				*dst++ = c;
				text_buf[r++] = c;
				r &= (N - 1);
			}
		}
	}

	return dst - dststart;
}

/*
* initialize state, mostly the trees
*
* For i = 0 to N - 1, rchild[i] and lchild[i] will be the right and left
* children of node i.  These nodes need not be initialized.  Also, parent[i]
* is the parent of node i.  These are initialized to NIL (= N), which stands
* for 'not used.'  For i = 0 to 255, rchild[N + i + 1] is the root of the
* tree for strings that begin with character i.  These are initialized to NIL.
* Note there are 256 trees. */
static void init_state(struct encode_state *sp)
{
	int  i;

	memset(sp, 0, sizeof(*sp));

	for (i = 0; i < N - F; i++)
		sp->text_buf[i] = ' ';
	for (i = N + 1; i <= N + 256; i++)
		sp->rchild[i] = NIL;
	for (i = 0; i < N; i++)
		sp->parent[i] = NIL;
}

/*
* Inserts string of length F, text_buf[r..r+F-1], into one of the trees
* (text_buf[r]'th tree) and returns the longest-match position and length
* via the global variables match_position and match_length.
* If match_length = F, then removes the old node in favor of the new one,
* because the old one will be deleted sooner. Note r plays double role,
* as tree node and position in buffer.
*/
static void insert_node(struct encode_state *sp, int r)
{
	int  i, p, cmp;
	uint8_t  *key;

	cmp = 1;
	key = &sp->text_buf[r];
	p = N + 1 + key[0];
	sp->rchild[r] = sp->lchild[r] = NIL;
	sp->match_length = 0;
	for (; ; ) {
		if (cmp >= 0) {
			if (sp->rchild[p] != NIL)
				p = sp->rchild[p];
			else {
				sp->rchild[p] = r;
				sp->parent[r] = p;
				return;
			}
		}
		else {
			if (sp->lchild[p] != NIL)
				p = sp->lchild[p];
			else {
				sp->lchild[p] = r;
				sp->parent[r] = p;
				return;
			}
		}
		for (i = 1; i < F; i++) {
			if ((cmp = key[i] - sp->text_buf[p + i]) != 0)
				break;
		}
		if (i > sp->match_length) {
			sp->match_position = p;
			if ((sp->match_length = i) >= F)
				break;
		}
	}
	sp->parent[r] = sp->parent[p];
	sp->lchild[r] = sp->lchild[p];
	sp->rchild[r] = sp->rchild[p];
	sp->parent[sp->lchild[p]] = r;
	sp->parent[sp->rchild[p]] = r;
	if (sp->rchild[sp->parent[p]] == p)
		sp->rchild[sp->parent[p]] = r;
	else
		sp->lchild[sp->parent[p]] = r;
	sp->parent[p] = NIL;  /* remove p */
}

/* deletes node p from tree */
static void delete_node(struct encode_state *sp, int p)
{
	int  q;

	if (sp->parent[p] == NIL)
		return;  /* not in tree */
	if (sp->rchild[p] == NIL)
		q = sp->lchild[p];
	else if (sp->lchild[p] == NIL)
		q = sp->rchild[p];
	else {
		q = sp->lchild[p];
		if (sp->rchild[q] != NIL) {
			do {
				q = sp->rchild[q];
			} while (sp->rchild[q] != NIL);
			sp->rchild[sp->parent[q]] = sp->lchild[q];
			sp->parent[sp->lchild[q]] = sp->parent[q];
			sp->lchild[q] = sp->lchild[p];
			sp->parent[sp->lchild[p]] = q;
		}
		sp->rchild[q] = sp->rchild[p];
		sp->parent[sp->rchild[p]] = q;
	}
	sp->parent[q] = sp->parent[p];
	if (sp->rchild[sp->parent[p]] == p)
		sp->rchild[sp->parent[p]] = q;
	else
		sp->lchild[sp->parent[p]] = q;
	sp->parent[p] = NIL;
}

__attribute__((dllexport)) 
uint8_t *lzss_encode(uint8_t *dst, uint32_t dstlen, uint8_t *src, uint32_t srcLen)
{
	/* Encoding state, mostly tree but some current match stuff */
	struct encode_state *sp;

	int  i, c, len, r, s, last_match_length, code_buf_ptr;
	uint8_t code_buf[17], mask;
	uint8_t *srcend = src + srcLen;
	uint8_t *dstend = dst + dstlen;

	/* initialize trees */
	sp = (struct encode_state *) malloc(sizeof(*sp));
	init_state(sp);

	/*
	* code_buf[1..16] saves eight units of code, and code_buf[0] works
	* as eight flags, "1" representing that the unit is an unencoded
	* letter (1 byte), "" a position-and-length pair (2 bytes).
	* Thus, eight units require at most 16 bytes of code.
	*/
	code_buf[0] = 0;
	code_buf_ptr = mask = 1;

	/* Clear the buffer with any character that will appear often. */
	s = 0;  r = N - F;

	/* Read F bytes into the last F bytes of the buffer */
	for (len = 0; len < F && src < srcend; len++)
		sp->text_buf[r + len] = *src++;
	if (!len) {
		free(sp);
		return (void *)0;  /* text of size zero */
	}
	/*
	* Insert the F strings, each of which begins with one or more
	* 'space' characters.  Note the order in which these strings are
	* inserted.  This way, degenerate trees will be less likely to occur.
	*/
	for (i = 1; i <= F; i++)
		insert_node(sp, r - i);

	/*
	* Finally, insert the whole string just read.
	* The global variables match_length and match_position are set.
	*/
	insert_node(sp, r);
	do {
		/* match_length may be spuriously long near the end of text. */
		if (sp->match_length > len)
			sp->match_length = len;
		if (sp->match_length <= THRESHOLD) {
			sp->match_length = 1;  /* Not long enough match.  Send one byte. */
			code_buf[0] |= mask;  /* 'send one byte' flag */
			code_buf[code_buf_ptr++] = sp->text_buf[r];  /* Send uncoded. */
		}
		else {
			/* Send position and length pair. Note match_length > THRESHOLD. */
			code_buf[code_buf_ptr++] = (uint8_t)sp->match_position;
			code_buf[code_buf_ptr++] = (uint8_t)
				(((sp->match_position >> 4) & 0xF0)
					| (sp->match_length - (THRESHOLD + 1)));
		}
		if ((mask <<= 1) == 0) {  /* Shift mask left one bit. */
								  /* Send at most 8 units of code together */
			for (i = 0; i < code_buf_ptr; i++)
				if (dst < dstend)
					*dst++ = code_buf[i];
				else {
					free(sp);
					return (void *)0;
				}
				code_buf[0] = 0;
				code_buf_ptr = mask = 1;
		}
		last_match_length = sp->match_length;
		for (i = 0; i < last_match_length && src < srcend; i++) {
			delete_node(sp, s);    /* Delete old strings and */
			c = *src++;
			sp->text_buf[s] = c;    /* read new bytes */

									/*
									* If the position is near the end of buffer, extend the buffer
									* to make string comparison easier.
									*/
			if (s < F - 1)
				sp->text_buf[s + N] = c;

			/* Since this is a ring buffer, increment the position modulo N. */
			s = (s + 1) & (N - 1);
			r = (r + 1) & (N - 1);

			/* Register the string in text_buf[r..r+F-1] */
			insert_node(sp, r);
		}
		while (i++ < last_match_length) {
			delete_node(sp, s);

			/* After the end of text, no need to read, */
			s = (s + 1) & (N - 1);
			r = (r + 1) & (N - 1);
			/* but buffer may not be empty. */
			if (--len)
				insert_node(sp, r);
		}
	} while (len > 0);   /* until length of string to be processed is zero */

	if (code_buf_ptr > 1) {    /* Send remaining code. */
		for (i = 0; i < code_buf_ptr; i++)
			if (dst < dstend)
				*dst++ = code_buf[i];
			else {
				free(sp);
				return (void *)0;
			}
	}

	free(sp);
	return dst;
}
'''

g_tcc = pytcc.TCC()
g_lzsslib = g_tcc.build_to_mem(pytcc.CCode(g_lzsscode))

lzss_decode_t = CFUNCTYPE(c_int, c_char_p, c_char_p, c_uint32)
lzss_encode_t = CFUNCTYPE(POINTER(c_uint8), c_char_p, c_uint32, c_char_p, c_uint32)
lzss_decode = lzss_decode_t(g_lzsslib['lzss_decode'])
lzss_encode = lzss_encode_t(g_lzsslib['lzss_encode'])

def decode_bip(data: memoryview, outpath=None):
    zsize = len(data) - 4
    rawsize: int = struct.unpack_from("<I", data, 0)[0]
    outdata = bytearray(b'\x00' * rawsize)
    bufsrc = (c_char * zsize).from_buffer(data, 4)
    bufdst = (c_char * rawsize).from_buffer(outdata)
    dstsize = lzss_decode(bufdst, bufsrc, zsize)
    if outpath:
        with open(outpath, 'wb') as fp: 
            fp.write(outdata)
    assert(dstsize == len(outdata))
    return outdata

def encode_bip(data: memoryview, outpath=None):
    rawsize = len(data)
    outsize = 2*rawsize
    outdata = bytearray(b'\x00' * (outsize + 4))
    outdata[:4] = struct.pack("<I", rawsize)
    bufsrc = (c_char * rawsize).from_buffer(data)
    bufdst = (c_char * outsize).from_buffer(outdata, 4)
    pbufdstend = lzss_encode(bufdst, sizeof(bufdst), bufsrc, sizeof(bufsrc))
    zsize = addressof(pbufdstend.contents) - addressof(bufdst)
    del pbufdstend # remove refer
    if outpath:
        with open(outpath, 'wb') as fp: 
            fp.write(outdata[:zsize + 4])
    return outdata[:zsize+4]

def cli(argv: List[str]):
    def cmd_help():
        print("kid_psp_bip d bippath [decpath] # decode bip")
        print("kid_psp_bip e decpath [bippath] # encode bip")

    def cmd_decode():
        decode_bip(data, outpath)

    def cmd_encode():
        encode_bip(data, outpath)

    if len(argv) < 3: cmd_help(); return
    
    cmdtype = argv[1].lower()
    inpath = argv[2]
    outpath = 'out' if len(argv) < 4 else argv[3]

    fp = open(inpath, 'rb') # ACCESS_COPY to enable from_buffer
    data = mmap(fp.fileno(), 0, access=ACCESS_READ | ACCESS_COPY)
    if cmdtype == 'd': cmd_decode()
    elif cmdtype == 'e': cmd_encode()
    else: raise ValueError(f'unsupported cmdtype {argv[1]}!')
    data.close()
    fp.close()

def debug():
    cli([__file__, "d", "C09A.BIP", "C09A_dec.BIP"])
    cli([__file__, "e", "C09A_dec.BIP", "C09A_rebuild.BIP"])

if __name__ == '__main__':
    # debug()
    cli(sys.argv)
    
"""
history

"""