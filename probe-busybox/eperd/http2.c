/*
 * Copyright (c) 2021 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * http2.c
 */

#include "libbb.h"
#include "eperd.h"
#include "http2.h"
#include <assert.h>
#include <stdarg.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>

struct http2_hdr
{
	uint8_t length[3];
	uint8_t type;
	uint8_t flags;
	uint8_t stream_id[4];
};

#define HTTP2_HDR_TYPE_DATA		0
#define HTTP2_HDR_TYPE_HEADERS		1
#define HTTP2_HDR_TYPE_RST_STREAM	3
#define HTTP2_HDR_TYPE_SETTINGS		4
#define HTTP2_HDR_TYPE_PING		6
#define HTTP2_HDR_TYPE_GOAWAY		7
#define HTTP2_HDR_TYPE_WINDOW_UPDATE	8

#define HTTP2_HDR_DATA_END_STREAM	0x01
#define HTTP2_HDR_DATA_PADDED		0x08

#define HTTP2_HDR_HEADERS_END_STREAM	0x01
#define HTTP2_HDR_HEADERS_END_HEADERS	0x04
#define HTTP2_HDR_HEADERS_PADDED	0x08
#define HTTP2_HDR_HEADERS_PRIORITY	0x20

#define HTTP2_HDR_R	0x80000000
#define 	HTTP2_HDR_SETTINGS_ACK 	0x01

#define HTTP2_HDR_SETTINGS_HEADER_TABLE_SIZE		0x01
#define HTTP2_HDR_SETTINGS_ENABLE_PUSH			0x02
#define HTTP2_HDR_SETTINGS_MAX_CONCURRENT_STREAMS	0x03
#define HTTP2_HDR_SETTINGS_INITIAL_WINDOW_SIZE		0x04
#define HTTP2_HDR_SETTINGS_MAX_FRAME_SIZE		0x05
#define HTTP2_HDR_SETTINGS_MAX_HEADER_LIST_SIZE		0x06

#define HTTP2_HDR_GOAWAY_R		0x80000000
#define HTTP2_HDR_WINDOW_UPDATE_R	0x80000000

#define HTTP2_DEFAULT_WINDOW	65535
#define HTTP2_MAX_WINDOW	0x7fffffff

#define HTTP2_PROTOCOL_ERROR		0x1
#define HTTP2_INTERNAL_ERROR		0x2
#define HTTP2_FLOW_CONTROL_ERROR	0x3
#define HTTP2_FRAME_SIZE_ERROR		0x6
#define HTTP2_COMPRESSION_ERROR		0x9

#define HTTP2_HEADER_STATUS	":status"
#define HTTP2_CONTENT_TYPE	"content-type"
#define TEXT_HTML		"text/html"
#define APPLICATION_DNS_MESSAGE	"application/dns-message"

#define HPACK_STATIC_NR	61

#define HPACK_IHF	0x80	/* Indexed Header Field */
#define HPACK_IHF_MASK		0x80
#define HPACK_IHF_PREFIX_LEN	   1

#define HPACK_LHFII	0x40	/* Literal Header Field with Incr. Indexing */
#define HPACK_LHFII_MASK	0xC0
#define HPACK_LHFII_PREFIX_LEN	   2

#define HPACK_LHFwI	0x00	/* Literal Header Field without Indexing */
#define HPACK_LHFwI_MASK	0xF0
#define HPACK_LHFwI_PREFIX_LEN	   4

#define HPACK_LHFNI	0x10	

#define HPACK_INT_MORE		0x80	/* More bytes follow */

#define HPACK_H	0x80	/* Huffman encoding */
#define HPACK_H_MASK		0x80
#define HPACK_H_PREFIX_LEN	   1

#define HPACK_HUFF_ENC_NO	256	/* Number of entries in huffman table */

static struct table_ent
{
	const char *name;
	const char *value;
} static_table[]=
{
/*  0 */ { NULL,				NULL },
/*  1 */ { ":authority",			NULL },
/*  2 */ { ":method",				"GET" },
/*  3 */ { ":method",				"POST" },
/*  4 */ { ":path",				"/" },
/*  5 */ { ":path",				"/index.html" },
/*  6 */ { ":scheme",				"http" },
/*  7 */ { ":scheme",				"https" },
/*  8 */ { ":status",				"200" },
/*  9 */ { ":status",				"204" },
/* 10 */ { ":status",				"206" },
/* 11 */ { ":status",				"304" },
/* 12 */ { ":status",				"400" },
/* 13 */ { ":status",				"404" },
/* 14 */ { ":status",				"500" },
/* 15 */ { "accept-charset",			NULL },
/* 16 */ { "accept-encoding",			"gzip, deflate" },
/* 17 */ { "accept-language",			NULL },
/* 18 */ { "accept-ranges",			NULL },
/* 19 */ { "accept",				NULL },
/* 20 */ { "accept-control-allow-origin",	NULL },
/* 21 */ { "age",				NULL },
/* 22 */ { "allow",				NULL },
/* 23 */ { "authorization",			NULL },
/* 24 */ { "cache-control",			NULL },
/* 25 */ { "content-disposition",		NULL },
/* 26 */ { "content-encoding",			NULL },
/* 27 */ { "content-language",			NULL },
/* 28 */ { "content-length",			NULL },
/* 29 */ { "content-location",			NULL },
/* 30 */ { "content-range",			NULL },
/* 31 */ { "content-type",			NULL },
/* 32 */ { "cookie",				NULL },
/* 33 */ { "date",				NULL },
/* 34 */ { "etag",				NULL },
/* 35 */ { "expect",				NULL },
/* 36 */ { "expires",				NULL },
/* 37 */ { "from",				NULL },
/* 38 */ { "host",				NULL },
/* 39 */ { "if-match",				NULL },
/* 40 */ { "if-modified-since",			NULL },
/* 41 */ { "if-none-match",			NULL },
/* 42 */ { "if-range",				NULL },
/* 43 */ { "if-unmodified-since",		NULL },
/* 44 */ { "last-modified",			NULL },
/* 45 */ { "link",				NULL },
/* 46 */ { "location",				NULL },
/* 47 */ { "max-forwards",			NULL },
/* 48 */ { "proxy-authentication",		NULL },
/* 49 */ { "proxy-authorization",		NULL },
/* 50 */ { "range",				NULL },
/* 51 */ { "referer",				NULL },
/* 52 */ { "refresh",				NULL },
/* 53 */ { "retry-after",			NULL },
/* 54 */ { "server",				NULL },
/* 55 */ { "set-cookie",			NULL },
/* 56 */ { "strict-transport-security",		NULL },
/* 57 */ { "transfer-encoding",			NULL },
/* 58 */ { "user-agent",			NULL },
/* 59 */ { "vary",				NULL },
/* 60 */ { "via",				NULL },
/* 61 */ { "www-authenticate",			NULL },
};

struct huffman_encode
{
	uint32_t encoding;
	uint8_t bits;
	uint8_t value;
} huffman_encode[]=
{
/*   0 */ {     0x1ff8,	13,	  0 },
/*   1 */ {   0x7fffd8,	23,	  1 },
/*   2 */ {  0xfffffe2,	28,	  2 },
/*   3 */ {  0xfffffe3,	28,	  3 },
/*   4 */ {  0xfffffe4,	28,	  4 },
/*   5 */ {  0xfffffe5,	28,	  5 },
/*   6 */ {  0xfffffe6,	28,	  6 },
/*   7 */ {  0xfffffe7,	28,	  7 },
/*   8 */ {  0xfffffe8,	28,	  8 },
/*   9 */ {   0xffffea,	24,	  9 },
/*  10 */ { 0x3ffffffc,	30,	 10 },
/*  11 */ {  0xfffffe9,	28,	 11 },
/*  12 */ {  0xfffffea,	28,	 12 },
/*  13 */ { 0x3ffffffd,	30,	 13 },
/*  14 */ {  0xfffffeb,	28,	 14 },
/*  15 */ {  0xfffffec,	28,	 15 },
/*  16 */ {  0xfffffed,	28,	 16 },
/*  17 */ {  0xfffffee,	28,	 17 },
/*  18 */ {  0xfffffef,	28,	 18 },
/*  19 */ {  0xffffff0,	28,	 19 },
/*  20 */ {  0xffffff1,	28,	 20 },
/*  21 */ {  0xffffff2,	28,	 21 },
/*  22 */ { 0x3ffffffe,	30,	 22 },
/*  23 */ {  0xffffff3,	28,	 23 },
/*  24 */ {  0xffffff4,	28,	 24 },
/*  25 */ {  0xffffff5,	28,	 25 },
/*  26 */ {  0xffffff6,	28,	 26 },
/*  27 */ {  0xffffff7,	28,	 27 },
/*  28 */ {  0xffffff8,	28,	 28 },
/*  29 */ {  0xffffff9,	28,	 29 },
/*  30 */ {  0xffffffa,	28,	 30 },
/*  31 */ {  0xffffffb,	28,	 31 },
/*  32 */ {       0x14,	 6,	' ' },
/*  33 */ {      0x3f8,	10,	'!' },
/*  34 */ {      0x3f9,	10,	'"' },
/*  35 */ {      0xffa,	12,	'#' },
/*  36 */ {     0x1ff9,	13,	'$' },
/*  37 */ {       0x15,	 6,	'%' },
/*  38 */ {       0xf8,	 8,	'&' },
/*  39 */ {      0x7fa,	11,	'\'' },
/*  40 */ {      0x3fa,	10,	'(' },
/*  41 */ {      0x3fb,	10,	')' },
/*  42 */ {       0xf9,	 8,	'*' },
/*  43 */ {      0x7fb,	11,	'+' },
/*  44 */ {       0xfa,	 8,	',' },
/*  45 */ {       0x16,	 6,	'-' },
/*  46 */ {       0x17,	 6,	'.' },
/*  47 */ {       0x18,	 6,	'/' },
/*  48 */ {        0x0,	 5,	'0' },
/*  49 */ {        0x1,	 5,	'1' },
/*  50 */ {        0x2,	 5,	'2' },
/*  51 */ {       0x19,	 6,	'3' },
/*  52 */ {       0x1a,	 6,	'4' },
/*  53 */ {       0x1b,	 6,	'5' },
/*  54 */ {       0x1c,	 6,	'6' },
/*  55 */ {       0x1d,	 6,	'7' },
/*  56 */ {       0x1e,	 6,	'8' },
/*  57 */ {       0x1f,	 6,	'9' },
/*  58 */ {       0x5c,	 7,	':' },
/*  59 */ {       0xfb,	 8,	';' },
/*  60 */ {     0x7ffc,	15,	'<' },
/*  61 */ {       0x20,	 6,	'=' },
/*  62 */ {      0xffb,	12,	'>' },
/*  63 */ {      0x3fc,	10,	'?' },
/*  64 */ {     0x1ffa,	13,	'@' },
/*  65 */ {       0x21,	 6,	'A' },
/*  66 */ {       0x5d,	 7,	'B' },
/*  67 */ {       0x5e,	 7,	'C' },
/*  68 */ {       0x5f,	 7,	'D' },
/*  69 */ {       0x60,	 7,	'E' },
/*  70 */ {       0x61,	 7,	'F' },
/*  71 */ {       0x62,	 7,	'G' },
/*  72 */ {       0x63,	 7,	'H' },
/*  73 */ {       0x64,	 7,	'I' },
/*  74 */ {       0x65,	 7,	'J' },
/*  75 */ {       0x66,	 7,	'K' },
/*  76 */ {       0x67,	 7,	'L' },
/*  77 */ {       0x68,	 7,	'M' },
/*  78 */ {       0x69,	 7,	'N' },
/*  79 */ {       0x6a,	 7,	'O' },
/*  80 */ {       0x6b,	 7,	'P' },
/*  81 */ {       0x6c,	 7,	'Q' },
/*  82 */ {       0x6d,	 7,	'R' },
/*  83 */ {       0x6e,	 7,	'S' },
/*  84 */ {       0x6f,	 7,	'T' },
/*  85 */ {       0x70,	 7,	'U' },
/*  86 */ {       0x71,	 7,	'V' },
/*  87 */ {       0x72,	 7,	'W' },
/*  88 */ {       0xfc,	 8,	'X' },
/*  89 */ {       0xf3,	 7,	'Y' },
/*  90 */ {       0xfd,	 8,	'Z' },
/*  91 */ {     0x1ffb,	13,	'[' },
/*  92 */ {    0x7fff0,	19,	'\\' },
/*  93 */ {     0x1ffc,	13,	']' },
/*  94 */ {     0x3ffc,	14,	'^' },
/*  95 */ {       0x22,	 6,	'_' },
/*  96 */ {     0x7ffd,	15,	'`' },
/*  97 */ {        0x3,	 5,	'a' },
/*  98 */ {       0x23,	 6,	'b' },
/*  99 */ {        0x4,	 5,	'c' },
/* 100 */ {       0x24,	 6,	'd' },
/* 101 */ {        0x5,	 5,	'e' },
/* 102 */ {       0x25,	 6,	'f' },
/* 103 */ {       0x26,	 6,	'g' },
/* 104 */ {       0x27,	 6,	'h' },
/* 105 */ {        0x6,	 5,	'i' },
/* 106 */ {       0x74,	 7,	'j' },
/* 107 */ {       0x75,	 7,	'k' },
/* 108 */ {       0x28,	 6,	'l' },
/* 109 */ {       0x29,	 6,	'm' },
/* 110 */ {       0x2a,	 6,	'n' },
/* 111 */ {        0x7,	 5,	'o' },
/* 112 */ {       0x2b,	 6,	'p' },
/* 113 */ {       0x76,	 7,	'q' },
/* 114 */ {       0x2c,	 6,	'r' },
/* 115 */ {        0x8,	 5,	's' },
/* 116 */ {        0x9,	 5,	't' },
/* 117 */ {       0x2d,	 6,	'u' },
/* 118 */ {       0x77,	 7,	'v' },
/* 119 */ {       0x78,	 7,	'w' },
/* 120 */ {       0x79,	 7,	'x' },
/* 121 */ {       0x7a,	 7,	'y' },
/* 122 */ {       0x7b,	 7,	'z' },
/* 123 */ {     0x7ffe,	15,	'{' },
/* 124 */ {      0x7fc,	11,	'|' },
/* 125 */ {     0x3ffd,	14,	'}' },
/* 126 */ {     0x1ffd,	13,	'~' },
/* 127 */ {  0xffffffc,	28,	127 },
/* 128 */ {    0xfffe6,	20,	128 },
/* 129 */ {   0x3fffd2,	22,	129 },
/* 130 */ {    0xfffe7,	20,	130 },
/* 131 */ {    0xfffe8,	20,	131 },
/* 132 */ {   0x3fffd3,	22,	132 },
/* 133 */ {   0x3fffd4,	22,	133 },
/* 134 */ {   0x3fffd5,	22,	134 },
/* 135 */ {   0x7fffd9,	23,	135 },
/* 136 */ {   0x3fffd6,	22,	136 },
/* 137 */ {   0x7fffda,	23,	137 },
/* 138 */ {   0x7fffdb,	23,	138 },
/* 139 */ {   0x7fffdc,	23,	139 },
/* 140 */ {   0x7fffdd,	23,	140 },
/* 141 */ {   0x7fffde,	23,	141 },
/* 142 */ {   0xffffeb,	24,	142 },
/* 143 */ {   0x7fffdf,	23,	143 },
/* 144 */ {   0xffffec,	24,	144 },
/* 145 */ {   0xffffed,	24,	145 },
/* 146 */ {   0x3fffd7,	22,	146 },
/* 147 */ {   0x7fffe0,	23,	147 },
/* 148 */ {   0xffffee,	24,	148 },
/* 149 */ {   0x7fffe1,	23,	149 },
/* 150 */ {   0x7fffe2,	23,	150 },
/* 151 */ {   0x7fffe3,	23,	151 },
/* 152 */ {   0x7fffe4,	23,	152 },
/* 153 */ {   0x1fffdc,	21,	153 },
/* 154 */ {   0x3fffd8,	22,	154 },
/* 155 */ {   0x7fffe5,	23,	155 },
/* 156 */ {   0x3fffd9,	22,	156 },
/* 157 */ {   0x7fffe6,	23,	157 },
/* 158 */ {   0x7fffe7,	23,	158 },
/* 159 */ {   0xffffef,	24,	159 },
/* 160 */ {   0x3fffda,	22,	160 },
/* 161 */ {   0x1fffdd,	21,	161 },
/* 162 */ {   0xfffe9,	20,	162 },
/* 163 */ {   0x3fffdb,	22,	163 },
/* 164 */ {   0x3fffdc,	22,	164 },
/* 165 */ {   0x7fffe8,	23,	165 },
/* 166 */ {   0x7fffe9,	23,	166 },
/* 167 */ {   0x1fffde,	21,	167 },
/* 168 */ {   0x7fffea,	23,	168 },
/* 169 */ {   0x3fffdd,	22,	169 },
/* 170 */ {   0x3fffde,	22,	170 },
/* 171 */ {   0xfffff0,	24,	171 },
/* 172 */ {   0x1fffdf,	21,	172 },
/* 173 */ {   0x3fffdf,	22,	173 },
/* 174 */ {   0x7fffeb,	23,	174 },
/* 175 */ {   0x7fffec,	23,	175 },
/* 176 */ {   0x1fffe0,	21,	176 },
/* 177 */ {   0x1fffe1,	21,	177 },
/* 178 */ {   0x3fffe0,	22,	178 },
/* 179 */ {   0x1fffe2,	21,	179 },
/* 180 */ {   0x7fffed,	23,	180 },
/* 181 */ {   0x3fffe1,	22,	181 },
/* 182 */ {   0x7fffee,	23,	182 },
/* 183 */ {   0x7fffef,	23,	183 },
/* 184 */ {    0xfffea,	20,	184 },
/* 185 */ {   0x3fffe2,	22,	185 },
/* 186 */ {   0x3fffe3,	22,	186 },
/* 187 */ {   0x3fffe4,	22,	187 },
/* 188 */ {   0x7ffff0,	23,	188 },
/* 189 */ {   0x3fffe5,	22,	189 },
/* 190 */ {   0x3fffe6,	22,	190 },
/* 191 */ {   0x7ffff1,	23,	191 },
/* 192 */ {  0x3ffffe0,	26,	192 },
/* 193 */ {  0x3ffffe1,	26,	193 },
/* 194 */ {    0xfffeb,	20,	194 },
/* 195 */ {    0x7fff1,	19,	195 },
/* 196 */ {   0x3fffe7,	22,	196 },
/* 197 */ {   0x7ffff2,	23,	197 },
/* 198 */ {   0x3fffe8,	22,	198 },
/* 199 */ {  0x1ffffec,	25,	199 },
/* 200 */ {  0x3ffffe2,	26,	200 },
/* 201 */ {  0x3ffffe3,	26,	201 },
/* 202 */ {  0x3ffffe4,	26,	202 },
/* 203 */ {  0x7ffffde,	27,	203 },
/* 204 */ {  0x7ffffdf,	27,	204 },
/* 205 */ {  0x3ffffe5,	26,	205 },
/* 206 */ {   0xfffff1,	24,	206 },
/* 207 */ {  0x1ffffed,	25,	207 },
/* 208 */ {    0x7fff2,	19,	208 },
/* 209 */ {   0x1fffe3,	21,	209 },
/* 210 */ {  0x3ffffe6,	26,	210 },
/* 211 */ {  0x7ffffe0,	27,	211 },
/* 212 */ {  0x7ffffe1,	27,	212 },
/* 213 */ {  0x3ffffe7,	26,	213 },
/* 214 */ {  0x7ffffe2,	27,	214 },
/* 215 */ {   0xfffff2,	24,	215 },
/* 216 */ {   0x1fffe4,	21,	216 },
/* 217 */ {   0x1fffe5,	21,	217 },
/* 218 */ {  0x3ffffe8,	26,	218 },
/* 219 */ {  0x3ffffe9,	26,	219 },
/* 220 */ {  0xffffffd,	28,	220 },
/* 221 */ {  0x7ffffe3,	27,	221 },
/* 222 */ {  0x7ffffe4,	27,	222 },
/* 223 */ {  0x7ffffe5,	27,	223 },
/* 224 */ {    0xfffec,	20,	224 },
/* 225 */ {   0xfffff3,	24,	225 },
/* 226 */ {    0xfffed,	20,	226 },
/* 227 */ {   0x1fffe6,	21,	227 },
/* 228 */ {   0x3fffe9,	22,	228 },
/* 229 */ {   0x1fffe7,	21,	229 },
/* 230 */ {   0x1fffe8,	21,	230 },
/* 231 */ {   0x7ffff3,	23,	231 },
/* 232 */ {   0x3fffea,	22,	232 },
/* 233 */ {   0x3fffeb,	22,	233 },
/* 234 */ {  0x1ffffee,	25,	234 },
/* 235 */ {  0x1ffffef,	25,	235 },
/* 236 */ {   0xfffff4,	24,	236 },
/* 237 */ {   0xfffff5,	24,	237 },
/* 238 */ {  0x3ffffea,	26,	238 },
/* 239 */ {   0x7ffff4,	23,	239 },
/* 240 */ {  0x3ffffeb,	26,	240 },
/* 241 */ {  0x7ffffe6,	27,	241 },
/* 242 */ {  0x3ffffec,	26,	242 },
/* 243 */ {  0x3ffffed,	26,	243 },
/* 244 */ {  0x7ffffe7,	27,	244 },
/* 245 */ {  0x7ffffe8,	27,	245 },
/* 246 */ {  0x7ffffe9,	27,	246 },
/* 247 */ {  0x7ffffea,	27,	247 },
/* 248 */ {  0x7ffffeb,	27,	248 },
/* 249 */ {  0xffffffe,	28,	249 },
/* 250 */ {  0x7ffffec,	27,	250 },
/* 251 */ {  0x7ffffed,	27,	251 },
/* 252 */ {  0x7ffffee,	27,	252 },
/* 253 */ {  0x7ffffef,	27,	253 },
/* 254 */ {  0x7fffff0,	27,	254 },
/* 255 */ {  0x3ffffee,	26,	255 },
};

struct huffman_decode
{
	uint8_t bits;
	uint8_t value;
};

static struct huffman_decode huffman_decode0[256];
static struct huffman_decode huffman_decode_fe[256];
static struct huffman_decode huffman_decode_ff[256];
static struct huffman_decode huffman_decode_fffe[256];
static struct huffman_decode huffman_decode_ffff[256];
static struct huffman_decode huffman_decode_fffff[256];
static struct huffman_decode huffman_decode_fffffe[16];
static struct huffman_decode huffman_decode_ffffff[256];

struct dyn
{
	char *key;
	size_t keylen;
	char *value;
	size_t valuelen;
};

struct http2_env
{
	uint32_t http2_send_global_credits;
	uint32_t http2_send_stream1_credits;
	uint32_t http2_connection_window;
	uint32_t http2_stream1_window;
	uint8_t *http2_headers;
	size_t http2_headers_max;
	size_t http2_headers_offset;
	struct dyn *http2_dyn;
	size_t http2_dyn_max;
	size_t http2_dyn_idx;
	u_char *http2_input;
	size_t http2_input_max;
	size_t http2_input_len;
	u_char *http2_data;
	size_t http2_data_max;
	size_t http2_data_len;
	bool type_html;
	bool type_dns;
	bool done;
	unsigned status;

	struct evbuffer *outbuf;
};

static void send_request2(struct http2_env *env, struct evbuffer *outbuf,
	char *hostname_port, const char *path, u_char *data, size_t datalen);
static void send_settings2(struct evbuffer *outbuf);
static void send_headers2(struct http2_env *env, struct evbuffer *outbuf,
	uint32_t stream_id);
static void send_data2(struct evbuffer *outbuf, u_char *data, size_t datalen,
	uint32_t stream_id);
static void send_goaway2(struct evbuffer *outbuf, uint32_t error_code,
	uint32_t last_stream_id, const char *reason);
static void add_header2(struct http2_env *env,
	const char *name, const char *value);
static void add_byte2(struct http2_env *env, uint8_t byte);
static void add_length2(struct http2_env *env, int prefix_len,
	uint8_t prefix_value, uint32_t value);
static void add_str2(struct http2_env *env, const char *str);
static int Xhttp2_dns_input1(struct http2_env *env, struct evbuffer *inbuf,
	void *ref, http2_write_response_cb_t write_response_cb,
	http2_read_response_cb_t read_response_cb);
static int Xreceive_data2(struct http2_env *env, struct http2_hdr *hdrp,
	uint32_t length, uint32_t stream_id, u_char *buf);
static int Xreceive_headers2(struct http2_env *env, struct http2_hdr *hdrp,
	uint32_t length, uint32_t stream_id,  int verbose, u_char *buf);
static int Xreceive_rst_stream2(struct http2_env *env, uint32_t length,
	uint32_t stream_id, u_char *buf);
static int Xreceive_settings2(struct http2_env *env, struct http2_hdr *hdrp,
	uint32_t length, uint32_t stream_id, u_char *buf);
static int Xreceive_ping2(struct http2_env *env, 
	uint32_t length, uint32_t stream_id, u_char *data);
static int Xreceive_goaway2(struct http2_env *env, 
	uint32_t length, uint32_t stream_id, u_char *data);
static int Xreceive_window_update2(struct http2_env *env,
	uint32_t length, uint32_t stream_id, u_char *buf);
static size_t Xdecode_header2(struct http2_env *env,
	uint8_t *buf, size_t len, int verbose);
static void add_dyn(struct http2_env *env, const char *key, size_t keylen,
	const char *value, size_t valuelen);
static int Xget_dyn(struct http2_env *env, uint32_t value,
	const char **kp, size_t *klen, const char **vp, size_t *vlen);
static size_t Xdecode_int2(struct http2_env *env, uint8_t *buf, size_t len,
	int prefix_len, uint32_t *valuep);
static void init_huffman(void);
static size_t Xdecode_huffman2(struct http2_env *env, uint8_t *buf, size_t len,
	char *outbuf, size_t outbuflen);
static void add_credits2(struct http2_env *env,
	uint32_t stream_id, uint32_t credits);
static int Xreport_header(struct http2_env *env, int verbose,
	const char *key, size_t keylen, const char *value, size_t valuelen);
static int Xparse_status_code2(struct http2_env *env, 
	const char *value, size_t valuelen, int *statusp);
static int memcasecmp(const void *p1, const void *p2, size_t len);
static void fatal(const char *fmt, ...);

struct http2_env *http2_init(void)
{
	struct http2_env *env;

	env= malloc(sizeof(*env));
	env->http2_send_global_credits= 0;
	env->http2_send_stream1_credits= 0;
	env->http2_connection_window= HTTP2_DEFAULT_WINDOW;
	env->http2_stream1_window= HTTP2_DEFAULT_WINDOW;
	env->http2_headers= NULL;
	env->http2_headers_max= 0;
	env->http2_headers_offset= 0;
	env->http2_dyn= NULL;
	env->http2_dyn_max= 0;
	env->http2_dyn_idx= 0;
	env->http2_input= NULL;
	env->http2_input_max= 0;
	env->http2_input_len= 0;
	env->http2_data= NULL;
	env->http2_data_max= 0;
	env->http2_data_len= 0;
	env->type_html= false;
	env->type_dns= false;
	env->done= false;
	env->outbuf= NULL;

	return env;
}

void http2_free(struct http2_env *env)
{
	size_t i;

	free(env->http2_headers);
	env->http2_headers= NULL;
	for (i= 0; i<env->http2_dyn_idx; i++)
	{
		free(env->http2_dyn[i].key);
		env->http2_dyn[i].key= NULL;
		free(env->http2_dyn[i].value);
		env->http2_dyn[i].value= NULL;
	}
	free(env->http2_dyn);
	env->http2_dyn= NULL;
	free(env->http2_input);
	env->http2_input= NULL;
	free(env->http2_data);
	env->http2_data= NULL;
	free(env);
}

void http2_dns(struct http2_env *env, struct bufferevent *bev,
	const char *hostname, const char *port, const char *path,
	u_char *req, size_t reqlen)
{
	static int first= 1;

	char hostname_port[300];

	if (first)
	{
		first= 0;
		init_huffman();
	}

	if (strcmp(port, "443") == 0)
	{
		strlcpy(hostname_port, hostname, sizeof(hostname_port));
	}
	else
	{
		snprintf(hostname_port, sizeof(hostname_port), "%s:%s", 
			hostname, port);
	}

	if (bev)
	{
		send_request2(env, bufferevent_get_output(bev),
			hostname_port, path, req, reqlen);
	}
}

int http2_dns_input(struct http2_env *env, struct bufferevent *bev,
	http2_reply_cb_t reply_cb, void *ref,
	http2_write_response_cb_t write_response_cb,
	http2_read_response_cb_t read_response_cb)
{
	int r;
	size_t avail;
	struct evbuffer *inbuf;

	if (env->done)
		return -1;

	if (bev)
	{
		inbuf= bufferevent_get_input(bev);
		env->outbuf= bufferevent_get_output(bev);
	}
	else
	{
		inbuf= NULL;
		env->outbuf= NULL;
	}

	for(;;)
	{
		if (inbuf)
			avail= evbuffer_get_length(inbuf);
		else
			avail= 1;

		if (avail == 0)
		{
			env->outbuf= NULL;
			return 1;
		}

		r= Xhttp2_dns_input1(env, inbuf, ref, write_response_cb,
			read_response_cb);
		if (r == -1)
		{
			env->outbuf= NULL;
			return -1;
		}
		if (env->done)
		{
			reply_cb(ref, env->status,
				env->http2_data, env->http2_data_len);
			break;
		}
	}
	env->outbuf= NULL;
	return 0;
}

static int Xhttp2_dns_input1(struct http2_env *env, struct evbuffer *inbuf,
	void *ref, http2_write_response_cb_t write_response_cb,
	http2_read_response_cb_t read_response_cb)
{
	int r;
	ssize_t n;
	uint32_t length, stream_id;
	size_t len, needed;
	struct http2_hdr *http2_hdr;
	uint8_t *data;

	needed= sizeof(*http2_hdr);
	if (env->http2_input_max < needed)
	{
		env->http2_input= realloc(env->http2_input, needed);
		env->http2_input_max= needed;
	}
	if (env->http2_input_len < needed)
	{
		len= needed-env->http2_input_len;
		if (read_response_cb)
		{
			n= read_response_cb(ref, env->http2_input +
				env->http2_input_len, len);
		}
		else
		{
			n = evbuffer_remove(inbuf, env->http2_input+
				env->http2_input_len, len);
			if (n < 0)
				fatal("http2_dns_input1: evbuffer_remove failed");
		}

		if (write_response_cb)
		{
			write_response_cb(ref, env->http2_input+
                        	env->http2_input_len, n);
		}

		env->http2_input_len += n;
		if (env->http2_input_len < needed)
			return 0;
	}
#if 0
	fprintf(stderr, "http2_dns_input1: http2_input_len = %lu\n",
		env->http2_input_len);
#endif

	http2_hdr= (struct http2_hdr *)env->http2_input;

	length= (http2_hdr->length[0] << 16) | 
		(http2_hdr->length[1] << 8) |
		http2_hdr->length[2];
#if 0
	fprintf(stderr, "http2_dns_input1: length %u\n", length);
#endif

	needed= sizeof(*http2_hdr) + length;
	if (env->http2_input_max < needed)
	{
		env->http2_input= realloc(env->http2_input, needed);
		env->http2_input_max= needed;
	}
	if (env->http2_input_len < needed)
	{
		len= needed-env->http2_input_len;
		if (read_response_cb)
		{
			n= read_response_cb(ref, env->http2_input +
				env->http2_input_len, len);
		}
		else
		{
			n = evbuffer_remove(inbuf, env->http2_input+
				env->http2_input_len, len);
			if (n < 0)
				fatal("http2_dns_input1: evbuffer_remove failed");
		}

		if (write_response_cb)
		{
			write_response_cb(ref, env->http2_input+
                        	env->http2_input_len, n);
		}

		env->http2_input_len += n;
		if (env->http2_input_len < needed)
			return 0;
	}

	/* Get http2_hdr again because the buffer may have moved */
	http2_hdr= (struct http2_hdr *)env->http2_input;
	stream_id= (http2_hdr->stream_id[0] << 24) |
		(http2_hdr->stream_id[1] << 16) |
		(http2_hdr->stream_id[2] << 8) |
		http2_hdr->stream_id[3];
	stream_id &= ~HTTP2_HDR_R;

#if 0
	fprintf(stderr, "http2_dns_input1: stream ID %u\n", stream_id);
	fprintf(stderr, "http2_dns_input1: type %u\n", http2_hdr->type);
#endif

	data= env->http2_input+sizeof(*http2_hdr);
	switch(http2_hdr->type)
	{
	case HTTP2_HDR_TYPE_DATA:
		r= Xreceive_data2(env, http2_hdr, length, stream_id, data);
		if (r == -1)
			return -1;
		if (http2_hdr->flags & HTTP2_HDR_DATA_END_STREAM)
			env->done= true;
		break;
	case HTTP2_HDR_TYPE_HEADERS:
		r= Xreceive_headers2(env, http2_hdr, length, stream_id,
			0/*verbose*/, data);
		if (r == -1)
			return -1;
		break;
	case HTTP2_HDR_TYPE_RST_STREAM:
		r= Xreceive_rst_stream2(env, length, stream_id, data);
		if (r == -1)
			return -1;
		break;
	case HTTP2_HDR_TYPE_SETTINGS:
		r= Xreceive_settings2(env, http2_hdr, length, stream_id, data);
		if (r == -1)
			return -1;
		break;
	case HTTP2_HDR_TYPE_PING:
		r= Xreceive_ping2(env, length, stream_id, data);
		if (r == -1)
			return -1;
		break;
	case HTTP2_HDR_TYPE_GOAWAY:
		r= Xreceive_goaway2(env, length, stream_id, data);
		if (r == -1)
			return -1;
		break;
	case HTTP2_HDR_TYPE_WINDOW_UPDATE:
		r= Xreceive_window_update2(env, length, stream_id, data);
		if (r == -1)
			return -1;
		break;
	default:
		fprintf(stderr, "receive_reply2: got unknown type %d\n",
			http2_hdr->type);
		send_goaway2(env->outbuf, HTTP2_PROTOCOL_ERROR, 0,
			"unknown type");
		return -1;
	}
	env->http2_input_len= 0;
	return 0;
}

static void send_request2(struct http2_env *env, struct evbuffer *outbuf,
	char *hostname_port, const char *path, u_char *data, size_t datalen)
{
	const char *start= "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

	char str[20];

	evbuffer_add(outbuf, start, strlen(start));

	send_settings2(outbuf);

	snprintf(str, sizeof(str), "%lu", datalen);
	add_header2(env, ":method", "POST");
	add_header2(env, ":scheme", "https");	/* We only do HTTP2 over TLS */
	add_header2(env, ":authority", hostname_port);
	add_header2(env, ":path", path);
	add_header2(env, "user-agent", "RIPE Atlas");
	add_header2(env, "accept", "application/dns-message");
	add_header2(env, "content-type", "application/dns-message");
	add_header2(env, "content-length", str);

	send_headers2(env, outbuf, 1);
	send_data2(outbuf, data, datalen, 1);
}

static void send_settings2(struct evbuffer *outbuf)
{
	uint16_t id;
	uint32_t length, value;
	struct http2_hdr http2_hdr;

	/* Send settings frame. */

	length= sizeof(id) + sizeof(value);
	http2_hdr.length[0]= (length >> 16) & 0xff;
	http2_hdr.length[1]= (length >> 8) & 0xff;
	http2_hdr.length[2]= length & 0xff;
	http2_hdr.type= HTTP2_HDR_TYPE_SETTINGS;
	http2_hdr.flags= 0;
	http2_hdr.stream_id[0]= 
		http2_hdr.stream_id[1]= 
		http2_hdr.stream_id[2]= 
		http2_hdr.stream_id[3]= 0;

	evbuffer_add(outbuf, &http2_hdr, sizeof(http2_hdr));

	id= htons(HTTP2_HDR_SETTINGS_ENABLE_PUSH);
	value= htonl(0);

	evbuffer_add(outbuf, &id, sizeof(id));
	evbuffer_add(outbuf, &value, sizeof(value));
}

static void send_headers2(struct http2_env *env, struct evbuffer *outbuf,
	uint32_t stream_id)
{
	size_t length;
	struct http2_hdr http2_hdr;

	length= env->http2_headers_offset;

	http2_hdr.length[0]= (length >> 16) & 0xff;
	http2_hdr.length[1]= (length >> 8) & 0xff;
	http2_hdr.length[2]= length & 0xff;
	http2_hdr.type= HTTP2_HDR_TYPE_HEADERS;
	http2_hdr.flags= HTTP2_HDR_HEADERS_END_HEADERS;
	http2_hdr.stream_id[0]= (stream_id >> 24) & 0x7f;
	http2_hdr.stream_id[1]= (stream_id >> 16) & 0xff;
	http2_hdr.stream_id[2]= (stream_id >> 8) & 0xff;
	http2_hdr.stream_id[3]= stream_id & 0xff;

	evbuffer_add(outbuf, &http2_hdr, sizeof(http2_hdr));
	evbuffer_add(outbuf, env->http2_headers,
		env->http2_headers_offset);

	free(env->http2_headers);
	env->http2_headers= NULL;
	env->http2_headers_max= 0;
	env->http2_headers_offset= 0;
}

static void send_data2(struct evbuffer *outbuf, u_char *data, size_t datalen,
	uint32_t stream_id)
{
	size_t length;
	struct http2_hdr http2_hdr;

	length= datalen;

	http2_hdr.length[0]= (length >> 16) & 0xff;
	http2_hdr.length[1]= (length >> 8) & 0xff;
	http2_hdr.length[2]= length & 0xff;
	http2_hdr.type= HTTP2_HDR_TYPE_DATA;
	http2_hdr.flags= HTTP2_HDR_DATA_END_STREAM;
	http2_hdr.stream_id[0]= (stream_id >> 24) & 0x7f;
	http2_hdr.stream_id[1]= (stream_id >> 16) & 0xff;
	http2_hdr.stream_id[2]= (stream_id >> 8) & 0xff;
	http2_hdr.stream_id[3]= stream_id & 0xff;

	evbuffer_add(outbuf, &http2_hdr, sizeof(http2_hdr));
	evbuffer_add(outbuf, data, datalen);
}

static void send_goaway2(struct evbuffer *outbuf, uint32_t error_code,
	uint32_t last_stream_id, const char *reason)
{
	size_t length;
	struct http2_hdr http2_hdr;
	uint32_t data[2];

	fprintf(stderr, "send_goaway2: error %d, lat stream id %d, reason %s\n",
		error_code, last_stream_id, reason);

	data[0]= htonl(last_stream_id);
	data[1]= htonl(error_code);

	length= sizeof(data);
	if (reason)
		length += strlen(reason);

	http2_hdr.length[0]= (length >> 16) & 0xff;
	http2_hdr.length[1]= (length >> 8) & 0xff;
	http2_hdr.length[2]= length & 0xff;
	http2_hdr.type= HTTP2_HDR_TYPE_GOAWAY;
	http2_hdr.flags= 0;
	http2_hdr.stream_id[0]= 0;
	http2_hdr.stream_id[1]= 0;
	http2_hdr.stream_id[2]= 0;
	http2_hdr.stream_id[3]= 0;

	evbuffer_add(outbuf, &http2_hdr, sizeof(http2_hdr));
	evbuffer_add(outbuf, data, sizeof(data));
	if (reason)
		evbuffer_add(outbuf, reason, strlen(reason));
}

static void add_header2(struct http2_env *env,
	const char *name, const char *value)
{
#if 0
	fprintf(stderr, "add_header2: %s = %s\n",
		name, value);
#endif

	/* Simple version, no compression */
	add_byte2(env, HPACK_LHFNI);
	add_length2(env, 1, 0x00, strlen(name));
	add_str2(env, name);
	add_length2(env, 1, 0x00, strlen(value));
	add_str2(env, value);
}

static void add_byte2(struct http2_env *env, uint8_t byte)
{
	size_t newsize;

	if (env->http2_headers_max < env->http2_headers_offset+1)
	{
		newsize= env->http2_headers_offset+64;
		env->http2_headers= realloc(env->http2_headers, newsize);
		env->http2_headers_max= newsize;
	}
	env->http2_headers[env->http2_headers_offset]= byte;
	env->http2_headers_offset++;
}

static void add_length2(struct http2_env *env, int prefix_len,
	uint8_t prefix_value, uint32_t value)
{
	int first_bits;
	unsigned first_max;

	assert(prefix_len < 8);
	first_bits= 8-prefix_len;
	first_max= (1 << first_bits)-1;

	if (value < first_max)
	{
		/* Value fits in the first byte */
		add_byte2(env, prefix_value | value);
		return;
	}
	add_byte2(env, prefix_value | first_max);
	value -= first_max;

	while (value > 0x7f)
	{
		add_byte2(env, 0x80 | (value & 0x7f));
		value >>= 7;
	}
	add_byte2(env, value);
}

static void add_str2(struct http2_env *env, const char *str)
{
	size_t len, newsize;

	len= strlen(str);
	if (env->http2_headers_max < env->http2_headers_offset+len)
	{
		newsize= env->http2_headers_offset+len+64;
		env->http2_headers= realloc(env->http2_headers, newsize);
		env->http2_headers_max= newsize;
	}
	memcpy(env->http2_headers+env->http2_headers_offset, str, len);
	env->http2_headers_offset += len;
}

#if 0
static size_t encode_huffman2(char *buf, size_t len,
	u8_t *outbuf, size_t outbuflen)
{
	u8_t byte;
	u32_t value;
	int bits, encbits;
	size_t o, o_out;
	struct huffman_encode *ent;

	bits= 0;
	o= 0;
	o_out= 0;

	for(;;)
	{
#if 0
		fprintf(stderr, "encode_huffman2: len %d, value 0x%x\n",
			bits, value & ((1 << bits)-1));
#endif
		if (bits >= 8)
		{
			if (o_out >= outbuflen)
				fatal("encode_huffman2: output buffer full");
			outbuf[o_out]= (value >> (bits-8)) & 0xff;
#if 0
			fprintf(stderr, "encode_huffman2: byte %d: 0x%x\n",
				o_out, outbuf[o_out]);
#endif
			o_out++;
			bits -= 8;
			continue;
		}

#if 0
		fprintf(stderr, "encode_huffman2: o %d, len %d\n", o, len);
#endif

		if (o >= len)
			break;

		byte= buf[o] & 0xff;
		o++;
		ent= &huffman_encode[byte];
		encbits= ent->bits;
		if (encbits + bits > 32)
		{
			/* Get the first 8 bits */
			value= (value << 8) |
				((ent->encoding >> (encbits-8)) & 0xff);
			bits += 8;
			assert(bits >= 8);
			if (o_out >= outbuflen)
				fatal("encode_huffman2: output buffer full");
			outbuf[o_out]= (value >> (bits-8)) & 0xff;
			o_out++;
			bits -= 8;

			encbits -= 8;
			value= (value << encbits) |
				(ent->encoding & ((1 << encbits)-1));
			bits += encbits;

			continue;
		}

		value= (value << encbits) |
			(ent->encoding & ((1 << encbits)-1));
		bits += encbits;
	}

	assert(o == len);

	if (bits != 0)
	{
		assert(bits < 8);
		value= (value << (8-bits)) | ((1 << (8-bits))-1);
		bits= 8;
		if (o_out >= outbuflen)
			fatal("encode_huffman2: output buffer full");
		outbuf[o_out]= (value >> (bits-8)) & 0xff;
#if 0
		fprintf(stderr, "encode_huffman2: byte %d: 0x%x\n",
			o_out, outbuf[o_out]);
#endif
		o_out++;
		bits -= 8;
		
	}
	assert(bits == 0);
	return o_out;
	fatal("should do trailer");
}

static void send_credits2(FILE *file)
{
	u32_t length, window, stream_id;
	struct http2_hdr http2_hdr;

	length= sizeof(window);
	http2_hdr.length[0]= (length >> 16) & 0xff;
	http2_hdr.length[1]= (length >> 8) & 0xff;
	http2_hdr.length[2]= length & 0xff;
	http2_hdr.type= HTTP2_HDR_TYPE_WINDOW_UPDATE;
	http2_hdr.flags= 0;
	http2_hdr.stream_id[0]= 
		http2_hdr.stream_id[1]= 
		http2_hdr.stream_id[2]= 
		http2_hdr.stream_id[3]= 0;
	window= htonl(http2_send_global_credits);
	http2_send_global_credits= 0;
	assert(window);

	fwrite(&http2_hdr, sizeof(http2_hdr), 1, file);
	fwrite(&window, sizeof(window), 1, file);

	if (http2_send_stream1_credits)
	{
		stream_id= 1;
		http2_hdr.stream_id[0]= (stream_id >> 24) & 0x7f;
		http2_hdr.stream_id[1]= (stream_id >> 16) & 0xff;
		http2_hdr.stream_id[2]= (stream_id >> 8) & 0xff;
		http2_hdr.stream_id[3]= stream_id & 0xff;

		window= htonl(http2_send_stream1_credits);
		http2_send_stream1_credits= 0;
		assert(window);

		fwrite(&http2_hdr, sizeof(http2_hdr), 1, file);
		fwrite(&window, sizeof(window), 1, file);
	}
}

#endif

static int Xreceive_data2(struct http2_env *env, struct http2_hdr *hdrp,
	uint32_t length, uint32_t stream_id, u_char *buf)
{
	size_t data_len, needed, pad_offset, pad_length;

	if (hdrp->flags & HTTP2_HDR_DATA_PADDED)
	{
		pad_offset= 1;
		pad_length= buf[0];
		if (pad_length >= length)
		{
			send_goaway2(env->outbuf, HTTP2_PROTOCOL_ERROR,
				0, "padding error");
			return -1;
		}
	}
	else
	{
		pad_offset= 0;
		pad_length= 0;
	}

	add_credits2(env, stream_id, length);

	data_len= length-(pad_offset+pad_length);
	if (env->type_html)
	{
		fprintf(stderr, "%.*s", (int)data_len, buf+pad_offset);
	}
	if (env->type_dns)
	{
		needed= env->http2_data_len+data_len;
		if (env->http2_data_max < needed)
		{
			needed += 4096;
			env->http2_data= realloc(env->http2_data, needed);
			env->http2_data_max= needed;
		}
		memcpy(env->http2_data+env->http2_data_len,
			buf+pad_offset, data_len);
		env->http2_data_len += data_len;
	}

	return 0;
}

static int Xreceive_headers2(struct http2_env *env, struct http2_hdr *hdrp,
	uint32_t length, uint32_t stream_id,  int verbose, u_char *buf)
{
	size_t o, headers_len, len, pad_offset, pad_length, prio_offset;

	if (stream_id == 0)
	{
		send_goaway2(env->outbuf, HTTP2_PROTOCOL_ERROR, 0,
			"0 stream ID");
		return -1;
	}
	if (stream_id != 1)
	{
		/* We create and support only one stream */
		send_goaway2(env->outbuf, HTTP2_PROTOCOL_ERROR, 0,
			"stream not open");
		return -1;
	}

	if (hdrp->flags & HTTP2_HDR_HEADERS_PADDED)
	{
		pad_offset= 1;
		pad_length= buf[0];
	}
	else
	{
		pad_offset= 0;
		pad_length= 0;
	}

	if (hdrp->flags & HTTP2_HDR_HEADERS_PRIORITY)
		prio_offset= 5;
	else
		prio_offset= 0;

	if (pad_offset + prio_offset + pad_length > length)
	{
		send_goaway2(env->outbuf, HTTP2_PROTOCOL_ERROR,
			0, "too much padding");
		return -1;
	}

	o= pad_offset+prio_offset;
	headers_len= length-pad_length;
	while (o < length)
	{
		len= Xdecode_header2(env, buf+o, headers_len-o, verbose);
		if (len == 0)
			return -1;
		o += len;
	}
	return 0;
}

static int Xreceive_rst_stream2(struct http2_env *env, uint32_t length,
	uint32_t stream_id, u_char *buf)
{
	uint32_t value;

	if (length != 4)
	{
		send_goaway2(env->outbuf, HTTP2_FRAME_SIZE_ERROR, 0, "length");
		return -1;
	}
	memcpy(&value, buf, sizeof(value));
	value= ntohl(value);

	if (stream_id == 0)
	{
		send_goaway2(env->outbuf, HTTP2_PROTOCOL_ERROR, 0,
			"zero stream ID");
		return -1;
	}

	fprintf(stderr, "Got RST on stream %u with error %u\n", 
		stream_id, value);
	return 0;
}

static int Xreceive_settings2(struct http2_env *env, struct http2_hdr *hdrp,
	uint32_t length, uint32_t stream_id, u_char *buf)
{
	size_t o;
	uint16_t type;
	uint32_t value;
	uint8_t *setting;

	if (length % 6 != 0)
	{
		send_goaway2(env->outbuf, HTTP2_FRAME_SIZE_ERROR,
			0, "frame");
		return -1;
	}

	if (hdrp->flags & HTTP2_HDR_SETTINGS_ACK)
	{
#if 0
		fprintf(stderr, "receive_settings2: got ACK\n");
#endif
		if (length != 0)
		{
			send_goaway2(env->outbuf, HTTP2_FRAME_SIZE_ERROR,
				0, "non-empty ACK settings frame");
			return -1;
		}
	}

	if (stream_id != 0)
	{
		send_goaway2(env->outbuf, HTTP2_PROTOCOL_ERROR,
			0, "non-zero stream ID");
		return -1;
	}

	for (o= 0, setting= buf; o<length; o+=6, setting += 6)
	{
		memcpy(&type, setting, sizeof(type));
		memcpy(&value, setting+sizeof(type), sizeof(value));
		type= ntohs(type);
		value= ntohl(value);
		switch(type)
		{
		case HTTP2_HDR_SETTINGS_HEADER_TABLE_SIZE:
#if 0
			fprintf(stderr,
			"receive_settings2: max header table size %u\n",
				value);
#endif
			break;
		case HTTP2_HDR_SETTINGS_ENABLE_PUSH:
#if 0
			fprintf(stderr,
			"receive_settings2: enable push %u\n",
				value);
#endif
			break;
		case HTTP2_HDR_SETTINGS_MAX_CONCURRENT_STREAMS:
#if 0
			fprintf(stderr,
			"receive_settings2: max concurrent streams %u\n",
				value);
#endif
			break;
		case HTTP2_HDR_SETTINGS_INITIAL_WINDOW_SIZE:
#if 0
			fprintf(stderr,
			"receive_settings2: initial window size %u\n",
				value);
#endif
			break;
		case HTTP2_HDR_SETTINGS_MAX_FRAME_SIZE:
#if 0
			fprintf(stderr,
			"receive_settings2: max frame size %u\n",
				value);
#endif
			break;
		case HTTP2_HDR_SETTINGS_MAX_HEADER_LIST_SIZE:
#if 0
			fprintf(stderr,
			"receive_settings2: max header list size %u\n",
				value);
#endif
			break;
		default:
			fprintf(stderr,
				"receive_settings2: unknown setting type %d",
				type);
			break;
		}
	}
	return 0;
}

static int Xreceive_ping2(struct http2_env *env,
	uint32_t length, uint32_t stream_id, u_char *data)
{
	int i;

	if (stream_id != 0)
	{
		send_goaway2(env->outbuf, HTTP2_PROTOCOL_ERROR,
			0, "non-zero stream ID");
		return -1;
	}
	if (length != 8)
	{
		send_goaway2(env->outbuf, HTTP2_FRAME_SIZE_ERROR,
			0, "ping frame not 8 octets");
		return -1;
	}
	fprintf(stderr, "receive_ping2: value: ");
	for (i= 0; (uint32_t)i<length; i++)
		fprintf(stderr, "%02x", data[i]);
	fprintf(stderr, "\n");
	return 0;
}

static int Xreceive_goaway2(struct http2_env *env, 
	uint32_t length, uint32_t stream_id, u_char *data)
{
	int i;
	uint32_t value;

	if (stream_id != 0)
	{
		send_goaway2(env->outbuf, HTTP2_PROTOCOL_ERROR,
			0, "non-zero stream ID");
		return -1;
	}
	if (length < 8)
	{
		send_goaway2(env->outbuf, HTTP2_FRAME_SIZE_ERROR,
			0, "goaway frame not at least 8 octets");
		return -1;
	}
	memcpy(&value, data, sizeof(value));
	value= ntohl(value) & ~HTTP2_HDR_GOAWAY_R;

	fprintf(stderr, "receive_goaway2: last-stream-ID: %u\n", value);

	memcpy(&value, data+4, sizeof(value));
	value= ntohl(value);

	fprintf(stderr, "receive_goaway2: error: %u\n", value);

	fprintf(stderr, "receive_goaway2: debug 0x%x: ", length-8);
	for (i= 8; (uint32_t)i<length; i++)
		fprintf(stderr, "%c", data[i]);
	fprintf(stderr, "\n");

	return 0;
}

static int Xreceive_window_update2(struct http2_env *env,
	uint32_t length, uint32_t stream_id, u_char *buf)
{
	uint32_t value;
	uint32_t *windowp;

	if (length != 4)
	{
		send_goaway2(env->outbuf, HTTP2_FRAME_SIZE_ERROR,
			0, "window update frame not 4 octets");
		return -1;
	}
	memcpy(&value, buf, sizeof(value));
	value= ntohl(value) & ~HTTP2_HDR_WINDOW_UPDATE_R;

	if (value == 0)
	{
		send_goaway2(env->outbuf, HTTP2_PROTOCOL_ERROR,
			0, "zero increment");
		return -1;
	}

	if (stream_id == 0)
		windowp= &env->http2_connection_window;
	else if (stream_id == 1)
		windowp= &env->http2_stream1_window;
	else
	{
		send_goaway2(env->outbuf, HTTP2_INTERNAL_ERROR,
			0, "window increment for unknown stream");
		return -1;
	}
	
	/* Update connection window */
	*windowp += value;
	if (*windowp > HTTP2_MAX_WINDOW)
	{
		send_goaway2(env->outbuf, HTTP2_FLOW_CONTROL_ERROR,
			0, "window overflow");
		return -1;
	}
	return 0;
}

static size_t Xdecode_header2(struct http2_env *env,
	uint8_t *buf, size_t len, int verbose)
{
	int r;
	uint8_t byte;
	uint32_t value;
	size_t o, klen, vlen, namelen, tmplen;
	struct table_ent *ent;
	const char *kp, *vp, *namep;
	char namebuf[256];
	char strbuf[1024];

	assert(sizeof(static_table)/sizeof(static_table[0]) ==
		HPACK_STATIC_NR+1);

	byte= buf[0];
#if 0
	fprintf(stderr, "decode_header2: byte 0x%x\n", byte);
#endif
	if ((byte & HPACK_IHF_MASK) == HPACK_IHF)
	{
		tmplen= Xdecode_int2(env, buf, len, HPACK_IHF_PREFIX_LEN, &value);
		if (tmplen == 0)
			return 0;
		if (value == 0)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "bad index");
			return 0;
		}
		if (value > HPACK_STATIC_NR)
		{
			r= Xget_dyn(env, value, &kp, &klen, &vp, &vlen);
			if (r == -1)
				return 0;
			r= Xreport_header(env, verbose, kp, klen, vp, vlen);
 			if (r == -1)
				return 0;
			return tmplen;
		}
		ent= &static_table[value];
		if (!ent->value)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "entry has no value");
			return 0;
		}
		add_dyn(env, ent->name, strlen(ent->name),
                        ent->value, strlen(ent->value));
		r= Xreport_header(env, verbose, ent->name, strlen(ent->name),
			ent->value, strlen(ent->value));
 		if (r == -1)
			return 0;
		return tmplen;
	}
	if (byte == HPACK_LHFII || byte == HPACK_LHFwI)
	{
		/* Literal Header Field without Indexing --
		 * New Name
		 * or
		 * Literal Header Field with Incremental Indexing --
		 * New Name
		 */
		o= 1;
		if (o >= len)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "out of space");
			return 0;
		}

		byte= buf[o];
		tmplen= Xdecode_int2(env, buf+o, len-o, HPACK_H_PREFIX_LEN,
			&value);
		if (tmplen == 0)
			return 0;
		o += tmplen;
		assert(o <= len);
		if (value > len-o)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "string too large for space");
			return 0;
		}
		if ((byte & HPACK_H_MASK) == HPACK_H)
		{
			tmplen= Xdecode_huffman2(env, buf+o, value,
				namebuf, sizeof(namebuf)-1);
			if (tmplen == 0)
				return 0;
			o += value;
			namebuf[tmplen]= '\0';
		}
		else
		{
			if (value > sizeof(namebuf)-1)
			{
	
				send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
					0, "name too long");
				return 0;
			}
			memcpy(namebuf, buf+o, value);
			namebuf[value]= '\0';
			o += value;
		}

		if (o >= len)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "out of space");
			return 0;
		}

		byte= buf[o];
		tmplen= Xdecode_int2(env, buf+o, len-o, HPACK_H_PREFIX_LEN,
			&value);
		if (tmplen == 0)
			return 0;
		o += tmplen;
		assert(o <= len);
		if (value > len-o)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "string too large for space");
			return 0;
		}
		if ((byte & HPACK_H_MASK) == HPACK_H)
		{
			tmplen= Xdecode_huffman2(env, buf+o, value,
				strbuf, sizeof(strbuf));
			if (tmplen == 0)
				return 0;
			o += value;
			add_dyn(env, namebuf, strlen(namebuf),
                        	strbuf, tmplen);
			r= Xreport_header(env, verbose, namebuf, strlen(namebuf),
				strbuf, tmplen);
 			if (r == -1)
				return 0;
			return o;
		}

		add_dyn(env, namebuf, strlen(namebuf),
                        (char *)buf+o, value);
		r= Xreport_header(env, verbose, namebuf, strlen(namebuf),
			(char *)buf+o, value);
 		if (r == -1)
			return 0;
		o += value;
		return o;
	}
	if ((byte & HPACK_LHFII_MASK) == HPACK_LHFII)
	{
		/* Literal Header Field with Incremental Indexing --
		 * Indexed Name
		 */
		o= 0;
		tmplen= Xdecode_int2(env, buf, len, HPACK_LHFII_PREFIX_LEN,
			&value);
		if (tmplen == 0)
			return 0;
		if (value == 0)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "bad index");
			return 0;
		}
		if (value > HPACK_STATIC_NR)
		{
			r= Xget_dyn(env, value, &namep, &namelen, &vp, &vlen);
			if (r == -1)
				return 0;
			ent= NULL;
		}
		else
		{
			ent= &static_table[value];
			namep= ent->name;
			namelen= strlen(namep);
		}

		o += tmplen;
		if (o >= len)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "out of space");
			return 0;
		}

		byte= buf[o];
		tmplen= Xdecode_int2(env, buf+o, len-o, HPACK_H_PREFIX_LEN,
			&value);
		if (tmplen == 0)
			return 0;
		o += tmplen;
		assert(o <= len);
		if (value > len-o)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "string too large for space");
			return 0;
		}
		if ((byte & HPACK_H_MASK) == HPACK_H)
		{
			tmplen= Xdecode_huffman2(env, buf+o, value,
				strbuf, sizeof(strbuf));
			if (tmplen == 0)
				return 0;
			o += value;
			add_dyn(env, namep, namelen, strbuf, tmplen);
			r= Xreport_header(env, verbose, namep, namelen,
				strbuf, tmplen);
 			if (r == -1)
				return 0;
			return o;
		}

		add_dyn(env, namep, namelen, (char *)buf+o, value);
		r= Xreport_header(env, verbose, namep, namelen,
			(char *)buf+o, value);
 		if (r == -1)
			return 0;
		o += value;
		return o;
	}
	if ((byte & HPACK_LHFwI_MASK) == HPACK_LHFwI)
	{
		/* Literal Header Field without Indexing --
		 * Indexed Name
		 */
		o= 0;
		tmplen= Xdecode_int2(env, buf, len, HPACK_LHFwI_PREFIX_LEN,
			&value);
		if (tmplen == 0)
			return 0;
		if (value == 0)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "bad index");
			return 0;
		}
		if (value > HPACK_STATIC_NR)
		{
			r= Xget_dyn(env, value, &namep, &namelen, &vp, &vlen);
			if (r == -1)
				return 0;
			ent= NULL;
		}
		else
		{
			ent= &static_table[value];
			namep= ent->name;
			namelen= strlen(namep);
		}

		o += tmplen;
		if (o >= len)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "out of space");
			return 0;
		}

		byte= buf[o];
		tmplen= Xdecode_int2(env, buf+o, len-o, HPACK_H_PREFIX_LEN,
			&value);
		if (tmplen == 0)
			return 0;
		o += tmplen;
		assert(o <= len);
		if (value > len-o)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "string too large for space");
			return 0;
		}
		if ((byte & HPACK_H_MASK) == HPACK_H)
		{
			tmplen= Xdecode_huffman2(env, buf+o, value,
				strbuf, sizeof(strbuf));
			if (tmplen == 0)
				return 0;
			o += value;
			r= Xreport_header(env, verbose, namep, namelen,
				strbuf, tmplen);
 			if (r == -1)
				return 0;
			return o;
		}

		r= Xreport_header(env, verbose, namep, namelen,
			(char *)buf+o, value);
 		if (r == -1)
			return 0;
		o += value;
		return o;
	}

	send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
		0, "bad first byte");
	return 0;
}

static void add_dyn(struct http2_env *env, const char *key, size_t keylen,
	const char *value, size_t valuelen)
{
	size_t needed;
	void *k1, *v1;
	struct dyn *dyn;

	if (env->http2_dyn_max < env->http2_dyn_idx+1)
	{
		needed= env->http2_dyn_idx+16;
		env->http2_dyn= realloc(env->http2_dyn, needed*sizeof(*dyn));
		env->http2_input_max= needed;
	}
	dyn= &env->http2_dyn[env->http2_dyn_idx];
	k1= malloc(keylen);
	memcpy(k1, key, keylen);
	v1= malloc(valuelen);
	memcpy(v1, value, valuelen);
	dyn->key= k1;
	dyn->keylen= keylen;
	dyn->value= v1;
	dyn->valuelen= valuelen;
	env->http2_dyn_idx++;
}

static int Xget_dyn(struct http2_env *env, uint32_t value,
	const char **kp, size_t *klen, const char **vp, size_t *vlen)
{
	struct dyn *dyn;

	if (value < HPACK_STATIC_NR)
		fatal("bad value for get_dyn");
	value -= HPACK_STATIC_NR;
	if (value >= env->http2_dyn_idx)
	{
		send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
			0, "bad dynamic index");
		return -1;
	}
	dyn= &env->http2_dyn[env->http2_dyn_idx-1-value];

	*kp= dyn->key;
	*klen= dyn->keylen;
	*vp= dyn->value;
	*vlen= dyn->valuelen;

	return 0;
}

static size_t Xdecode_int2(struct http2_env *env, uint8_t *buf, size_t len,
	int prefix_len, uint32_t *valuep)
{
	uint8_t byte;
	uint32_t v, new_bits, new_value;
	int bits, mask, max_value, shift;
	size_t o;

	assert(prefix_len < 8);
	bits= 8-prefix_len;
	mask= (1 << bits)-1;
	max_value= mask;

	assert(len >= 1);
	byte= buf[0];
	byte &= mask;
	if (byte < max_value)
	{
		*valuep= byte;
		return 1;
	}
	v= 0;
	for (o= 1; o<len; o++)
	{
		byte= buf[o];

		/* Be careful to avoid overflow */
		new_bits= byte & ~HPACK_INT_MORE;
		shift= (o-1)*7;
		new_value= new_bits << shift;
		if (new_value >> shift != new_bits)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "overflow in multi-byte integer");
			return 0;
		}
		v |= new_value;
		if (byte & HPACK_INT_MORE)
		{
			/* More bytes will follow */
			continue;
		}

		/* This is the last byte. Add max_value */
		v += max_value;
		if (v < (uint32_t)max_value)
		{
			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "overflow in multi-byte integer");
			return 0;
		}

		*valuep= v;
		return o+1;
	}
	send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
		0, "multi-byte int runs beyond buffer");
	return 0;
}

static void init_huffman(void)
{
	uint8_t byte, mask, nibble;
	int i, j, len;

	/* Check consitency of huffman_encode */
	assert(sizeof(huffman_encode)/sizeof(huffman_encode[0]) ==
		HPACK_HUFF_ENC_NO);

	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		if (huffman_encode[i].value != i)
		{
			fatal(
		"init_huffman: bad value in huffman_encode: row %d, found %d",
				i, huffman_encode[i].value);
		}
	}

	/* Fill in huffman_decode0 table */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		len= huffman_encode[i].bits;
		if (len >= 8)
		{
			byte= huffman_encode[i].encoding >> (len-8);
			assert(byte < 256);
			if (huffman_decode0[byte].bits == 0)
			{
				/* New entry */
				huffman_decode0[byte].bits= len;
				huffman_decode0[byte].value=
					huffman_encode[i].value;
			}
			else
			{
				/* Existing entry. Old and new bits need
				 * to be more than 8
				 */
				if (huffman_decode0[byte].bits <= 8 ||
					len <= 8)
				{
					fatal(
					"init_huffman: inconsistent entry");
				}
			}
			continue;
		}
		byte= huffman_encode[i].encoding << (8-len);
		assert(byte < 256);
		mask= (1 << (8-len))-1;
		for (j= 0; j<= mask; j++)
		{
			if (huffman_decode0[byte+j].bits != 0)
			{
				fatal(
"init_huffman: duplicate entry: adding row %d, byte 0x%x, offset %d, found bits %d, value %d",
					i, byte, j,
					huffman_decode0[byte+j].bits,
					huffman_decode0[byte+j].value);
			}

			/* New entry */
			huffman_decode0[byte+j].bits= len;
			huffman_decode0[byte+j].value=
				huffman_encode[i].value;
		}
	}

	/* Check that all entries have been filled-in */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		assert(huffman_decode0[i].bits > 0);
	}

	/* Fill in huffman_decode_fe table */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		len= huffman_encode[i].bits;
		if (len <= 8)
			continue;

		if (((huffman_encode[i].encoding >> (len-8)) & 0xff) != 0xfe)
			continue;	/* No FE prefix */

		len -= 8;
		assert(len < 8);

		byte= huffman_encode[i].encoding << (8-len);
		assert(byte < 256);
		mask= (1 << (8-len))-1;
		for (j= 0; j<= mask; j++)
		{
			if (huffman_decode_fe[byte+j].bits != 0)
			{
				fatal(
"init_huffman: duplicate entry: adding row %d, byte 0x%x, offset %d, found bits %d, value %d",
					i, byte, j,
					huffman_decode_fe[byte+j].bits,
					huffman_decode_fe[byte+j].value);
			}

			/* New entry */
			huffman_decode_fe[byte+j].bits= len;
			huffman_decode_fe[byte+j].value=
				huffman_encode[i].value;
		}
	}

	/* Check that all entries have been filled-in */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		if (huffman_decode_fe[i].bits == 0)
		{
			fatal(
			"init_huffman: empty entry %d in huffman_decode_fe",
				i);
		}
	}

	/* Fill in huffman_decode_ff table */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		len= huffman_encode[i].bits;
		if (len <= 8)
			continue;

		if (((huffman_encode[i].encoding >> (len-8)) & 0xff) != 0xff)
			continue;	/* No FF prefix */

		len -= 8;
		if (len >= 8)
		{
			byte= huffman_encode[i].encoding >> (len-8);
			assert(byte < 256);
			if (huffman_decode_ff[byte].bits == 0)
			{
				/* New entry */
				huffman_decode_ff[byte].bits= len;
				huffman_decode_ff[byte].value=
					huffman_encode[i].value;
			}
			else
			{
				/* Existing entry. Old and new bits need
				 * to be more than 8
				 */
				if (huffman_decode_ff[byte].bits <= 8 ||
					len <= 8)
				{
					fatal(
					"init_huffman: inconsistent entry");
				}
			}
			continue;
		}

		byte= huffman_encode[i].encoding << (8-len);
		assert(byte < 256);
		mask= (1 << (8-len))-1;
		for (j= 0; j<= mask; j++)
		{
			if (huffman_decode_ff[byte+j].bits != 0)
			{
				fatal(
"init_huffman: duplicate entry: adding row %d, byte 0x%x, offset %d, found bits %d, value %d",
					i, byte, j,
					huffman_decode_ff[byte+j].bits,
					huffman_decode_ff[byte+j].value);
			}

			/* New entry */
			huffman_decode_ff[byte+j].bits= len;
			huffman_decode_ff[byte+j].value=
				huffman_encode[i].value;
		}
	}

	/* Check that all entries have been filled-in */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		if (huffman_decode_ff[i].bits == 0)
		{
			fatal(
			"init_huffman: empty entry %d in huffman_decode_ff",
				i);
		}
	}

	/* Fill in huffman_decode_fffe table */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		len= huffman_encode[i].bits;
		if (len <= 16)
			continue;

		if (((huffman_encode[i].encoding >> (len-16)) & 0xffff) !=
			0xfffe)
		{
			continue;	/* No FFFE prefix */
		}

		len -= 16;
#if 0
		if (len >= 8)
		{
			byte= huffman_encode[i].encoding >> (len-8);
			assert(byte < 256);
			if (huffman_decode_ff[byte].bits == 0)
			{
				/* New entry */
				huffman_decode_ff[byte].bits= len;
				huffman_decode_ff[byte].value=
					huffman_encode[i].value;
			}
			else
			{
				/* Existing entry. Old and new bits need
				 * to be more than 8
				 */
				if (huffman_decode_ff[byte].bits <= 8 ||
					len <= 8)
				{
					fatal(
					"init_huffman: inconsistent entry");
				}
			}
			continue;
		}
#endif

		byte= huffman_encode[i].encoding << (8-len);
		assert(byte < 256);
		mask= (1 << (8-len))-1;
		for (j= 0; j<= mask; j++)
		{
			if (huffman_decode_fffe[byte+j].bits != 0)
			{
				fatal(
"init_huffman: duplicate entry: adding row %d, byte 0x%x, offset %d, found bits %d, value %d",
					i, byte, j,
					huffman_decode_fffe[byte+j].bits,
					huffman_decode_fffe[byte+j].value);
			}

			/* New entry */
			huffman_decode_fffe[byte+j].bits= len;
			huffman_decode_fffe[byte+j].value=
				huffman_encode[i].value;
		}
	}

	/* Check that all entries have been filled-in */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		if (huffman_decode_fffe[i].bits == 0)
		{
			fatal(
			"init_huffman: empty entry %d in huffman_decode_fffe",
				i);
		}
	}

	/* Fill in huffman_decode_ffff table */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		len= huffman_encode[i].bits;
		if (len <= 16)
			continue;

		if (((huffman_encode[i].encoding >> (len-16)) & 0xffff) !=
			0xffff)
		{
			continue;	/* No FFFF prefix */
		}

		len -= 16;

		if (len >= 8)
		{
			byte= huffman_encode[i].encoding >> (len-8);
			assert(byte < 256);
			if (huffman_decode_ffff[byte].bits == 0)
			{
				/* New entry */
				huffman_decode_ffff[byte].bits= len;
				huffman_decode_ffff[byte].value=
					huffman_encode[i].value;
			}
			else
			{
				/* Existing entry. Old and new bits need
				 * to be more than 8
				 */
				if (huffman_decode_ffff[byte].bits <= 8 ||
					len <= 8)
				{
					fatal(
					"init_huffman: inconsistent entry");
				}
			}
			continue;
		}

		byte= huffman_encode[i].encoding << (8-len);
		assert(byte < 256);
		mask= (1 << (8-len))-1;
		for (j= 0; j<= mask; j++)
		{
			if (huffman_decode_ffff[byte+j].bits != 0)
			{
				fatal(
"init_huffman: duplicate entry: adding row %d, byte 0x%x, offset %d, found bits %d, value %d",
					i, byte, j,
					huffman_decode_ffff[byte+j].bits,
					huffman_decode_ffff[byte+j].value);
			}

			/* New entry */
			huffman_decode_ffff[byte+j].bits= len;
			huffman_decode_ffff[byte+j].value=
				huffman_encode[i].value;
		}
	}

	/* Check that all entries have been filled-in */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		if (huffman_decode_ffff[i].bits == 0)
		{
			fatal(
			"init_huffman: empty entry %d in huffman_decode_ffff",
				i);
		}
	}

	/* Fill in huffman_decode_fffff table */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		len= huffman_encode[i].bits;
		if (len <= 20)
			continue;

		if (((huffman_encode[i].encoding >> (len-20)) & 0xfffff) !=
			0xfffff)
		{
			continue;	/* No FFFFF prefix */
		}

		len -= 20;

		if (len >= 8)
		{
			byte= huffman_encode[i].encoding >> (len-8);
			assert(byte < 256);
			if (huffman_decode_fffff[byte].bits == 0)
			{
				/* New entry */
				huffman_decode_fffff[byte].bits= len;
				huffman_decode_fffff[byte].value=
					huffman_encode[i].value;
			}
			else
			{
				/* Existing entry. Old and new bits need
				 * to be more than 8
				 */
				if (huffman_decode_fffff[byte].bits <= 8 ||
					len <= 8)
				{
					fatal(
					"init_huffman: inconsistent entry");
				}
			}
			continue;
		}

		byte= huffman_encode[i].encoding << (8-len);
		assert(byte < 256);
		mask= (1 << (8-len))-1;
		for (j= 0; j<= mask; j++)
		{
			if (huffman_decode_fffff[byte+j].bits != 0)
			{
				fatal(
"init_huffman: duplicate entry: adding row %d, byte 0x%x, offset %d, found bits %d, value %d",
					i, byte, j,
					huffman_decode_fffff[byte+j].bits,
					huffman_decode_fffff[byte+j].value);
			}

			/* New entry */
			huffman_decode_fffff[byte+j].bits= len;
			huffman_decode_fffff[byte+j].value=
				huffman_encode[i].value;
		}
	}

	/* Check that all entries have been filled-in */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		if (huffman_decode_fffff[i].bits == 0)
		{
			fatal(
			"init_huffman: empty entry %d in huffman_decode_fffff",
				i);
		}
	}

	/* Fill in huffman_decode_fffffe table */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		len= huffman_encode[i].bits;
		if (len <= 24)
			continue;

		if (((huffman_encode[i].encoding >> (len-24)) & 0xffffff) !=
			0xfffffe)
		{
			continue;	/* No FFFFFE prefix */
		}

		len -= 24;

		if (len >= 4)
		{
			nibble= (huffman_encode[i].encoding >> (len-4)) & 0xf;
			assert(nibble < 16);
			if (huffman_decode_fffffe[nibble].bits == 0)
			{
				/* New entry */
				huffman_decode_fffffe[nibble].bits= len;
				huffman_decode_fffffe[nibble].value=
					huffman_encode[i].value;
			}
			else
			{
				/* Existing entry. Old and new bits need
				 * to be more than 8
				 */
				if (huffman_decode_fffffe[byte].bits <= 4 ||
					len <= 4)
				{
					fatal(
					"init_huffman: inconsistent entry");
				}
			}
			continue;
		}

		nibble= (huffman_encode[i].encoding << (4-len)) & 0xf;
		assert(nibble < 16);
		mask= (1 << (4-len))-1;
		for (j= 0; j<= mask; j++)
		{
			if (huffman_decode_fffffe[nibble+j].bits != 0)
			{
				fatal(
"init_huffman: duplicate entry: adding row %d, byte 0x%x, offset %d, found bits %d, value %d",
					i, byte, j,
					huffman_decode_fffffe[nibble+j].bits,
					huffman_decode_fffffe[nibble+j].value);
			}

			/* New entry */
			huffman_decode_fffffe[nibble+j].bits= len;
			huffman_decode_fffffe[nibble+j].value=
				huffman_encode[i].value;
		}
	}

	/* Check that all entries have been filled-in */
	for (i= 0; i<16; i++)
	{
		if (huffman_decode_fffffe[i].bits == 0)
		{
			fatal(
			"init_huffman: empty entry %d in huffman_decode_fffffe",
				i);
		}
	}

	/* Fill in huffman_decode_ffffff table */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		len= huffman_encode[i].bits;
		if (len <= 24)
			continue;

		if (((huffman_encode[i].encoding >> (len-24)) & 0xffffff) !=
			0xffffff)
		{
			continue;	/* No FFFFFF prefix */
		}

		len -= 24;
#if 0
		if (len >= 8)
		{
			byte= huffman_encode[i].encoding >> (len-8);
			assert(byte < 256);
			if (huffman_decode_ff[byte].bits == 0)
			{
				/* New entry */
				huffman_decode_ff[byte].bits= len;
				huffman_decode_ff[byte].value=
					huffman_encode[i].value;
			}
			else
			{
				/* Existing entry. Old and new bits need
				 * to be more than 8
				 */
				if (huffman_decode_ff[byte].bits <= 8 ||
					len <= 8)
				{
					fatal(
					"init_huffman: inconsistent entry");
				}
			}
			continue;
		}
#endif

		byte= huffman_encode[i].encoding << (8-len);
		assert(byte < 256);
		mask= (1 << (8-len))-1;
		for (j= 0; j<= mask; j++)
		{
			if (huffman_decode_ffffff[byte+j].bits != 0)
			{
				fatal(
"init_huffman: duplicate entry: adding row %d, byte 0x%x, offset %d, found bits %d, value %d",
					i, byte, j,
					huffman_decode_ffffff[byte+j].bits,
					huffman_decode_ffffff[byte+j].value);
			}

			/* New entry */
			huffman_decode_ffffff[byte+j].bits= len;
			huffman_decode_ffffff[byte+j].value=
				huffman_encode[i].value;
		}
	}

	/* Claim unused entries */
	for (j= 252; j<256; j++)
	{
		huffman_decode_ffffff[j].bits= 42;
		huffman_decode_ffffff[j].value= 42;
	}

	/* Check that all entries have been filled-in */
	for (i= 0; i< HPACK_HUFF_ENC_NO; i++)
	{
		if (huffman_decode_ffffff[i].bits == 0)
		{
			fatal(
			"init_huffman: empty entry %d in huffman_decode_ffffff",
				i);
		}
	}
}

static size_t Xdecode_huffman2(struct http2_env *env, uint8_t *buf, size_t len,
	char *outbuf, size_t outbuflen)
{
	uint8_t byte, decval, mask, nibble;
	size_t o, o_out;
	uint32_t bits;
	int bitslen, declen;

	o= 0;
	o_out= 0;
	bits= 0;
	bitslen= 0;

	for(;;)
	{
		/* Try to have at least 8 bits. At the end of the string that
		 * may not work.
		 */
		if (bitslen < 8 && o < len)
		{
			bits= (bits << 8) | buf[o];
			bitslen += 8;
			o++;
		}

#if 0
		fprintf(stderr, "decode_huffman2: got bits 0x%x, len %d\n",
			bits & ((1 << bitslen)-1), bitslen);
#endif

		/* Extract first byte */
		if (bitslen < 8)
			byte= bits << (8-bitslen);
		else
			byte= (bits >> (bitslen-8)) & 0xff;

#if 0
		fprintf(stderr, "decode_huffman2: got first byte 0x%02x\n", 
			byte);
#endif

		if (bitslen >= 8 && byte == 0xfe)
		{
			/* Use huffman_decode_fe table */
			bitslen -= 8;
			if (bitslen < 8 && o < len)
			{
				bits= (bits << 8) | buf[o];
				bitslen += 8;
				o++;
			}

			/* Extract second byte */
			if (bitslen < 8)
				byte= bits << (8-bitslen);
			else
				byte= (bits >> (bitslen-8)) & 0xff;

#if 0
			fprintf(stderr,
				"decode_huffman2: got 2nd byte 0x%02x\n", 
				byte);
#endif
			
			declen= huffman_decode_fe[byte].bits;
			decval= huffman_decode_fe[byte].value;

#if 0
			fprintf(stderr,
			"decode_huffman2: got len %d, value '%c'\n", 
				declen, decval);
#endif

			assert(declen <= 8);
			if (declen <= bitslen)
			{
				bitslen -= declen;
				if (o_out >= outbuflen)
				{
					send_goaway2(env->outbuf,
						HTTP2_COMPRESSION_ERROR,
						0, "no space in output buffer");
					return 0;
				}
				outbuf[o_out]= decval;
				o_out++;
				continue;
			}

			send_goaway2(env->outbuf,
				HTTP2_COMPRESSION_ERROR,
				0, "not enough bits");
			return 0;
		}

		if (byte != 0xff)
		{
			declen= huffman_decode0[byte].bits;
			decval= huffman_decode0[byte].value;

#if 0
			fprintf(stderr,
				"decode_huffman2: got len %d, value '%c'\n", 
				declen, decval);
#endif

			if (declen <= bitslen)
			{
				assert(declen <= 8);
				bitslen -= declen;
				if (o_out >= outbuflen)
				{
					send_goaway2(env->outbuf,
						HTTP2_COMPRESSION_ERROR,
						0, "no space in output buffer");
					return 0;
				}
				outbuf[o_out]= decval;
				o_out++;
				continue;
			}

			/* An incomplete symbol marks the end the string.
			 * Perform some checks.
			 */
			assert(bitslen < 8);
			assert(o == len);

			/* The remaining bits should be a prefix of the EOS
			 * symbol, basically all bits have to be one.
			 */
			mask= (1 << bitslen)-1;
			if ((bits & mask) == mask)
				break;

			send_goaway2(env->outbuf,
				HTTP2_COMPRESSION_ERROR,
				0, "garbage at end of string");
			return 0;
		}

		assert(bitslen >= 8);
		assert(byte == 0xff);

		/* Use huffman_decode_ff table */
		bitslen -= 8;
		if (bitslen < 8 && o < len)
		{
			bits= (bits << 8) | buf[o];
			bitslen += 8;
			o++;
		}

		/* Extract second byte */
		if (bitslen < 8)
			byte= bits << (8-bitslen);
		else
			byte= (bits >> (bitslen-8)) & 0xff;

#if 0
		fprintf(stderr,
			"decode_huffman2: got 2nd byte 0x%02x\n", 
			byte);
#endif

		if (bitslen >= 8 && byte == 0xfe)
		{
			/* Use huffman_decode_fffe table */
			bitslen -= 8;
			if (bitslen < 8 && o < len)
			{
				bits= (bits << 8) | buf[o];
				bitslen += 8;
				o++;
			}

			/* Extract third byte */
			if (bitslen < 8)
				byte= bits << (8-bitslen);
			else
				byte= (bits >> (bitslen-8)) & 0xff;

#if 0
			fprintf(stderr,
				"decode_huffman2: got 3rd byte 0x%02x\n", 
				byte);
#endif
			
			declen= huffman_decode_fffe[byte].bits;
			decval= huffman_decode_fffe[byte].value;

#if 0
			fprintf(stderr,
			"decode_huffman2: got len %d, value '%c'\n", 
				declen, decval);
#endif

			assert(declen <= 8);
			if (declen <= bitslen)
			{
				bitslen -= declen;
				if (o_out >= outbuflen)
				{
					send_goaway2(env->outbuf,
						HTTP2_COMPRESSION_ERROR,
						0, "no space in output buffer");
					return 0;
				}
				outbuf[o_out]= decval;
				o_out++;
				continue;
			}

			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "not enough bits");
			return 0;
		}


		if (byte != 0xff)
		{
			declen= huffman_decode_ff[byte].bits;
			decval= huffman_decode_ff[byte].value;

#if 0
			fprintf(stderr,
				"decode_huffman2: got len %d, value '%c'\n", 
				declen, decval);
#endif

			assert(declen <= 8);

			if (declen <= bitslen)
			{
				assert(declen <= 8);
				bitslen -= declen;
				if (o_out >= outbuflen)
				{
					send_goaway2(env->outbuf,
						HTTP2_COMPRESSION_ERROR,
						0, "no space in output buffer");
					return 0;
				}
				outbuf[o_out]= decval;
				o_out++;
				continue;
			}

			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "garbage at end of string");
			return 0;
		}

		assert(bitslen >= 8);
		assert(byte == 0xff);

		/* Use huffman_decode_ffff table */
		bitslen -= 8;
		if (bitslen < 8 && o < len)
		{
			bits= (bits << 8) | buf[o];
			bitslen += 8;
			o++;
		}

		/* Extract third byte */
		if (bitslen < 8)
			byte= bits << (8-bitslen);
		else
			byte= (bits >> (bitslen-8)) & 0xff;

#if 0
		fprintf(stderr,
			"decode_huffman2: got 3rd byte 0x%02x\n", 
			byte);
#endif

		if (bitslen >= 8 && byte == 0xfe)
		{
			/* Use huffman_decode_fffffe table. This table
			 * is index using 4 bits
			 */
			bitslen -= 8;
			if (bitslen < 4 && o < len)
			{
				bits= (bits << 8) | buf[o];
				bitslen += 8;
				o++;
			}

			/* Extract high nibble of fourth byte */
			if (bitslen < 4)
				nibble= bits << (4-bitslen);
			else
				nibble= (bits >> (bitslen-4)) & 0xf;

#if 0
			fprintf(stderr,
		"decode_huffman2: got high nibble of 4th byte 0x%x\n", 
				nibble);
#endif
			
			declen= huffman_decode_fffffe[nibble].bits;
			decval= huffman_decode_fffffe[nibble].value;

#if 0
			fprintf(stderr,
			"decode_huffman2: got len %d, value '%c'\n", 
				declen, decval);
#endif

			assert(declen <= 4);
			if (declen <= bitslen)
			{
				bitslen -= declen;
				if (o_out >= outbuflen)
				{
					send_goaway2(env->outbuf,
						HTTP2_COMPRESSION_ERROR,
						0, "no space in output buffer");
					return 0;
				}
				outbuf[o_out]= decval;
				o_out++;
				continue;
			}

			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "not enough bits");
			return 0;
		}

		if (bitslen >= 8 && (byte & 0xf0) == 0xf0 && byte != 0xff)
		{
			/* Use huffman_decode_fffff table. The prefix is
			 * 20 bits.
			 */
			bitslen -= 4;
			if (bitslen < 8 && o < len)
			{
				bits= (bits << 8) | buf[o];
				bitslen += 8;
				o++;
			}

			/* Extract low nibble of the third byte and the
			 * high nibble of fourth byte
			 */
			if (bitslen < 8)
				byte= bits << (8-bitslen);
			else
				byte= bits >> (bitslen-8);

#if 0
			fprintf(stderr,
		"decode_huffman2: got low 3rd/high 4th 0x%x\n", 
				byte);
#endif
			
			declen= huffman_decode_fffff[byte].bits;
			decval= huffman_decode_fffff[byte].value;

#if 0
			fprintf(stderr,
			"decode_huffman2: got len %d, value '%c'\n", 
				declen, decval);
#endif

			assert(declen <= 8);
			if (declen <= bitslen)
			{
				bitslen -= declen;
				if (o_out >= outbuflen)
				{
					send_goaway2(env->outbuf,
						HTTP2_COMPRESSION_ERROR,
						0, "no space in output buffer");
					return 0;
				}
				outbuf[o_out]= decval;
				o_out++;
				continue;
			}

			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "not enough bits");
			return 0;
		}

		if (byte != 0xff)
		{
			declen= huffman_decode_ffff[byte].bits;
			decval= huffman_decode_ffff[byte].value;

#if 0
			fprintf(stderr,
				"decode_huffman2: got len %d, value '%c'\n", 
				declen, decval);
#endif

			assert(declen <= 8);

			if (declen <= bitslen)
			{
				assert(declen <= 8);
				bitslen -= declen;
				if (o_out >= outbuflen)
				{
					send_goaway2(env->outbuf,
						HTTP2_COMPRESSION_ERROR,
						0, "no space in output buffer");
					return 0;
				}
				outbuf[o_out]= decval;
				o_out++;
				continue;
			}

			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "garbage at end of string");
			return 0;
		}

		assert(bitslen >= 8);
		assert(byte == 0xff);

		/* Use huffman_decode_ffffff table */
		bitslen -= 8;
		if (bitslen < 8 && o < len)
		{
			bits= (bits << 8) | buf[o];
			bitslen += 8;
			o++;
		}

		/* Extract fourth byte */
		if (bitslen < 8)
			byte= bits << (8-bitslen);
		else
			byte= (bits >> (bitslen-8)) & 0xff;

#if 0
		fprintf(stderr,
			"decode_huffman2: got 4th byte 0x%02x\n", 
			byte);
#endif

#if 0
		if (bitslen >= 8 && byte == 0xfe)
		{
			/* Use huffman_decode_fffe table */
			bitslen -= 8;
			if (bitslen < 8 && o < len)
			{
				bits= (bits << 8) | buf[o];
				bitslen += 8;
				o++;
			}

			/* Extract third byte */
			if (bitslen < 8)
				byte= bits << (8-bitslen);
			else
				byte= (bits >> (bitslen-8)) & 0xff;

			fprintf(stderr,
				"decode_huffman2: got 3rd byte 0x%02x\n", 
				byte);
			
			declen= huffman_decode_fffe[byte].bits;
			decval= huffman_decode_fffe[byte].value;

#if 0
			fprintf(stderr,
			"decode_huffman2: got len %d, value '%c'\n", 
				declen, decval);
#endif

			assert(declen <= 8);
			if (declen <= bitslen)
			{
				bitslen -= declen;
				if (o_out >= outbuflen)
				{
					send_goaway2(env->outbuf,
						HTTP2_COMPRESSION_ERROR,
						0, "no space in output buffer");
					return 0;
				}
				outbuf[o_out]= decval;
				o_out++;
				continue;
			}

			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "not enough bits");
			return 0;
		}
#endif

		if (byte != 0xff)
		{
			declen= huffman_decode_ffffff[byte].bits;
			decval= huffman_decode_ffffff[byte].value;

#if 0
			fprintf(stderr,
				"decode_huffman2: got len %d, value '%c'\n", 
				declen, decval);
#endif

			assert(declen <= 8);

			if (declen <= bitslen)
			{
				assert(declen <= 8);
				bitslen -= declen;
				if (o_out >= outbuflen)
				{
					send_goaway2(env->outbuf,
						HTTP2_COMPRESSION_ERROR,
						0, "no space in output buffer");
					return 0;
				}
				outbuf[o_out]= decval;
				o_out++;
				continue;
			}

			send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
				0, "garbage at end of string");
			return 0;
		}

		send_goaway2(env->outbuf, HTTP2_COMPRESSION_ERROR,
			0, "should decode ff");
		return 0;
	}
	return o_out;
}

static void add_credits2(struct http2_env *env,
	uint32_t stream_id, uint32_t credits)
{
	env->http2_send_global_credits += credits;
	if (stream_id == 1)
		env->http2_send_stream1_credits += credits;
	else
	{
		fatal("add_credits2: should handle more streams");
	}
}

static int Xreport_header(struct http2_env *env, int verbose,
	const char *key, size_t keylen, const char *value, size_t valuelen)
{
	int r, status;
	size_t len;
	const u_char *p;

	if (verbose)
	{
		fprintf(stderr, "'%.*s': '%.*s'\n", (int)keylen, key,
			(int)valuelen, value);
	}

	if (keylen == strlen(HTTP2_HEADER_STATUS) &&
		memcmp(key, HTTP2_HEADER_STATUS, keylen) == 0)
	{
		r= Xparse_status_code2(env, value, valuelen, &status);
		if (r == -1)
			return -1;
		env->status= status;
		if (verbose)
			fprintf(stderr, "HTTP/2 %.*s\n", (int)valuelen, value);
		else if (status != 200)
			fprintf(stderr, "Request failed with %03d\n", status);
	}
	if (keylen == strlen(HTTP2_CONTENT_TYPE) &&
		memcmp(key, HTTP2_CONTENT_TYPE, keylen) == 0)
	{
		len= valuelen;
		p= memchr(value, ';', len);
		if (p != NULL)
			len= p-(const u_char *)value;
		
		/* Trim trailing white space */
		while (len > 0 && isspace(value[len-1]))
			len--;

		p= (const u_char *)value;
		/* Skip leading white space */
		while (p < (const u_char *)value+len && isspace(*p))
			p++;
		len= (const u_char *)value+len-p;

		if (len == strlen(TEXT_HTML) &&
			memcasecmp(p, TEXT_HTML, len) == 0)
		{
			env->type_html= true;
		}
		if (len == strlen(APPLICATION_DNS_MESSAGE) &&
			memcasecmp(p, APPLICATION_DNS_MESSAGE, len) == 0)
		{
			env->type_dns= true;
		}

			
	}
	return 0;
}

static int Xparse_status_code2(struct http2_env *env, 
	const char *value, size_t valuelen, int *statusp)
{
	int status;
	size_t i;
	char *check;
	char buf[4];

	if (valuelen != sizeof(buf)-1)
	{
		send_goaway2(env->outbuf, HTTP2_PROTOCOL_ERROR, 0,
			"bad status code");
		return -1;
	}
	memcpy(buf, value, valuelen);
	buf[valuelen]= '\0';

	for (i= 0; i<valuelen; i++)
	{
		if (!isdigit((unsigned char)value[i]))
		{
			send_goaway2(env->outbuf, HTTP2_PROTOCOL_ERROR, 0,
				"error parsing status code");
			return -1;
		}
	}

	status= strtoul(buf, &check, 10);
	if (check[0] != '\0')
	{
		send_goaway2(env->outbuf, HTTP2_PROTOCOL_ERROR, 0,
			"garbage after status code");
		return -1;
	}

	*statusp= status;
	return 0;
}

static int memcasecmp(const void *p1, const void *p2, size_t len)
{
	const u_char *cp1, *cp2;
	int c1, c2;
	size_t i;

	cp1= p1;
	cp2= p2;

	for (i= 0; i<len; i++)
	{
		c1= *cp1++;
		c2= *cp2++;

		if (c1 == c2)
			continue;

		if (isascii(c1) && isascii(c2) &&
			tolower(c1) == tolower(c2))
		{
			continue;
		}
		if (c1 < c2)
			return -1;
		else
			return 1;
	}
	return 0;
}

static void fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	crondlog(DIE9 "fatal");
}
