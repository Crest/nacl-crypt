#include "hdr.h"

#include <string.h>

#include <crypto_box.h>
#include <crypto_secretbox.h>
#include <randombytes.h>

#define HDR_NONCE(x) ((x)->hdr)
#define HDR_MAC(x) (((x)->hdr) + NONCE_LENGTH)
#define HDR_KEY(x) (((x)->hdr) + NONCE_LENGTH + MAC_LENGTH)

void init_hdr(struct hdr *restrict hdr) {
	void *nonce = HDR_NONCE(hdr);
	void *key   = HDR_KEY(hdr);
	
	randombytes(nonce, NONCE_LENGTH);
	randombytes(key, KEY_LENGTH);
}

int enc_hdr(struct hdr *restrict hdr, const struct pk *restrict pk, const struct sk *restrict sk) {
	uint8_t       m[crypto_box_ZEROBYTES + KEY_LENGTH];
	uint8_t       c[crypto_box_ZEROBYTES + KEY_LENGTH];
	const void   *n = HDR_NONCE(hdr);
	const void   *p = pk->pk;
	const void   *s = sk->sk;
	const void   *k = HDR_KEY(hdr);
	const size_t  l = sizeof(m);
	int           r;

	memset(m, 0, crypto_box_ZEROBYTES);
	memcpy(m + crypto_box_ZEROBYTES, k, KEY_LENGTH);
		
	if ( (r = crypto_box(c,m,l,n,p,s)) ) return r;
	memcpy(HDR_MAC(hdr), c + crypto_box_BOXZEROBYTES, sizeof(c) - crypto_box_BOXZEROBYTES);
	
	return 0;
}

int dec_hdr(struct hdr *restrict hdr, const struct pk *restrict pk, const struct sk *restrict sk) {
	uint8_t       m[crypto_box_ZEROBYTES + KEY_LENGTH];
	uint8_t       c[crypto_box_ZEROBYTES + KEY_LENGTH];
	const void   *n = HDR_NONCE(hdr);	
	const void   *p = pk->pk;
	const void   *s = sk->sk;
	      void   *k = HDR_KEY(hdr);
	const size_t  l = sizeof(m);
	int           r;
	
	memset(c, 0, crypto_box_BOXZEROBYTES);
	memcpy(c + crypto_box_BOXZEROBYTES, HDR_MAC(hdr), sizeof(c) - crypto_box_BOXZEROBYTES);
	
	if ( (r = crypto_box_open(m,c,l,n,p,s)) ) return r;
	memcpy(k, m + crypto_box_ZEROBYTES, KEY_LENGTH);
	
	return 0;
}
