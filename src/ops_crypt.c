#include "db.h"
#include "ops.h"
#include "opts.h"
#include "hdr.h"
#include "types.h"

#include <stdio.h>
#include <string.h>

#define BS (131072)

int encrypt() {
	struct pk  pk;
	struct sk  sk;
	struct hdr hdr;
	enum   rc  rc;
    
	switch ( (rc = get_pk(opts.target, &pk)) ) {
		case PK_FOUND:
			break;

		case DB_LOCKED:
			fprintf(stderr, "Failed to retrieve public key. The database is locked.\n");
			return 75;
			break;

		case DB_BUSY:
			fprintf(stderr, "Failed to retrieve public key. The database is busy.\n");
			return 75;
			break;
        
		case NOT_FOUND:
			fprintf(stderr, "Their is no public key named \"%s\" in the database.\n", opts.target);
			return 1;
			break;

		default:
			fprintf(stderr, "Failed to retrieve public key (rc = %i).\n", rc);
			return 70;
			break;
	}

	switch ( (rc = get_sk(opts.source, &sk)) ) {
		case SK_FOUND:
			break;

		case DB_LOCKED:
			fprintf(stderr, "Failed to retrieve private key. The database is locked.\n");
			return 75;
			break;

		case DB_BUSY:
			fprintf(stderr, "Failed to retrieve private key. The databse is busy.\n");
			return 75;
			break;

		case NOT_FOUND:
			fprintf(stderr, "Their is no private key named \"%s\" in the database.\n", opts.source);
			return 1;
			break;

		default:
			fprintf(stderr, "Failed to retrieve privat key (rc = %i).\n", rc);
			return 70;
			break;
	}
	
	init_hdr(&hdr);
	uint8_t k[crypto_secretbox_KEYBYTES];
	memcpy(k, &hdr.hdr[NONCE_LENGTH + MAC_LENGTH], sizeof(k));
	
	if ( enc_hdr(&hdr, &pk, &sk) ) {
		fprintf(stderr, "I'm to dumb to use crypto_box().\n");
		return 70;
	}

	if ( fwrite(&hdr.hdr, sizeof(hdr.hdr), 1, stdout) != 1 || ferror(stdout) ) {
		fprintf(stderr, "Failed to encrypt message from \"%s\" to \"%s\". Write to standard output failed.\n", opts.source, opts.target);
		return 74;
	}
	
	uint8_t n[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t m[crypto_secretbox_ZEROBYTES + BS];
	uint8_t c[crypto_secretbox_ZEROBYTES + BS];
	
	for ( uint64_t i = 0; true; i++ ) {
		if ( i == UINT64_MAX ) {
			fprintf(stderr, "You managed to encrypt 2^64 blocks -> Overflow :-(.");
			return 70;
		}
		
		n[0] = i >> 56; n[1] = i >> 48; n[2] = i >> 40; n[3] = i >> 32;
		n[4] = i >> 24; n[5] = i >> 16; n[6] = i >>  8; n[7] = i >>  0;

		memset(m, 0, crypto_secretbox_ZEROBYTES);
		size_t j = fread(m + crypto_secretbox_ZEROBYTES, 1, BS, stdin);
		if ( ferror(stdin) ) {
			fprintf(stderr, "Failed to encrypt message from \"%s\" to \"%s\". Read from standard input failed.\n", opts.source, opts.target);
			return 74;
		}
		
		if ( crypto_secretbox(c, m, crypto_secretbox_ZEROBYTES + j, n, k) ) {
			fprintf(stderr, "I'm to dumb to use crypto_secretbox().\n");
			return 70;
		}

		if ( fwrite(c + crypto_secretbox_BOXZEROBYTES, j + crypto_secretbox_BOXZEROBYTES, 1, stdout) != 1 || ferror(stdout) ) {
			fprintf(stderr, "Failed to encrypt message from \"%s\" to \"%s\". Write to standard output failed.\n", opts.source, opts.target);
			return 74;
		}
		
		if ( feof(stdin) )
			break;
	}
	return 0;
}

int decrypt() {
	struct pk  pk;
	struct sk  sk;
	struct hdr hdr;
	enum   rc  rc;
	    
	switch ( (rc = get_pk(opts.source, &pk)) ) {
		case PK_FOUND:
			break;

		case DB_LOCKED:
			fprintf(stderr, "Failed to retrieve public key. The database is locked.\n");
			return 75;
			break;

		case DB_BUSY:
			fprintf(stderr, "Failed to retrieve public key. The database is busy.\n");
			return 75;
			break;
        
		case NOT_FOUND:
			fprintf(stderr, "Their is no public key named \"%s\" in the database.\n", opts.target);
			return 1;
			break;

		default:
			fprintf(stderr, "Failed to retrieve public key (rc = %i).\n", rc);
			return 70;
			break;
	}

	switch ( (rc = get_sk(opts.target, &sk)) ) {
    	case SK_FOUND:
			break;

		case DB_LOCKED:
			fprintf(stderr, "Failed to retrieve private key. The database is locked.\n");
			return 75;
			break;

		case DB_BUSY:
			fprintf(stderr, "Failed to retrieve private key. The databse is busy.\n");
			return 75;
			break;

		case NOT_FOUND:
			fprintf(stderr, "Their is no private key named \"%s\" in the database.\n", opts.source);
			return 1;
			break;

		default:
			fprintf(stderr, "Failed to retrieve privat key (rc = %i).\n", rc);
			return 70;
			break;
	}
	
	if ( fread(hdr.hdr, sizeof(hdr.hdr), 1, stdin) != 1 || ferror(stdin) ) {
    	fprintf(stderr, "Failed to decrypt message from \"%s\" to \"%s\". Read from standard input failed.\n", opts.source, opts.target);
		return 74;
	}

	if ( feof(stdin) ) {
    	fprintf(stderr, "Failed to decrypt message from \"%s\" to \"%s\". The message is too short to be valid.\n", opts.source, opts.target);
		return 76;
	}
	
	if ( dec_hdr(&hdr, &pk, &sk) ) {
		fprintf(stderr, "Failed to decrypt message from \"%s\" to \"%s\". The header is corrupted.\n", opts.source, opts.target);
		return 76;
	}

	uint8_t k[crypto_secretbox_KEYBYTES];
	memcpy(k, &hdr.hdr[NONCE_LENGTH + MAC_LENGTH], sizeof(k));
	
	uint8_t n[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t m[crypto_secretbox_ZEROBYTES + BS];
	uint8_t c[crypto_secretbox_ZEROBYTES + BS];
	
	for ( uint64_t i = 0; true; i++ ) {
		if ( feof(stdin) )
			break;
		
		if ( i == UINT64_MAX ) {
			fprintf(stderr, "You managed to decrypt 2^64 blocks -> Overflow :-(.");
			return 70;
		}

		n[0] = i >> 56; n[1] = i >> 48; n[2] = i >> 40; n[3] = i >> 32;
		n[4] = i >> 24; n[5] = i >> 16; n[6] = i >>  8; n[7] = i >>  0;
		
		memset(c, 0, crypto_secretbox_BOXZEROBYTES);
		size_t j = fread(c + crypto_secretbox_BOXZEROBYTES, 1, BS + MAC_LENGTH, stdin);
		if ( ferror(stdin) ) {
			fprintf(stderr, "Failed to decrypt message from \"%s\" to \"%s\". Read from standard output failed.\n", opts.source, opts.target);
			return 74;
		}
		
			
		if ( j < MAC_LENGTH ) {
			fprintf(stderr, "Failed to decrypt message from \"%s\" to \"%s\". The block #%" PRIu64 " is too short be valid.\n", opts.source, opts.target, i);
			return 76;
		}
    	
		if ( crypto_secretbox_open(m, c, crypto_secretbox_BOXZEROBYTES + j, n, k) ) {
			fprintf(stderr, "Failed to decrypt message from \"%s\" to \"%s\". The block #%" PRIu64 " has an invalid MAC.\n", opts.source, opts.target, i);
			return 76;
		}
		
		j -= MAC_LENGTH;
		if ( j != 0 && fwrite(m + crypto_secretbox_ZEROBYTES, j, 1, stdout) != 1 ) {
			fprintf(stderr, "Failed to decrypt message from \"%s\" to \"%s\". Write to standard output failed.\n", opts.source, opts.target);
			return 74;
		}

		if ( ferror(stdout) ) {
			fprintf(stderr, "Failed to decrypt message from \"%s\" to \"%s\". I/O error on standard output.\n", opts.source, opts.target);
			return 74;
		}
	}
	
	return 0;
}
