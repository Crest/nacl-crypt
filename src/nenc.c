#include "types.h"
#include "db.h"
#include "opts.h"
#include "hdr.h"

#include <crypto_box.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define BS (131072)

static int start_db();
static int dispatch();
static int generate_key();
static int export_key();
static int import_key();
static int delete_key();
static int list_keys();
static int encrypt();
static int decrypt();

int main(int argc, char **argv) {
	char *db_path   = parse_args(&argc, &argv);
	int   exit_code = 0;
	
	if ( (exit_code = start_db(db_path)) ) goto quit;
	
	exit_code = dispatch();
	
quit:
	close_db();
	return exit_code;
}

static int dispatch() {
	int exit_code = 0;
	
	switch ( opts.op ) {
		case GENERATE_KEY:
			exit_code = generate_key();
			break;
		
		case EXPORT_KEY:
			exit_code = export_key();
			break;
			
		case IMPORT_KEY:
			exit_code = import_key();
			break;

		case DELETE_KEY:
			exit_code = delete_key();
			break;

		case LIST_KEYS:
			exit_code = list_keys();
			break;

		case ENCRYPT:
			exit_code = encrypt();
			break;

		case DECRYPT:
			exit_code = decrypt();
			break;
		
		default:
			fprintf(stderr, "Unsupported operation.\n");
			close_db();
			exit(2);
	}
	return exit_code;
}

static int start_db(char *db_path) {
	enum rc rc;
	switch ( rc = open_db(db_path) ) {
        	case OK:
			return 0;

		case DB_LOCKED:
			fprintf(stderr, "Failed to open database. It's locked.");
			return 75;
			break;

		case DB_BUSY:
			fprintf(stderr, "Failed to open database. It's busy.");
			return 75;
			break;

		default:
			fprintf(stderr, "Failed to open database (rc = %i).\n", rc);
			return 66;
			break;
	}
}

static uint8_t to_hex(uint8_t n) {
	return ( n < 10 ) ? '0' + n : 'A' - 10 + n;
}

static void pk_to_hex(struct hex_pk *hex, const struct pk *bin) {
	for ( int i = 0; i < crypto_box_PUBLICKEYBYTES; i++ ) {
		uint8_t x = bin->pk[i];
		hex->hex_pk[2 * i    ] = to_hex(x >> 4);
		hex->hex_pk[2 * i + 1] = to_hex(x & 15);
	}
	hex->hex_pk[2 * crypto_box_PUBLICKEYBYTES] = '\0';
}

static void sk_to_hex(struct hex_sk *hex, const struct sk *bin) {
	 for ( int i = 0; i < crypto_box_SECRETKEYBYTES; i++ ) {
	 	uint8_t x = bin->sk[i];
		hex->hex_sk[2 * i    ] = to_hex(x >> 4);
		hex->hex_sk[2 * i + 1] = to_hex(x & 15);
	}
	hex->hex_sk[2 * crypto_box_SECRETKEYBYTES] = '\0';
}

static void kp_to_hex(struct hex_kp *hex, const struct kp *bin) {
	pk_to_hex(&hex->hex_pk, &bin->pk);
	sk_to_hex(&hex->hex_sk, &bin->sk);
}

static int generate_key() {
	struct kp kp;
	enum rc   rc;
	crypto_box_keypair(kp.pk.pk, kp.sk.sk);
	
	switch ( rc = opts.force ? put_kp(opts.name, &kp) : set_kp(opts.name, &kp) ) {
		case KP_STORED:
			printf("Generated keypair named \"%s\".\n", opts.name);
			break;
		
		case SK_OVERWRITE_FAILED:
			fprintf(stderr, "Failed to add new private key named \"%s\" to database. Their is an other private key named \"%s\" in the database.\n", opts.name, opts.name);
			return 65;
			break;
			
		case PK_OVERWRITE_FAILED:
			fprintf(stderr, "Failed to add new public key named \"%s\" to database. Their is an other public key named \"%s\" in the database.\n", opts.name, opts.name);
			return 65;
			break;

		case DB_LOCKED:
			fprintf(stderr, "Failed to add new key pair. The database is locked.\n");
			return 75;
			break;

		case DB_BUSY:
			fprintf(stderr, "Failed to add new key pair. The database is busy.\n");
			return 75;
			break;
		
		default:
			fprintf(stderr, "Failed to add key pair to database (rc = %i).\n", rc);
			return 70;
			break;
	}
	
	return 0;	
}

static int export_key() {
	struct kp     kp;
	struct hex_kp hex;
	enum rc       rc = NOT_FOUND;

	if ( opts.use_public && opts.use_private ) {
		rc = get_kp(opts.name, &kp);
	} else if ( opts.use_public ) {
		rc = get_pk(opts.name, &kp.pk);
	} else if ( opts.use_private ) {
		rc = get_sk(opts.name, &kp.sk);
	}
	
	switch ( rc ) {
		case NOT_FOUND:
		case PK_FOUND:
		case SK_FOUND:
		case KP_FOUND:
			break;
		
		case DB_LOCKED:
			fprintf(stderr, "Failed to retrieve key material. The database is locked.\n");
			return 75;
			break;

		case DB_BUSY:
			fprintf(stderr, "Failed to retrieve key material. The database is busy.\n");
			return 75;
			break;
			
		default:
			fprintf(stderr, "Failed to retrieve key material from database (rc = %i).\n", rc);
			return 70;
			break;
	}

	if ( rc == NOT_FOUND && !(opts.use_public ^ opts.use_private) ) {
		fprintf(stderr, "Their is no key named \"%s\" stored in the database.\n", opts.name);
		return 1;
	}

	if ( !(rc & PK_FOUND) && opts.use_public ) {
		fprintf(stderr, "Their is no public key named \"%s\" stored in the database.\n", opts.name);
		return 1;
	}

	if ( !(rc & SK_FOUND) && opts.use_private ) {
		fprintf(stderr, "Their is no private key named \"%s\" stored in the database.\n", opts.name);
		return 1;
	}
	
	if ( opts.use_public && opts.use_private ) {
		kp_to_hex(&hex, &kp);
		printf("p:%s\nP:%s\n", hex.hex_pk.hex_pk, hex.hex_sk.hex_sk);
	} else if ( opts.use_public ) {
		pk_to_hex(&hex.hex_pk, &kp.pk);
		printf("p:%s\n", hex.hex_pk.hex_pk);
	} else if ( opts.use_private ) {
		sk_to_hex(&hex.hex_sk, &kp.sk);
		printf("P:%s\n", hex.hex_sk.hex_sk);
	}

	return 0;
}

#define MAX_LINE 1024

size_t hex_chars(const char *restrict s) {
	size_t n = 0;
	while ( isxdigit(*s++) ) n++;
	return n;
}

static char parse_line(const char **data) {
	char buf[MAX_LINE];
	char *p = fgets(buf, sizeof(buf), stdin);
	
	if ( !p ) return '\0';
	
	char c = p[0];
	if ( c != 'p' && c != 'P' ) return '\0';
	
	char s = p[1];
	if ( s != ':' ) return '\0';
	
	switch ( c ) {
		case 'p':
			if ( hex_chars(buf + 2) != 2 * crypto_box_PUBLICKEYBYTES )
				return '\0';
			break;
		
		case 'P':
			if ( hex_chars(buf + 2) != 2 * crypto_box_SECRETKEYBYTES )
				return '\0';
			break;
		
		default:
			printf("%s", buf);
			return '\0';
	}
	
	*data = buf + 2;
	return c;
}

static uint8_t dehex_half(const char *restrict str) {
	if ( !str )
		return 0xFF;
	
	switch ( *str ) {
		case '0': return 0;
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'a':
		case 'A': return 0xA;
		case 'b':
		case 'B': return 0xB;
		case 'c':
		case 'C': return 0xC;
		case 'd':
		case 'D': return 0xD;
		case 'e':
		case 'E': return 0xE;
		case 'f':
		case 'F': return 0xF;
		default : return 0xFF;
	}
}

static uint16_t dehex(const char *restrict str) {
	if ( !str ) {
    	return 0xFFFF;
	}

	uint8_t n0 = dehex_half(&str[0]); if ( n0 == 0xFF ) return 0xFFFF;
	uint8_t n1 = dehex_half(&str[1]); if ( n1 == 0xFF ) return 0xFFFF;
	
	return (n0 << 4) | n1;
}

static int dehex_pk(struct pk *pk, const char *line) {
	for ( int i = 0; i < crypto_box_PUBLICKEYBYTES; i++ ) {
    	uint16_t byte = dehex(&line[2*i]);
		if ( byte == 0xFFFF ) return 1;
		pk->pk[i] = byte;
	}
	
	return 0;
}

static int dehex_sk(struct sk *sk, const char *line) {
	for ( int i = 0; i < crypto_box_SECRETKEYBYTES; i++ ) {
    	uint16_t byte = dehex(&line[2*i]);
		if ( byte == 0xFFFF ) return 1;
		sk->sk[i] = byte;
	}
	return 0;
}

static int import_key() {
	const char *line = NULL;
	enum rc     rc   = NOT_FOUND;
	struct kp   kp;
	
	if ( opts.use_public  && ('p' != parse_line(&line) || dehex_pk(&kp.pk, line)) )
		return 66;
	
	if ( opts.use_private && ('P' != parse_line(&line) || dehex_sk(&kp.sk, line)) )
		return 66;
		
	if ( opts.use_public && opts.use_private ) {
		rc = opts.force ? put_kp(opts.name, &kp   ) : set_kp(opts.name, &kp   );
	} else if ( opts.use_public ) {
		rc = opts.force ? put_pk(opts.name, &kp.pk) : set_pk(opts.name, &kp.pk);
	} else if ( opts.use_private ) {
		rc = opts.force ? put_sk(opts.name, &kp.sk) : set_sk(opts.name, &kp.sk);
	}
	
	switch ( rc ) {
		case SK_STORED:
		case PK_STORED:
		case KP_STORED:
			break;

		case DB_LOCKED:
			fprintf(stderr, "Failed to import key. The database is locked.\n");
			return 75;
			break;

		case DB_BUSY:
			fprintf(stderr, "Failed to import key. The database is busy.\n");
			return 75;
			break;

		case SK_OVERWRITE_FAILED:
			fprintf(stderr, "Failed to add new private key named \"%s\" to database. Their is an other private key named \"%s\" in the database.\n", opts.name, opts.name);
			return 65;
			break;
			
		case PK_OVERWRITE_FAILED:
			fprintf(stderr, "Failed to add new public key named \"%s\" to database. Their is an other public key named \"%s\" in the database.\n", opts.name, opts.name);
			return 65;
			break;
		
		default:
			fprintf(stderr, "Failed to add key pair to database (rc = %i).\n", rc);
			return 70;
			break;
	}
	
	return 0;
}


static int encrypt() {
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
	memcpy(k, &hdr.hdr + NONCE_LENGTH + MAC_LENGTH, sizeof(k));
	
	if ( enc_hdr(&hdr, &pk, &sk) ) {
    	fprintf(stderr, "I'm to dumb to use crypto_box().\n");
		return 70;
	}

	if ( fwrite(&hdr.hdr, sizeof(hdr.hdr), 1, stdout) != 1 || ferror(stdout) ) {
    	fprintf(stderr, "Failed to encrypt message from \"%s\" to \"%s\". Write to standard output failed.\n", opts.source, opts.target);
		return 74;
	}
		
	// if ( dec_hdr(&hdr, &pk, &sk) ) {
    // 	return 70;
	// }

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

static int decrypt() {
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
	memcpy(k, &hdr.hdr + NONCE_LENGTH + MAC_LENGTH, sizeof(k));
	
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
		
		if ( fwrite(m + crypto_secretbox_ZEROBYTES, j - MAC_LENGTH, 1, stdout) != 1 || ferror(stdout) ) {
        	fprintf(stderr, "Failed to decrypt message from \"%s\" to \"%s\". Write to standard output failed.\n", opts.source, opts.target);
			return 74;
		}

	}
	
	return 0;
}

static int delete_key() {
	enum rc rc = NOT_DELETED;
	
	if ( opts.use_public && opts.use_private ) {
		rc = del_kp(opts.name, opts.force);
	} else if ( opts.use_public ) {
		rc = del_pk(opts.name, opts.force);
	} else if ( opts.use_private ) {
		rc = del_sk(opts.name, opts.force);
	}
	
	switch ( rc ) {
    	case KP_DELETED:
		case PK_DELETED:
		case SK_DELETED:
		case NOT_DELETED:
			break;

		case DB_LOCKED:
			fprintf(stderr, "Failed to delete key material. The database is locked.\n");
			return 75;
			break;

		case DB_BUSY:
			fprintf(stderr, "Failed to delete key material. The database is busy.\n");
			return 75;
			break;

		default:
			fprintf(stderr, "Failed to delete key material (rc = %i).\n", rc);
			return 70;
			break;
	}

	if ( !opts.force ) {
		if ( rc == NOT_DELETED && !(opts.use_public ^ opts.use_private) ) {
			fprintf(stderr, "Failed to delete key pair named \"%s\" from the database because their is no such key in the database.\n", opts.name);
			return 1;
		}

		if ( !(rc & PK_DELETED) && opts.use_public ) {
        	fprintf(stderr, "Failed to delete public key named \"%s\" from the database because their is no such public key in the database.\n", opts.name);
			return 1;
		}

		if ( !(rc & SK_DELETED) && opts.use_private ) {
        	fprintf(stderr, "Failed do delete private key named \"%s\" from the database because their is no such private key in the database.\n", opts.name);
			return 1;
		}
	}       
	
	return 0;
}

static enum rc list_callback(enum rc rc, const unsigned char *name, const struct kp *kp) {
	struct hex_kp hex;
	bool p = opts.use_public  && (rc & PK_FOUND);
	bool s = opts.use_private && (rc & SK_FOUND);
	
	if ( p && s ) {
		kp_to_hex(&hex, kp);
		printf("%s\t%s\t%s\n", name, hex.hex_pk.hex_pk, hex.hex_sk.hex_sk);
	} else if ( p ) {
		char sk[2*crypto_box_SECRETKEYBYTES+sizeof('\0')];
    	pk_to_hex(&hex.hex_pk, &kp->pk);
		memset(sk, '_', sizeof(sk) - sizeof('\0'));
		sk[2*crypto_box_SECRETKEYBYTES] = '\0';
		printf("%s\t%s\t%s\n", name, hex.hex_pk.hex_pk, sk);
	} else if ( s ) {
		char pk[2*crypto_box_PUBLICKEYBYTES+sizeof('\0')];
    	sk_to_hex(&hex.hex_sk, &kp->sk);
		memset(pk, '_', sizeof(pk) - sizeof('\0'));
		pk[2*crypto_box_PUBLICKEYBYTES] = '\0';
		printf("%s\t%s\t%s\n", name, pk, hex.hex_sk.hex_sk);
	} else {
    	printf("%s\n", name);
	}
	return OK;
}
static int list_keys() {
	enum rc rc;
	switch ( (rc = list_kp(list_callback)) ) {
		case OK:
			break;

    	case DB_LOCKED:
			fprintf(stderr, "Failed to iterate over key material. The database is locked.\n");
			return 75;
			break;

		case DB_BUSY:
			fprintf(stderr, "Failed to iterate over key material. The database is busy.\n");
			return 75;
			break;

		default:
			fprintf(stderr, "Failed to iterate over key material (rc = %i)\n", rc);
			return 70;
			break;
	}
	return 0;
}
