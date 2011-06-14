#include "db.h"
#include "ops.h"
#include "opts.h"
#include "types.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define MAX_LINE 1024

static const char keypair_generated[] = "Generated keypair named \"%s\".\n";
static const char keypair_sk_failed[] = "Failed to add new private key named \"%s\" to database. Their is an other private key named \"%s\" in the database.\n";
static const char keypair_pk_failed[] = "Failed to add new public key named \"%s\" to database. Their is an other public key named \"%s\" in the database.\n";
static const char keypair_locked[]    = "Failed to add new key pair. The database is locked.\n";
static const char keypair_busy[]      = "Failed to add new key pair. The database is busy.\n";
static const char keypair_failed[]    = "Failed to add key pair to database (rc = %i).\n";

static const char export_locked[]       = "Failed to retrieve key material. The database is locked.\n";
static const char export_busy[]         = "Failed to retrieve key material. The database is busy.\n";
static const char export_kp_not_found[] = "Their is no key named \"%s\" stored in the database.\n";
static const char export_pk_not_found[] = "Their is no public key named \"%s\" stored in the database.\n";
static const char export_sk_not_found[] = "Their is no private key named \"%s\" stored in the database.\n";
static const char export_failed[]       = "Failed to retrieve key material from database (rc = %i).\n";

static const char import_locked[]       = "Failed to import key. The database is locked.\n";
static const char import_busy[]         = "Failed to import key. The database is busy.\n";
static const char import_sk_overwrite[] = "Failed to add new private key named \"%s\" to database. Their is an other private key named \"%s\" in the database.\n";
static const char import_pk_overwrite[] = "Failed to add new public key named \"%s\" to database. Their is an other public key named \"%s\" in the database.\n";
static const char import_failed[]       = "Failed to add key pair to database (rc = %i).\n";

static size_t   hex_chars(const char *restrict s);
static uint8_t  to_hex(uint8_t n);
static void     pk_to_hex(struct hex_pk *hex, const struct pk *bin);
static void     sk_to_hex(struct hex_sk *hex, const struct sk *bin);
static char     parse_line(const char **data);
static uint8_t  dehex_half(const char *restrict str);
static uint16_t dehex(const char *restrict str);
static int      dehex_pk(struct pk *pk, const char *line);
static int      dehex_sk(struct sk *sk, const char *line);
static enum rc  list_callback(enum rc rc, const unsigned char *name, const struct kp *kp);

static size_t hex_chars(const char *restrict s) {
	size_t n = 0;
	while ( isxdigit(*s++) ) n++;
	return n;
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

int generate_key() {
	struct kp kp;
	enum rc   rc;
	crypto_box_keypair(kp.pk.pk, kp.sk.sk);
	
	switch ( rc = opts.force ? put_kp(opts.name, &kp) : set_kp(opts.name, &kp) ) {
		case KP_STORED:
			printf(keypair_generated, opts.name);
			break;
		
		case SK_OVERWRITE_FAILED:
			fprintf(stderr, keypair_sk_failed, opts.name, opts.name);
			return 65;
			break;
			
		case PK_OVERWRITE_FAILED:
			fprintf(stderr, keypair_pk_failed, opts.name, opts.name);
			return 65;
			break;

		case DB_LOCKED:
			fprintf(stderr, keypair_locked);
			return 75;
			break;

		case DB_BUSY:
			fprintf(stderr, keypair_busy);
			return 75;
			break;
		
		default:
			fprintf(stderr, keypair_failed, rc);
			return 70;
			break;
	}
	
	return 0;	
} 

int import_key() {
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
			fprintf(stderr, import_locked);
			return 75;
			break;

		case DB_BUSY:
			fprintf(stderr, import_busy);
			return 75;
			break;

		case SK_OVERWRITE_FAILED:
			fprintf(stderr, import_sk_overwrite, opts.name, opts.name);
			return 65;
			break;
			
		case PK_OVERWRITE_FAILED:
			fprintf(stderr, import_pk_overwrite, opts.name, opts.name);
			return 65;
			break;
		
		default:
			fprintf(stderr, import_failed, rc);
			return 70;
			break;
	}
	
	return 0;
}

int export_key() {
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
			fprintf(stderr, export_locked);
			return 75;
			break;

		case DB_BUSY:
			fprintf(stderr, export_busy);
			return 75;
			break;
			
		default:
			fprintf(stderr, export_failed, rc);
			return 70;
			break;
	}

	if ( rc == NOT_FOUND && !(opts.use_public ^ opts.use_private) ) {
		fprintf(stderr, export_kp_not_found, opts.name);
		return 1;
	}

	if ( !(rc & PK_FOUND) && opts.use_public ) {
		fprintf(stderr, export_pk_not_found, opts.name);
		return 1;
	}

	if ( !(rc & SK_FOUND) && opts.use_private ) {
		fprintf(stderr, export_sk_not_found, opts.name);
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

int delete_key() {
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

int list_keys() {
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
