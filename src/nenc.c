#include "types.h"
#include "db.h"
#include "opts.h"

#include <crypto_box.h>

#include <stdio.h>
#include <stdlib.h>

static int start_db();
static int dispatch();
static void generate_key();
static void export_key();
static void import_key();

int main(int argc, char **argv) {
	char *db_path   = parse_args(&argc, &argv);
	int   exit_code = 0;
	
	if ( exit_code = start_db(db_path) ) goto quit;
	
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
		
		default:
			fprintf(stderr, "Unsupported operation.\n");
			close_db();
			exit(2);
	}
}

static int start_db(char *db_path) {
	enum rc rc;
	switch ( rc = open_db(db_path) ) {
        	case OK:
			return 0;

		case DB_LOCKED:
			fprintf("Failed to open database. It's locked.");
			return 75;
			break;

		case DB_BUSY:
			fprintf("Failed to open database. It's busy.");
			return 75;
			break;

		default:
			fprintf("Failed to open database (rc = %i).\n", rc);
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
static void generate_key() {
	struct kp kp;
	enum rc   rc;
	crypto_box_keypair(kp.pk.pk, kp.sk.sk);
	switch ( rc = opts.force ? put_kp(opts.name, &kp) : set_kp(opts.name, &kp) ) {
        	case KP_STORED:
			printf("Generated keypair named \"%s\".\n", opts.name);
			break;
		case SK_OVERWRITE_FAILED:
			fprintf(stderr, "Failed to add new private key named \"%s\" to database. Their is an other private key named \"%s\" in the database.\n", opts.name, opts.name);
			exit(65);
			break;
			
		case PK_OVERWRITE_FAILED:
			fprintf(stderr, "Failed to add new public key named \"%s\" to database. Their is an other public key named \"%s\" in the database.\n", opts.name, opts.name);
			exit(65);
			break;
		
		default:
			fprintf(stderr, "Failed to add key pair to database (rc = %i).\n", rc);
                        exit(70);
			break;
	}
	
}

static void export_key() {
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
		
                default:
			fprintf(stderr, "Failed to retrieve key material from database (rc = %i).\n", rc);
			exit(70);
			break;
	}

	if ( rc == NOT_FOUND ) {
        	fprintf(stderr, "Their is no key named \"%s\" stored in the database.\n", opts.name);
		exit(1);
	}

	if ( !(rc & PK_FOUND) && opts.use_public ) {
		fprintf(stderr, "Their is no public key named \"%s\" stored in the database.\n", opts.name);
		exit(1);
	}

	if ( !(rc & SK_FOUND) && opts.use_private ) {
		fprintf(stderr, "Their is no private key named \"%s\" stored in the database.\n", opts.name);
		exit(1);
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
}

static void import_key() {

}
