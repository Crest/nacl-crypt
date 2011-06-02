#ifndef _NACL_CRYPT_TYPES_H
#define _NACL_CRYPT_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <crypto_box.h>
#include <crypto_secretbox.h>

typedef struct pk {
	uint8_t pk[crypto_box_PUBLICKEYBYTES];
} pk_t;

typedef struct sk {
	uint8_t sk[crypto_box_SECRETKEYBYTES];
} sk_t;

typedef struct kp {
	struct pk pk;
	struct sk sk;
} kp_t;

#define NONCE_LENGTH (crypto_box_NONCEBYTES)
#define MAC_LENGTH   (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)
#define KEY_LENGTH   (crypto_secretbox_KEYBYTES)
typedef struct hdr {
	uint8_t hdr[NONCE_LENGTH + MAC_LENGTH + KEY_LENGTH];
} hdr_t;

typedef struct hex_pk {
	char hex_pk[2 * crypto_box_PUBLICKEYBYTES + sizeof('\0')];
} hex_pk_t;

typedef struct hex_sk {
	char hex_sk[2 * crypto_box_SECRETKEYBYTES + sizeof('\0')];
} hex_sk_t;

typedef struct hex_kp {
	struct hex_pk hex_pk;
	struct hex_sk hex_sk;
} hex_kp_t;

typedef enum op {
	NOP = 0,
	GENERATE_KEY,
	EXPORT_KEY,
	IMPORT_KEY,
	DELETE_KEY,
	LIST_KEYS,
	ENCRYPT,
	DECRYPT,
} op_t;

typedef struct opts {
	enum op     op;
	const char *target;
	const char *source;
	const char *name;
	unsigned    force       : 1;
	unsigned    use_public  : 1;
	unsigned    use_private : 1;
} opts_t;

typedef enum rc {
	NOT_FOUND  = 0 << 0,
	PK_FOUND   = 1 << 0,
	SK_FOUND   = 1 << 1,
	KP_FOUND   = PK_FOUND | SK_FOUND,
	
	NOT_STORED  = NOT_FOUND,
	PK_STORED   = PK_FOUND,
	SK_STORED   = SK_FOUND,
	KP_STORED   = PK_STORED | SK_FOUND,
	
	NOT_DELETED = NOT_FOUND,
	PK_DELETED  = PK_FOUND,
	SK_DELETED  = SK_FOUND,
	KP_DELETED  = PK_DELETED | SK_DELETED,
	
	DB_LOCKED   = 4,
	DB_BUSY     = 5,
	
	SK_OVERWRITE_FAILED = 6,
	PK_OVERWRITE_FAILED = 7,
	OK          = 8
} rc_t;

#endif /* _NACL_CRYPT_TYPES_H */
