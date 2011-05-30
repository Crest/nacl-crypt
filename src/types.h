#ifndef _NACL_CRYPT_TYPES_H
#define _NACL_CRYPT_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <crypto_box.h>

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

typedef enum rc {
	NOT_FOUND  = 0 << 0,
	PK_FOUND   = 1 << 0,
	SK_FOUND   = 1 << 1,
	KP_FOUND   = PK_FOUND | SK_FOUND,
	NOT_STORED = NOT_FOUND,
	PK_STORED  = PK_FOUND,
	SK_STORED  = SK_FOUND,
	KP_STORED  = PK_STORED | SK_FOUND,
	DB_LOCKED  = 4,
	DB_BUSY    = 5,
	SK_OVERWRITE_FAILED = 6,
	PK_OVERWRITE_FAILED = 7
} rc_t;

#endif /* _NACL_CRYPT_TYPES_H */
