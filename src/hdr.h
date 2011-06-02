#ifndef _NACL_CRYPT_HDR_H
#define _NACL_CRYPT_HDR_H

#include "types.h"

void init_hdr(struct hdr *restrict hdr);
int  enc_hdr(struct hdr *restrict hdr, const struct pk *restrict pk, const struct sk *restrict sk);
int  dec_hdr(struct hdr *restrict hdr, const struct pk *restrict pk, const struct sk *restrict sk);

#endif /* _NACL_CRYPT_HDR_H */
