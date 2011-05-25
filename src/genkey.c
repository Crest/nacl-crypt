#define _POSIX_C_SOURCE 200809
#include <stdio.h>
#include <stdlib.h>

#include <crypto_box.h>

int main(int argc, char **argv) {
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];

	crypto_box_keypair(pk, sk);
	
	if ( printf("P:") < 0 ) return 1;
	for ( int i = 0; i < crypto_box_PUBLICKEYBYTES; i++ )
		if ( printf("%02X", pk[i]) < 0 ) return 1;
	
	if ( printf("\nS:") < 0 ) return 1;
	for ( int i = 0; i < crypto_box_SECRETKEYBYTES; i++ )
		if ( printf("%02X", sk[i]) < 0 ) return 1;
	return printf("\n") < 0;
}
