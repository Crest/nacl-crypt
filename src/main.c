#include <stdio.h>
#include <stdlib.h>

#include <crypto_box.h>

void usage() {

	exit(64);
}
int main(int argc, char **argv) {
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];

	crypto_box_keypair(pk, sk);
	
	return 1;
}
