#include "types.h"
#include "db.h"
#include "opts.h"

#include <crypto_box.h>

#include <stdio.h>

static void generate_key();

int main(int argc, char **argv) {
	parse_args(&argc, &argv);
	switch ( opts.op ) {
        	case GENERATE_KEY:
			printf("Generating keypair named \"%s\".\n", opts.name);
			generate_key();
			break;
	}
	close_db();
}

static void generate_key() {
	struct kp kp;
	crypto_box_keypair(kp.pk.pk, kp.sk.sk);
	printf("rc = %i\n", set_kp(opts.name, &kp));
}
