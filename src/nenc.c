#include "types.h"
#include "db.h"
#include "ops.h"
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

int main(int argc, char **argv) {
	char *db_path   = parse_args(&argc, &argv);
	int   exit_code = 0;
	
	if ( (exit_code = start_db(db_path)) ) goto quit;
	
	exit_code = dispatch();
	
quit:
	close_db();
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




