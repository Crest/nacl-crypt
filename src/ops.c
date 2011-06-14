#include "types.h"
#include "db.h"
#include "ops.h"
#include "opts.h"

#include <stdio.h>
#include <stdlib.h>

int dispatch() {
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
