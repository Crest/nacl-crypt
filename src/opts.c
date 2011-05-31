#include "opts.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct opts opts = {
	.op = NOP,
	.target      = NULL,
	.source      = NULL,
	.name        = NULL,
	.force       = false,
	.use_public  = false,
	.use_private = false
};

static void usage(int argc, char **argv);

void parse_args(int *argc, char ***argv) {
	int ch;
	while ( (ch = getopt(*argc, *argv, "fpPedg:x:i:r:s:t:")) != -1 ) {
        	switch ( ch ) {
                	case 'f':
				opts.force = true;
				break;

			case 'p':
				opts.use_public = true;
				break;

			case 'P':
				opts.use_private = true;
				break;

			case 'e':
				opts.op = opts.op == NOP ? ENCRYPT : MULTIPLE_OPS;
				break;

			case 'd':
				opts.op = opts.op == NOP ? DECRYPT : MULTIPLE_OPS;
				break;
			
			case 'g':
				opts.op = opts.op == NOP ? GENERATE_KEY : MULTIPLE_OPS;
				opts.name = opts.name ? opts.name : optarg;
				break;
			
			case 'x':
				opts.op = opts.op == NOP ? EXPORT_KEY : MULTIPLE_OPS;
				opts.name = opts.name ? opts.name : optarg;
				break;

			case 'i':
				opts.op = opts.op == NOP ? IMPORT_KEY : MULTIPLE_OPS;
				opts.name = opts.name ? opts.name : optarg;
				break;
			
			case 'r':
				opts.op = opts.op == NOP ? DELETE_KEY : MULTIPLE_OPS;
				opts.name = opts.name ? opts.name : optarg;
				break;
			
			case 's':
				opts.source = opts.source ? opts.source : optarg;
				break;
			
			case 't':
				opts.target = opts.target ? opts.target : optarg;
				break;
			
			default:
				usage(*argc, *argv);
		}
	}

	
	switch ( opts.op ) {
                case ENCRYPT:
		case DECRYPT:
			if ( opts.force || opts.use_public || opts.use_private || opts.source == NULL || opts.target == NULL || opts.name != NULL )
				usage(*argc, *argv);
			break;
			
		case GENERATE_KEY:
			if ( opts.use_public || opts.use_private || opts.source != NULL || opts.target != NULL || opts.name == NULL )
				usage(*argc, *argv);
			break;

		case EXPORT_KEY:
			if ( opts.force || opts.source != NULL || opts.target != NULL || opts.name == NULL )
				usage(*argc, *argv);
			break;
		
		case IMPORT_KEY:
		case DELETE_KEY:
			if ( opts.name == NULL || opts.target != NULL || opts.source != NULL )
				usage(*argc, *argv);
			break;

		default:
			usage(*argc, *argv);
	}

	if ( opts.use_public == false && opts.use_private == false )
		opts.use_public = true;

	*argc -= optind;
	*argv += optind;
}

static void usage(int argc, char **argv) {
	const char *argv0 = argc == 0 ? "nenc" : argv[0]; 
	fprintf(stderr,
		"usage: %s [-f] -f <name>\n"
		"       %s [-p] [-P] -x <name>\n"
		"       %s [-f] [-p] [-P] -i <name>\n"
		"       %s [-f] [-p] [-P] -r <name>\n"
		"       %s -e -s <name> -t <name>\n"
		"       %s -d -t <name> -s <name>\n",
		argv0, argv0, argv0, argv0, argv0, argv0
	);
	exit(64);
}
