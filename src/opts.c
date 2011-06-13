#include "opts.h"
#include "db.h"

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

char *parse_args(int *argc, char ***argv) {
	int   ch;
	char *env;
	while ( (ch = getopt(*argc, *argv, "fpPedlg:x:i:r:s:t:")) != -1 ) {
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
				if ( opts.op != NOP )
					usage(*argc, *argv);
				opts.op = ENCRYPT;
				break;

			case 'd':
				if ( opts.op != NOP )
					usage(*argc, *argv);
				opts.op = DECRYPT;
				break;

			case 'l':
				if ( opts.op != NOP )
					usage(*argc, *argv);
				opts.op = LIST_KEYS;
				break;
			
			case 'g':
				if ( opts.op != NOP || opts.name != NULL )
					usage(*argc, *argv);
				opts.op   = GENERATE_KEY;
				opts.name = optarg;
				break;
			
			case 'x':
				if ( opts.op != NOP || opts.name != NULL )
					usage(*argc, *argv);
				opts.op   = EXPORT_KEY;
				opts.name = optarg;
				break;

			case 'i':
				if ( opts.op != NOP || opts.name != NULL )
					usage(*argc, *argv);
				opts.op   = IMPORT_KEY;
				opts.name = optarg;
				break;
			
			case 'r':
				if ( opts.op != NOP || opts.name != NULL )
					usage(*argc, *argv);
				opts.op   = DELETE_KEY;
				opts.name = optarg;
				break;
			
			case 's':
				if ( opts.source != NULL )
					usage(*argc, *argv);
				opts.source = optarg;
				break;
			
			case 't':
				if ( opts.target != NULL )
					usage(*argc, *argv);
				opts.target = optarg;
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

		case LIST_KEYS:
			if ( opts.force || opts.name || opts.target || opts.source )
				usage(*argc, *argv);
			break;

		default:
			usage(*argc, *argv);
	}

	if ( opts.op != LIST_KEYS && opts.use_public == false && opts.use_private == false )
		opts.use_public = true;

	env = getenv("NACLCRYPT_DB");

	int left_args = *argc - optind;
	if ( (!env && left_args != 1) || (env && left_args != 0 && left_args != 1 ) )
		usage(*argc, *argv);
	
	*argc -= optind;
	*argv += optind;
	
	return *argc == 1 ? *argv[0] : env;
}

static void usage(int argc, char **argv) {
	const char *argv0 = argc == 0 ? "nenc" : argv[0]; 
	fprintf(stderr,
		"usage: %s [-f] -g <name> <db>\n"
		"       %s [-p] [-P] -x <name> <db>\n"
		"       %s [-f] [-p] [-P] -i <name> <db>\n"
		"       %s [-f] [-p] [-P] -r <name> <db>\n"
		"       %s -e -s <name> -t <name> <db>\n"
		"       %s -d -t <name> -s <name> <db>\n"
		"       %s [-p] [-P] -l <db>\n"
		"	<db> can be replaced by NACLCRYPT_DB=<db>\n",
		argv0, argv0, argv0, argv0, argv0, argv0, argv0
	);
	exit(64);
}
