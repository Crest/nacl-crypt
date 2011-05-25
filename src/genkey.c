#define _POSIX_C_SOURCE 200809

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

#include <crypto_box.h>

static const char env_name[] = "NACL_CRYPT_DB";
static const char create_keys_table[]  = "CREATE TABLE IF NOT EXISTS Keys (\n"
"    Name      PRIMARY KEY ASC,\n"
"    PublicKey BLOB,\n"
"    SecretKey BLOB,\n"
"    UNIQUE ( Name ) ON CONFLICT ROLLBACK\n"
");";
static const char insert_into_keys[] = "INSERT INTO Keys ( Name, PublicKey, SecretKey ) VALUES ( ?, ?, ? );";

static const char *db_path = NULL;
static sqlite3    *db      = NULL;
static const char *name    = NULL;

static unsigned char pk[crypto_box_PUBLICKEYBYTES];
static unsigned char sk[crypto_box_SECRETKEYBYTES];

static void usage(int argc);
static void fail(const char *restrict msg);
static void fail_sqlite3(const char *restrict msg);
static void err_sqlite3(const char *restrict msg, const char *restrict err);
static void get_db_path(int argc, const char **argv);
static void get_name(int argc, const char **argv);
static void generate_keypair();
static void open_db();
static void close_db();
static void create_table();
static void duplicate_name();
static void insert_keypair();

static void create_table() {
	char *err_msg = NULL;
	
	if ( sqlite3_exec(db, create_keys_table, NULL, NULL, &err_msg) != SQLITE_OK )
		err_sqlite3("Failed to create keys table", err_msg);
}

static void duplicate_name() {
	fprintf(stderr, "Names must be unique. The \"%s\" is already used.\n", name);
	exit(65);
}

static void insert_keypair() {
	sqlite3_stmt *insert;
	if ( sqlite3_prepare_v2(db, insert_into_keys, strlen(insert_into_keys)+sizeof('\0'), &insert, NULL) != SQLITE_OK )
		sqlite3_finalize(insert), fail_sqlite3("Failed to prepare insert statement");
	if ( sqlite3_bind_text(insert, 1, name, strlen(name)+sizeof('\0'), SQLITE_STATIC) != SQLITE_OK )
		sqlite3_finalize(insert), fail_sqlite3("Failed to bind first parameter to insert statement");
	if ( sqlite3_bind_blob(insert, 2, pk  , crypto_box_PUBLICKEYBYTES, SQLITE_STATIC) != SQLITE_OK )
		sqlite3_finalize(insert), fail_sqlite3("Failed to bind second parameter to insert statement");
	if ( sqlite3_bind_blob(insert, 3, sk  , crypto_box_SECRETKEYBYTES, SQLITE_STATIC) != SQLITE_OK )
		sqlite3_finalize(insert), fail_sqlite3("Failed to bind third parameter to insert statement");
	
        switch ( sqlite3_step(insert) ) {
		case SQLITE_DONE:
			sqlite3_finalize(insert);
			break;
		
		case SQLITE_CONSTRAINT:
			sqlite3_finalize(insert);
			duplicate_name();
			break;

		default:
			sqlite3_finalize(insert);
			fail_sqlite3("Failed to insert key pair into database");
			break;
	}
}

int main(int argc, const char **argv) {
	
	usage(argc);
	get_db_path(argc, argv);
	get_name(argc, argv);
	open_db();
		create_table();
		generate_keypair();
		insert_keypair();
    	close_db();
	return 0;
}

void usage(int argc) {
	if ( argc == 2 || argc == 3 ) return; 
	
	fprintf(stderr, "usage: genkey [db] name\n");
	exit(64);
}

void fail(const char *restrict msg) {
	if ( errno )
		perror(msg);
	else
		fprintf(stderr, "%s.\n", msg);
	exit(70);
}

static void fail_sqlite3(const char *restrict msg) {
	fprintf(stderr, "%s: \"%s\".\n", msg, sqlite3_errmsg(db));
	sqlite3_close(db);
	exit(65);
}

static void err_sqlite3(const char *restrict msg, const char *restrict err) {
	fprintf(stderr, "%s: %s\n", msg, err);
	sqlite3_free((void*) err);
	exit(74);
}

void get_db_path(int argc, const char **argv) {
	if ( argc == 3 ) {
		db_path = argv[1];
		return;
	}
	db_path = getenv(env_name);
	switch ( errno ) {
		case EINVAL:
			fail("Called getenv() with invalid parameter");
			break;

		case ENOMEM:
			fail("Call to getenv() failed because lack of memory");
			break;

                case EFAULT:
			fail("The gov^H^H^Henviroment is corrupted. Go install new regime");
 			break;

 		default:
			break;
	}
	if ( db_path == NULL )
		usage(-1);
}

void get_name(int argc, const char **argv) {
	switch ( argc ) {
		case 2:
			name = argv[1];
			break;

		case 3:
			name = argv[2];
			break;

		default:
			usage(-1);
	}
}

static void generate_keypair() {
	crypto_box_keypair(pk, sk);
}

static void open_db() {
	if ( sqlite3_open(db_path, &db) )
		fail_sqlite3("Can't open database");
}

static void close_db() {
	if ( sqlite3_close(db) != SQLITE_OK )
		fail_sqlite3("Can't close database");
}
