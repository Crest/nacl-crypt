#include "db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <sqlite3.h>


const char     *db_path = NULL;
static sqlite3 *db      = NULL;

static const char schema[] =
	"CREATE TABLE IF NOT EXISTS Names (\n"
	"    Id   INTEGER PRIMARY KEY ASC AUTOINCREMENT,\n"
	"    Name STRING NOT NULL UNIQUE\n"
	");\n"

	"CREATE TABLE IF NOT EXISTS PublicKeys (\n"
	"    Id        INTEGER PRIMARY KEY ASC AUTOINCREMENT,\n"
	"    NameId    INTEGER NOT NULL UNIQUE REFERENCES Names(Id) ON DELETE CASCADE ON UPDATE CASCADE,\n"
	"    PublicKey BLOB NOT NULL\n"
	");\n"

	"CREATE TABLE IF NOT EXISTS PrivateKeys (\n"
	"    Id         INTEGER PRIMARY KEY ASC AUTOINCREMENT,\n"
	"    NameId     INTEGER NOT NULL UNIQUE REFERENCES Names(Id) ON DELETE CASCADE ON UPDATE CASCADE,\n"
	"    PrivateKey BLOB NOT NULL\n"
	");";

static const char select_pk[] =
	"SELECT PublicKeys.PublicKey FROM PublicKeys\n"
	"    INNER JOIN Names ON Names.Id = PublicKeys.NameId\n"
	"    WHERE Names.Name = ?;";

static const char select_sk[] =
	"SELECT PrivateKeys.PrivateKey FROM PrivateKeys\n"
	"    INNER JOIN Names ON Names.Id = PrivateKeys.NameId\n"
	"    WHERE Names.Name = ?;";

static const char select_kp[] =
	"SELECT PrivateKeys.PrivateKey, PublicKeys.PublicKey FROM Names\n"
	"    JOIN PrivateKeys ON PrivateKeys.NameId = Names.Id\n"
	"    JOIN PublicKeys  ON PublicKeys.NameId  = Names.Id\n"
	"    WHERE Names.Name = ?;";

static const char foreign_keys_on[] =
	"PRAGMA foreign_keys = ON;";

static const char schema_failed[]         = "Failed to define schema";
static const char open_failed[]           = "Failed to open database";
static const char close_failed[]          = "Failed to close database";
static const char prepare_select_failed[] = "Failed to prepare select statement for key retrieval";
static const char bind_select_failed[]    = "Failed to bind first parameter to select statement for key retrieval";
static const char pk_len_failed[]         = "Private key read form database has wrong length";
static const char sk_len_failed[]         = "Public key read from database has wrong length";
static const char step_select_failed[]    = "Failed to step through rows returned by select statement for key retrieval";
static const char foreign_keys_failed[]   = "Failed to enable foreign key support";

static enum rc get(const char *restrict name, const char *restrict query, int query_len, struct sk *restrict sk, struct pk *restrict pk);

void define_schema() {
	char *err = NULL;
	if ( sqlite3_exec(db, schema, NULL, NULL, &err) != SQLITE_OK ) {
		fprintf(stderr, "%s: %s\n", schema_failed, err);
		sqlite3_free((void *) err);
		sqlite3_close(db);
		exit(EX_CONFIG);
	}
}

void open_db(const char *restrict db_path) {
	char *err = NULL;
	if ( sqlite3_open(db_path, &db) != SQLITE_OK ) {
		fprintf(stderr, "%s: %s\n", open_failed, sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(EX_NOINPUT);
	}
	if ( sqlite3_exec(db, foreign_keys_on, NULL, NULL, &err) != SQLITE_OK ) {
		fprintf(stderr, "%s: %s\n", foreign_keys_failed, err);
		sqlite3_free((void *) err);
		sqlite3_close(db);
		exit(EX_SOFTWARE);
	}
}

void close_db() {
	if ( sqlite3_close(db) != SQLITE_OK ) {
		fprintf(stderr, "%s: %s\n", close_failed, sqlite3_errmsg(db));
		exit(EX_SOFTWARE);
	}
}

enum rc get_pk(const char *restrict name, struct pk *pk) {
	return get(name, select_pk, strlen(select_pk) + sizeof('\0'), NULL, pk);
}

enum rc get_sk(const char *restrict name, struct sk *sk) {
	return get(name, select_sk, strlen(select_sk) + sizeof('\0'), sk, NULL);
}

enum rc get_kp(const char *restrict name, struct kp *kp) {
	return get(name, select_kp, strlen(select_kp) + sizeof('\0'), &kp->sk, &kp->pk);
}

static void explode(sqlite3_stmt *stmt, const char *restrict msg) {
	sqlite3_finalize(stmt);
	fprintf(stderr, "%s: %s\n", msg, sqlite3_errmsg(db));
	sqlite3_close(db);
	exit(EX_SOFTWARE);
}

static void explode2(sqlite3_stmt **stmts, const char *restrict msg) {
	while (*stmts) 
		sqlite3_finalize(*stmts++);
	explode(s2, msg);
}

static enum rc get(const char *restrict name, const char *restrict query, int query_len, struct sk *restrict sk, struct pk *restrict pk) {
	sqlite3_stmt *stmt = NULL;

        if ( sqlite3_prepare_v2(db, query, query_len, &stmt, NULL) != SQLITE_OK )
		explode(stmt, prepare_select_failed);

	if ( sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT) != SQLITE_OK )
		explode(stmt, bind_select_failed);
	
	switch ( sqlite3_step(stmt) ) {
        	case SQLITE_DONE:
			sqlite3_finalize(stmt);
			if ( sk ) memset(sk->sk, 0, crypto_box_SECRETKEYBYTES);
			if ( pk ) memset(pk->pk, 0, crypto_box_PUBLICKEYBYTES);
			return false;
			break;
		
		case SQLITE_ROW: {
			const void *blob0 = sqlite3_column_blob(stmt, 0);
			const int   len0  = sqlite3_column_bytes(stmt, 0);
			if ( pk && sk ) {
				const void *blob1 = sqlite3_column_blob(stmt, 1);
				const int   len1  = sqlite3_column_bytes(stmt, 1);
				if ( len0 != crypto_box_SECRETKEYBYTES )
					explode(stmt, sk_len_failed);
				if ( len1 != crypto_box_PUBLICKEYBYTES )
					explode(stmt, pk_len_failed);
				memcpy(sk->sk, blob0, crypto_box_SECRETKEYBYTES);
				memcpy(pk->pk, blob1, crypto_box_PUBLICKEYBYTES);
			} else if ( sk ) {
                        	if ( len0 != crypto_box_SECRETKEYBYTES )
					explode(stmt, sk_len_failed);
				memcpy(sk->sk, blob0, crypto_box_SECRETKEYBYTES);
			} else {
				if ( len0 != crypto_box_PUBLICKEYBYTES )
					explode(stmt, pk_len_failed);
				memcpy(pk->pk, blob0, crypto_box_PUBLICKEYBYTES);
			}
			sqlite3_finalize(stmt);
			return true;
			break;
		}

		default:
			explode(stmt, step_select_failed);
			return false;
			break;
	}
}

enum put_stmt {
	// Kepp sorted by order of allocation
	BEGIN           = 0,
	COMMIT          = 1,
        ROLLBACK        = 2,
	SELECT_ID       = 3,
	INSERT_NAME     = 4,
	INSERT_PK       = 5,
	INSERT_SK       = 6,
	STATEMENT_COUNT = 7
};

static enum rc put(const char *restrict name, bool replace, const struct sk *restrict sk, const struct pk *restrict pk) {
	sqlite3_stmt *s[STATEMENT_COUNT];
	memset(s, 0, sizeof(s));

	const char *restrict queries[] = {
		begin_exclusive, commit_transaction, rollback_transaction,
		select_id, insert_name, insert_pk, insert_sk
	};
	const char *restrict msgs[] = {
		prepare_begin_failed, prepare_commit_failed, prepare_rollback_failed,
		prepare_prepare_select_id_failed, prepare_insert_name_failed, prepare_insert_pk_failed, prepare_insert_sk_failed
	};

	for ( int i = 0; i < STATEMENT_COUNT; i++ )
		if ( sqlite3_prepare_v2(db, queries[i], query_lengths[i], &s[i], NULL) != SQLITE_OK )
			explode2(s, msgs[i]);
	
}
