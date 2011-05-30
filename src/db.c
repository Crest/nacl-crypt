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

static const char begin_exclusive[] =
	"BEGIN EXCLUSIVE TRANSACTION;";

static const char commit_transaction[] =
	"COMMIT TRANSACTION;";

static const char rollback_transaction[] =
	"ROLLBACK TRANSACTION;";

static const char select_id[] =
	"SELECT Names.Id FROM Names\n"
	"    WHERE Names.Name = ?;";

static const char insert_name[] =
	"INSERT INTO Names ( Id, Names )\n"
	"    VALUES ( NULL, ? );";

static const char insert_pk[] =
	"INSERT INTO PublicKeys ( Id, NameID, PublicKey )\n"
	"    VALUES ( NULL, ?, ? );";

static const char insert_sk[] =
	"INSERT INTO PrivateKeys ( Id, NameID, PrivateKey )\n"
	"    VALUES ( NULL, ?, ? );";

static const char update_pk[] =
	"UPDATE PrivateKeys SET ( PrivateKey = ? )\n"
	"    WHERE NamedId = ?;";

static const char update_sk[] =
	"UPDATE PublicKeys SET ( PublicKey = ? )\n"
	"    WHERE NamedId = ?;";

static const char schema_failed[]         = "Failed to define schema";
static const char open_failed[]           = "Failed to open database";
static const char close_failed[]          = "Failed to close database";
static const char prepare_select_failed[] = "Failed to prepare select statement for key retrieval";
static const char bind_select_failed[]    = "Failed to bind first parameter to select statement for key retrieval";
static const char pk_len_failed[]         = "Private key read form database has wrong length";
static const char sk_len_failed[]         = "Public key read from database has wrong length";
static const char step_select_failed[]    = "Failed to step through rows returned by select statement for key retrieval";
static const char foreign_keys_failed[]   = "Failed to enable foreign key support";

static const char prepare_begin_failed[]       = "Failed to prepare begin transaction statement";
static const char prepare_commit_failed[]      = "Failed to prepare commit transaction statement";
static const char prepare_rollback_failed[]    = "Failed to prepare rollback transaction statement";
static const char prepare_select_id_failed[]   = "Failed to prepare select statement for name id retrieval";
static const char prepare_insert_name_failed[] = "Failed to prepare insert statement to insert name";
static const char prepare_insert_pk_failed[]   = "Failed to prepare insert statement to insert public key";
static const char prepare_insert_sk_failed[]   = "Failed to prepare insert statement to insert private key";
static const char prepare_update_pk_failed[]   = "Failed to prepare update statement to change public key";
static const char prepare_update_sk_failed[]   = "Failed to prepare update statement to change private key";
static const char select_id_failed[]           = "Failed to select id by name";
static const char insert_name_failed[]         = "Failed to insert name";
static const char bind_name_id_failed[]        = "Failed to bind name id to insert";
static const char insert_sk_failed[]           = "Failed to insert private key";
static const char update_sk_failed[]           = "Failed to update private key";
static const char insert_pk_failed[]           = "Failed to insert public key";
static const char update_pk_failed[]           = "Failed to update public key";
static const char rollback_failed[]            = "Failed to rollback transaction";
static const char commit_failed[]              = "Failed to commit transaction";

static enum rc get(const char *restrict name, const char *restrict query, int query_len, struct sk *restrict sk, struct pk *restrict pk);
static enum rc put(const char *restrict name, bool replace, const struct sk *restrict sk, const struct pk *restrict pk);
static void explode(sqlite3_stmt *stmt, const char *restrict msg);
static void explode2(sqlite3_stmt **stmts, const char *restrict msg);
static void *memcpy_or_zero(void *restrict dst, const void *restrict src, size_t n);


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

enum rc set_pk(const char *restrict name, const struct pk *pk) {
	return put(name, false, NULL, pk); 
}

enum rc set_sk(const char *restrict name, const struct sk *sk) {
	return put(name, false, sk, NULL);
}

enum rc set_kp(const char *restrict name, const struct kp *kp) {
	return put(name, false, &kp->sk, &kp->pk);
}

enum rc put_pk(const char *restrict name, const struct pk *pk) {
	return put(name, true, NULL, pk);
}

enum rc put_sk(const char *restrict name, const struct sk *sk) {
	return put(name, true, sk, NULL);
}

enum rc put_kp(const char *restrict name, const struct kp *kp) {
	return put(name, true, &kp->sk, &kp->pk);
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
	fprintf(stderr, "%s: %s\n", msg, sqlite3_errmsg(db));
	sqlite3_close(db);
	exit(EX_SOFTWARE); 
}

static void *memcpy_or_zero(void *restrict dst, const void *restrict src, size_t n) {
	if ( src )
		return memcpy(dst, src, n);
	else
		return memset(dst, 0  , n), NULL;
}

static enum rc get(const char *restrict name, const char *restrict query, int query_len, struct sk *restrict sk, struct pk *restrict pk) {
	sqlite3_stmt *stmt  = NULL;
	enum rc       found = NOT_FOUND;

        if ( sqlite3_prepare_v2(db, query, query_len, &stmt, NULL) != SQLITE_OK )
		explode(stmt, prepare_select_failed);

	if ( sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT) != SQLITE_OK )
		explode(stmt, bind_select_failed);
	
	switch ( sqlite3_step(stmt) ) {
        	case SQLITE_DONE:
			sqlite3_finalize(stmt);
			if ( sk ) memset(sk->sk, 0, crypto_box_SECRETKEYBYTES);
			if ( pk ) memset(pk->pk, 0, crypto_box_PUBLICKEYBYTES);
			return found;
			break;
		
		case SQLITE_ROW: {
			const void *blob0 = sqlite3_column_blob(stmt, 0);
			const int   len0  = sqlite3_column_bytes(stmt, 0);
			
			if ( pk && sk ) {
				const void *blob1 = sqlite3_column_blob(stmt, 1);
				const int   len1  = sqlite3_column_bytes(stmt, 1);
		   		 
				if ( len0 != 0 && len0 != crypto_box_SECRETKEYBYTES )
					explode(stmt, sk_len_failed);
				if ( len1 != 0 && len1 != crypto_box_PUBLICKEYBYTES )
					explode(stmt, pk_len_failed);
				
				found |= memcpy_or_zero(sk->sk, blob0, crypto_box_SECRETKEYBYTES) ? SK_FOUND : NOT_FOUND;
				found |= memcpy_or_zero(pk->pk, blob1, crypto_box_PUBLICKEYBYTES) ? PK_FOUND : NOT_FOUND;
			} else if ( sk ) {
				if ( len0 != 0 && len0 != crypto_box_SECRETKEYBYTES )
					explode(stmt, sk_len_failed);
				
				found = memcpy_or_zero(sk->sk, blob0, crypto_box_SECRETKEYBYTES) ? SK_FOUND : NOT_FOUND;
			} else {
				if ( len0 != crypto_box_PUBLICKEYBYTES )
					explode(stmt, pk_len_failed);
				
				found = memcpy_or_zero(pk->pk, blob0, crypto_box_PUBLICKEYBYTES) ? PK_FOUND : NOT_FOUND;
			}
			sqlite3_finalize(stmt);
			return found;
			break;
		}

		default:
			explode(stmt, step_select_failed);
			return found;
			break;
	}
}

enum put_stmt {
	// Keep sorted by order of allocation
	BEGIN           = 0,
	COMMIT          = 1,
	ROLLBACK        = 2,
	SELECT_ID       = 3,
	INSERT_NAME     = 4,
	INSERT_PK       = 5,
	INSERT_SK       = 6,
	UPDATE_PK       = 7,
	UPDATE_SK       = 8,
	STATEMENT_COUNT = 9
};

static enum rc put(const char *restrict name, bool replace, const struct sk *restrict sk, const struct pk *restrict pk) {
	sqlite3_stmt *s[STATEMENT_COUNT];
	sqlite3_int64 id = 0;
	enum rc       rc = NOT_STORED;
	
	memset(s, 0, sizeof(s));

	const char *restrict queries[] = {
		begin_exclusive, commit_transaction, rollback_transaction,
		select_id, insert_name, insert_pk, insert_sk, update_pk, update_sk
	};
	const int query_lengths[] = {
    	strlen(queries[BEGIN]      ) + sizeof('\0'),
    	strlen(queries[COMMIT]     ) + sizeof('\0'),
    	strlen(queries[ROLLBACK]   ) + sizeof('\0'),
    	strlen(queries[SELECT_ID]  ) + sizeof('\0'),
    	strlen(queries[INSERT_NAME]) + sizeof('\0'),
    	strlen(queries[INSERT_PK]  ) + sizeof('\0'),
    	strlen(queries[INSERT_SK]  ) + sizeof('\0'),
		strlen(queries[UPDATE_PK]  ) + sizeof('\0'),
		strlen(queries[UPDATE_SK]  ) + sizeof('\0')
	};
	const char *restrict msgs[] = {
		prepare_begin_failed, prepare_commit_failed, prepare_rollback_failed,
		prepare_select_id_failed, prepare_insert_name_failed, prepare_insert_pk_failed, prepare_insert_sk_failed,
		prepare_update_pk_failed, prepare_update_sk_failed
	};

	// initialize all statements and back out if locked or busy
	for ( int i = 0; i < STATEMENT_COUNT; i++ ) {
		switch ( sqlite3_prepare_v2(db, queries[i], query_lengths[i], &s[i], NULL) ) {
			case SQLITE_BUSY:
				for ( int j = 0; j <= i; j++ )
					sqlite3_finalize(s[j]);
				return DB_BUSY;
				break;	
			
			case SQLITE_LOCKED:
				for ( int j = 0; j <= i; j++ )
					sqlite3_finalize(s[j]);
				return DB_LOCKED;
				break;

			case SQLITE_OK:
				break;

			default:
				explode2(s, msgs[i]);
		}
	}
	
	// bind parameters known at this time
	if ( sqlite3_bind_text(s[SELECT_ID], 1, name, strlen(name) + sizeof('\0'), SQLITE_TRANSIENT) != SQLITE_OK )
		explode2(s, msgs[SELECT_ID]);

	if ( sqlite3_bind_text(s[INSERT_NAME], 1, name, strlen(name) + sizeof('\0'), SQLITE_TRANSIENT) != SQLITE_OK )
		explode2(s, msgs[INSERT_NAME]);
	
	if ( pk && sqlite3_bind_blob(s[INSERT_PK], 2, pk, crypto_box_SECRETKEYBYTES, SQLITE_TRANSIENT) != SQLITE_OK )
		explode2(s, msgs[INSERT_PK]);

	if ( sk && sqlite3_bind_blob(s[INSERT_SK], 2, sk, crypto_box_PUBLICKEYBYTES, SQLITE_TRANSIENT) != SQLITE_OK )
		explode2(s, msgs[INSERT_SK]);

	if ( pk && sqlite3_bind_blob(s[UPDATE_PK], 1, pk, crypto_box_PUBLICKEYBYTES, SQLITE_TRANSIENT) != SQLITE_OK )
		explode2(s, msgs[UPDATE_PK]);

	if ( sk && sqlite3_bind_blob(s[UPDATE_SK], 1, sk, crypto_box_SECRETKEYBYTES, SQLITE_TRANSIENT) != SQLITE_OK )
		explode2(s, msgs[UPDATE_SK]);
	
	// start transaction back out if locked or busy
    switch ( sqlite3_step(s[BEGIN]) ) {
		case SQLITE_DONE:
			break;

		case SQLITE_BUSY:
			for ( int i = 0; i < STATEMENT_COUNT; i++ )
				sqlite3_finalize(s[i]);
			return DB_BUSY;
			break;
		case SQLITE_LOCKED:
			for ( int i = 0; i < STATEMENT_COUNT; i++ )
				sqlite3_finalize(s[i]);
			return DB_LOCKED;
			break;

		default:
			explode2(s, msgs[BEGIN]);
			break;
	}  
    
	// find name id, insert if missing
	switch ( sqlite3_step(s[SELECT_ID]) ) {
		case SQLITE_ROW:
			id = sqlite3_column_int64(s[SELECT_ID], 0);
			if ( sqlite3_step(s[SELECT_ID]) != SQLITE_DONE )
				explode2(s, select_id_failed);
			break;

		case SQLITE_DONE:
			if ( sqlite3_step(s[INSERT_NAME]) != SQLITE_DONE )
				explode2(s, insert_name_failed);
			id = sqlite3_last_insert_rowid(db);
			
		default:
			explode2(s, select_id_failed);
	}
    
	// set private key. overwrite if requested
	if ( sk ) {
		if ( sqlite3_bind_int64(s[INSERT_SK], 1, id) != SQLITE_OK ) {
			sqlite3_step(s[ROLLBACK]);
			explode2(s, bind_name_id_failed);
		}
		
		switch ( sqlite3_step(s[INSERT_SK]) ) {
			case SQLITE_DONE:
				rc |= SK_STORED;
				break;

			case SQLITE_CONSTRAINT:
				if ( replace ) {
            		if ( sqlite3_bind_int64(s[UPDATE_SK], 2, id) != SQLITE_OK ) {
						sqlite3_step(s[ROLLBACK]);
                        explode2(s, bind_name_id_failed);
					}

					if ( sqlite3_step(s[UPDATE_SK]) != SQLITE_DONE ) {
                    	sqlite3_step(s[ROLLBACK]);
						explode2(s, update_sk_failed);
					}

					rc |= SK_STORED;
					break;
				}
				
				rc = SK_OVERWRITE_FAILED;
				break;

			default:
				sqlite3_step(s[ROLLBACK]);
				explode2(s, insert_sk_failed);
				break;
		}
	}

	// set public key. overwrite if requested
	if ( pk && rc != SK_OVERWRITE_FAILED ) {
		if ( sqlite3_bind_int64(s[INSERT_PK], 1, id) != SQLITE_OK ) {
			sqlite3_step(s[ROLLBACK]);
			explode2(s, bind_name_id_failed);
		}

		switch ( sqlite3_step(s[INSERT_PK]) ) {
			case SQLITE_DONE:
				rc |= PK_STORED;
				break;

			case SQLITE_CONSTRAINT:
				if ( replace ) {
					if ( sqlite3_bind_int64(s[UPDATE_PK], 2, id) != SQLITE_OK ) {
						sqlite3_step(s[ROLLBACK]);
						explode2(s, bind_name_id_failed);
					}

					if ( sqlite3_step(s[UPDATE_PK]) != SQLITE_DONE ) {
						sqlite3_step(s[ROLLBACK]);
						explode2(s, update_pk_failed);
					}

					rc |= PK_STORED;
					break;
				}

				rc = PK_OVERWRITE_FAILED;
				break;
			
			default:
				sqlite3_step(s[ROLLBACK]);
				explode2(s, insert_pk_failed);
				break;
		}
	}

	if ( ( rc & KP_STORED ) == rc ) {
		if ( sqlite3_step(s[COMMIT]) != SQLITE_OK )
			explode2(s, commit_failed);
	} else {
		if ( sqlite3_step(s[ROLLBACK]) != SQLITE_OK )
			explode2(s, rollback_failed);
	}
	
	return rc;
}
