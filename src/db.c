#include "db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <sqlite3.h>

const char     *db_path = NULL;
static sqlite3 *db      = NULL;

#define CHARS_PER_UINT32 (10)

static const char schema[] =
	"CREATE TABLE IF NOT EXISTS Names (\n"
	"    Id   INTEGER PRIMARY KEY ASC AUTOINCREMENT,\n"
	"    Name STRING NOT NULL UNIQUE\n"
	");\n"

	"CREATE TABLE IF NOT EXISTS PublicKeys (\n"
	"    Id        INTEGER PRIMARY KEY ASC AUTOINCREMENT,\n"
	"    NameId    INTEGER NOT NULL UNIQUE REFERENCES Names(Id) ON DELETE CASCADE ON UPDATE CASCADE,\n"
	"    PublicKey BLOB NOT NULL CHECK ( LENGTH(PublicKey) = %" PRIu32 " )\n"
	");\n"

	"CREATE TABLE IF NOT EXISTS PrivateKeys (\n"
	"    Id         INTEGER PRIMARY KEY ASC AUTOINCREMENT,\n"
	"    NameId     INTEGER NOT NULL UNIQUE REFERENCES Names(Id) ON DELETE CASCADE ON UPDATE CASCADE,\n"
	"    PrivateKey BLOB NOT NULL CHECK ( LENGTH(PrivateKey) = %" PRIu32 " )\n"
	");\n"

	"CREATE TRIGGER IF NOT EXISTS DeleteStaleNamePublicKey\n"
	"    AFTER DELETE ON PublicKeys FOR EACH ROW\n"
	"    WHEN OLD.NameId NOT IN ( SELECT NameId FROM PrivateKeys ) BEGIN\n"
	"        DELETE FROM Names WHERE Names.Id = OLD.NameId;\n"
    "END;\n"
	
	"CREATE TRIGGER IF NOT EXISTS DeleteStaleNamePrivateKey\n"
	"    AFTER DELETE ON PrivateKeys FOR EACH ROW\n"
	"    WHEN OLD.NameId NOT IN ( SELECT NameId FROM PrivateKeys ) BEGIN\n"
	"        DELETE FROM Names WHERE Names.Id = OLD.NameId;\n"
	"END;\n";

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

static const char select_all[] =
	"SELECT Names.Name, PublicKeys.PublicKey, NULL FROM Names\n"
    "    JOIN PublicKeys ON Names.Id = PublicKeys.NameId\n"
	"    WHERE Names.Id NOT IN (SELECT PrivateKeys.NameId FROM PrivateKeys)\n"
	"UNION ALL\n"
	"SELECT Names.Name, NULL, PrivateKeys.PrivateKey FROM Names\n"
	"    JOIN PrivateKeys ON Names.Id = PrivateKeys.NameId\n"
	"    WHERE Names.Id NOT IN (SELECT PublicKeys.NameId FROM PublicKeys)\n"
	"UNION ALL\n"
	"SELECT Names.Name, PublicKeys.PublicKey, PrivateKeys.PrivateKey FROM Names\n"
	"    JOIN PublicKeys  ON Names.Id = PublicKeys.NameId\n"
	"    JOIN PrivateKeys ON Names.Id = PrivateKeys.NameId\n"
	"ORDER BY Names.Name;";

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
	"INSERT INTO Names ( Id, Name )\n"
	"    VALUES ( NULL, ? );";

static const char insert_sk[] =
	"INSERT INTO PrivateKeys ( Id, NameID, PrivateKey )\n"
	"    VALUES ( NULL, ?, ? );";

static const char insert_pk[] =
	"INSERT INTO PublicKeys ( Id, NameID, PublicKey )\n"
	"    VALUES ( NULL, ?, ? );";

static const char update_sk[] =
	"UPDATE PrivateKeys SET PrivateKey = ?\n"
	"    WHERE NameId = ?;";

static const char update_pk[] =
	"UPDATE PublicKeys SET PublicKey = ?\n"
	"    WHERE NameId = ?;";

static const char delete_sk[] =
	"DELETE FROM PrivateKeys\n"
	"    WHERE PrivateKeys.NameId IN ( SELECT Names.Id FROM Names\n"
	"        WHERE Names.Name = ? );";

static const char delete_pk[] =
	"DELETE FROM PublicKeys\n"
	"    WHERE PublicKeys.NameId IN ( SELECT Names.Id FROM Names\n"
	"        WHERE Names.Name = ? );";

static const char count_pk[] =
	"SELECT COUNT(*) FROM Names, PublicKeys\n"
	"    WHERE Names.Name = ? AND Names.Id = PublicKeys.NameId;";

static const char count_sk[] =
	"SELECT COUNT(*) FROM Names, PrivateKeys\n"
	"    WHERE Names.Name = ? AND Names.Id = PrivateKeys.NameId;";

static const char schema_failed[]         = "Failed to define schema";
static const char open_failed[]           = "Failed to open database";
static const char close_failed[]          = "Failed to close database";
static const char prepare_select_failed[] = "Failed to prepare select statement for key retrieval";
static const char bind_select_failed[]    = "Failed to bind first parameter to select statement for key retrieval";
static const char pk_len_failed[]         = "Private key read form database has wrong length";
static const char sk_len_failed[]         = "Public key read from database has wrong length";
static const char step_select_failed[]    = "Failed to step through rows returned by select statement for key retrieval";
static const char foreign_keys_failed[]   = "Failed to enable foreign key support";

static const char prepare_schema_failed[]      = "Failed to prepare SQL query for schema definition";
static const char prepare_begin_failed[]       = "Failed to prepare begin transaction statement";
static const char prepare_commit_failed[]      = "Failed to prepare commit transaction statement";
static const char prepare_rollback_failed[]    = "Failed to prepare rollback transaction statement";
static const char prepare_select_id_failed[]   = "Failed to prepare select statement for name id retrieval";
static const char prepare_insert_name_failed[] = "Failed to prepare insert statement to insert name";
static const char prepare_insert_pk_failed[]   = "Failed to prepare insert statement to insert public key";
static const char prepare_insert_sk_failed[]   = "Failed to prepare insert statement to insert private key";
static const char prepare_update_pk_failed[]   = "Failed to prepare update statement to change public key";
static const char prepare_update_sk_failed[]   = "Failed to prepare update statement to change private key";
static const char prepare_delete_pk_failed[]   = "Failed to prepare delete statement to delete public key";
static const char prepare_delete_sk_failed[]   = "Failed to prepare delete statement to delete private key";
static const char prepare_select_all_failed[]  = "Failed to prepare select statement to retrieve all key material";
static const char prepare_count_pk_failed[]    = "Failed to prepare select statement to count public keys by name";
static const char prepare_count_sk_failed[]    = "Failed to prepare select statement to count private keys by name";
static const char select_id_failed[]           = "Failed to select id by name";
static const char insert_name_failed[]         = "Failed to insert name";
static const char bind_name_id_failed[]        = "Failed to bind name id to insert";
static const char insert_sk_failed[]           = "Failed to insert private key";
static const char update_sk_failed[]           = "Failed to update private key";
static const char insert_pk_failed[]           = "Failed to insert public key";
static const char update_pk_failed[]           = "Failed to update public key";
static const char rollback_failed[]            = "Failed to rollback transaction";
static const char commit_failed[]              = "Failed to commit transaction";
static const char bind_name_failed[]           = "Failed to bind name to delete from statement";
static const char begin_failed[]               = "Failed to begin transaction";
static const char delete_sk_failed[]           = "Failed to delete private key";
static const char delete_pk_failed[]           = "Failed to delete public key";
static const char select_all_failed[]          = "Failed to select all key material";
static const char count_pk_failed[]            = "Failed to count public keys by name";
static const char count_sk_failed[]            = "Faield to count private keys by name";

static enum rc get(const char *restrict name, const char *restrict query, int query_len, struct sk *restrict sk, struct pk *restrict pk);
static enum rc put(const char *restrict name, bool replace, const struct sk *restrict sk, const struct pk *restrict pk);
static enum rc del(const char *restrict name, bool force, bool sk, bool pk);
static void explode(sqlite3_stmt *stmt, const char *restrict msg);
static void explode2(sqlite3_stmt **stmts, const char *restrict msg);
static void *memcpy_or_zero(void *restrict dst, const void *restrict src, size_t n);


enum rc define_schema() {
	char *err = NULL;
	char buf[strlen(schema) + sizeof('\0') + 2 * CHARS_PER_UINT32];
	
	if ( snprintf(buf, sizeof(buf), schema, crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES) < 0 ) {
    	sqlite3_close(db);
		fprintf(stderr, "%s.\n", prepare_schema_failed);
		exit(70);
	}
	
	switch ( sqlite3_exec(db, buf, NULL, NULL, &err) ) {
		case SQLITE_OK:
			break;
		
		case SQLITE_LOCKED:
			sqlite3_free(err);
			return DB_LOCKED;
			break;
		
		case SQLITE_BUSY:
			sqlite3_free(err);
			return DB_BUSY;
			break;

		default:
			fprintf(stderr, "%s: %s\n", schema_failed, err);
			sqlite3_free(err);
			sqlite3_close(db);
			exit(78);
			break;
	}
	
	return OK;
}

enum rc open_db(const char *restrict db_path) {
	char *err = NULL;
	switch ( sqlite3_open(db_path, &db) ) {
		case SQLITE_OK:
			break;
			
		case SQLITE_LOCKED:
			sqlite3_close(db);
			return DB_LOCKED;
			break;
		
		case SQLITE_BUSY:
			sqlite3_close(db);
			return DB_BUSY;
			break;
			
		default:
			fprintf(stderr, "%s: %s\n", open_failed, sqlite3_errmsg(db));
			sqlite3_close(db);
			exit(66);
			break;
	}
	
	switch ( sqlite3_exec(db, foreign_keys_on, NULL, NULL, &err) ) {
		case SQLITE_OK:
			break;
		
		case SQLITE_LOCKED:
			return DB_LOCKED;
			break;
		
		case SQLITE_BUSY:
			return DB_BUSY;
			break;
		
		default:
			fprintf(stderr, "%s: %s\n", foreign_keys_failed, err);
			sqlite3_free((void *) err);
			sqlite3_close(db);
			exit(70);
			break;
	}
	return define_schema();
}

void close_db() {
	if ( sqlite3_close(db) != SQLITE_OK ) {
		fprintf(stderr, "%s: %s\n", close_failed, sqlite3_errmsg(db));
		exit(70);
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

enum rc del_pk(const char *restrict name, bool force) {
	return del(name, force, false, true);
}

enum rc del_sk(const char *restrict name, bool force) {
	return del(name, force, true, false);
}

enum rc del_kp(const char *restrict name, bool force) {
	return del(name, force, true, true);
}

static void explode(sqlite3_stmt *stmt, const char *restrict msg) {
	sqlite3_finalize(stmt);
	fprintf(stderr, "%s: %s\n", msg, sqlite3_errmsg(db));
	sqlite3_close(db);
	exit(70);
}

static void explode2(sqlite3_stmt **stmts, const char *restrict msg) {
	while (*stmts) 
		sqlite3_finalize(*stmts++);
	fprintf(stderr, "%s: %s\n", msg, sqlite3_errmsg(db));
	sqlite3_close(db);
	exit(70); 
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
			return NOT_FOUND;
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
			} else if ( pk ) {
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
			return NOT_FOUND;
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
	PUT_STATEMENT_COUNT = 9
};

static enum rc put(const char *restrict name, bool replace, const struct sk *restrict sk, const struct pk *restrict pk) {
	sqlite3_stmt *s[PUT_STATEMENT_COUNT+1];
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
	for ( int i = 0; i < PUT_STATEMENT_COUNT; i++ ) {
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
	if ( sqlite3_bind_text(s[SELECT_ID], 1, name, -1, SQLITE_TRANSIENT) != SQLITE_OK )
		explode2(s, msgs[SELECT_ID]);

	if ( sqlite3_bind_text(s[INSERT_NAME], 1, name, -1, SQLITE_TRANSIENT) != SQLITE_OK )
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
			for ( int i = 0; i < PUT_STATEMENT_COUNT; i++ )
				sqlite3_finalize(s[i]);
			return DB_BUSY;
			break;
		case SQLITE_LOCKED:
			for ( int i = 0; i < PUT_STATEMENT_COUNT; i++ )
				sqlite3_finalize(s[i]);
			return DB_LOCKED;
			break;

		default:
			explode2(s, begin_failed);
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
			break;
			
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
		if ( sqlite3_step(s[COMMIT]) != SQLITE_DONE )
			explode2(s, commit_failed);
	} else {
		if ( sqlite3_step(s[ROLLBACK]) != SQLITE_DONE )
			explode2(s, rollback_failed);
	}

	for ( int i = 0; i < PUT_STATEMENT_COUNT; i++ )
		sqlite3_finalize(s[i]);
	
	return rc;
}

enum del_stmt {
	// Keep sorted by order of allocation
	DELETE_SK           = 3,
	DELETE_PK           = 4,
	COUNT_SK            = 5,
	COUNT_PK            = 6,
	DEL_STATEMENT_COUNT = 7
};

static enum rc del(const char *restrict name, bool force, bool sk, bool pk) {
	sqlite3_stmt *s[DEL_STATEMENT_COUNT + 1] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	const char *queries[] = {
		begin_exclusive, commit_transaction, rollback_transaction,
		delete_sk, delete_pk,
		count_sk, count_pk
	};
	const int query_lengths[] = {
		strlen(queries[BEGIN]      ) + sizeof('\0'),
		strlen(queries[COMMIT]     ) + sizeof('\0'),
		strlen(queries[ROLLBACK]   ) + sizeof('\0'),
		strlen(queries[DELETE_SK]  ) + sizeof('\0'),
		strlen(queries[DELETE_PK]  ) + sizeof('\0'),
		strlen(queries[COUNT_SK]   ) + sizeof('\0'),
		strlen(queries[COUNT_PK]   ) + sizeof('\0')
	};
	const char *msgs[]    = {
		prepare_begin_failed, prepare_commit_failed, prepare_rollback_failed,
		prepare_delete_sk_failed, prepare_delete_pk_failed,
		prepare_count_sk_failed, prepare_count_pk_failed
	};
	enum rc rc = NOT_FOUND;
	
	for ( int i = 0; i < DEL_STATEMENT_COUNT; i++ ) {
		switch ( sqlite3_prepare_v2(db, queries[i], query_lengths[i], &s[i], NULL ) ) {
        	case SQLITE_OK:
				break;

			case SQLITE_BUSY:
				for ( int j = 0; j <= i; j++ )
                	sqlite3_finalize(s[j]);
				
				return DB_BUSY;
				break;

			case SQLITE_LOCKED:
				for ( int j = 0; j < DEL_STATEMENT_COUNT; j++ )
					sqlite3_finalize(s[j]);

				return DB_LOCKED;
				break;

			default:
				explode2(s, msgs[i]); 
		}
	}
	
	sqlite3_stmt *begin    = s[BEGIN];
	sqlite3_stmt *commit   = s[COMMIT];
	sqlite3_stmt *rollback = s[ROLLBACK];
	sqlite3_stmt *del_sk   = s[DELETE_SK];
	sqlite3_stmt *del_pk   = s[DELETE_PK];
	sqlite3_stmt *cnt_sk   = s[COUNT_SK];
	sqlite3_stmt *cnt_pk   = s[COUNT_PK];

	if ( sk && sqlite3_bind_text(del_sk, 1, name, -1, SQLITE_TRANSIENT) != SQLITE_OK )
		explode2(s, bind_name_failed);
	if ( pk && sqlite3_bind_text(del_pk, 1, name, -1, SQLITE_TRANSIENT) != SQLITE_OK )
		explode2(s, bind_name_failed);
	if ( sk && sqlite3_bind_text(cnt_sk, 1, name, -1, SQLITE_TRANSIENT) != SQLITE_OK )
		explode2(s, bind_name_failed);
	if ( pk && sqlite3_bind_text(cnt_pk, 1, name, -1, SQLITE_TRANSIENT) != SQLITE_OK )
		explode2(s, bind_name_failed);

	switch ( sqlite3_step(begin) ) {
		case SQLITE_DONE:
			break;

		case SQLITE_BUSY:
			for ( int i = 0; i < DEL_STATEMENT_COUNT; i++ )
				sqlite3_finalize(s[i]);

			return DB_BUSY;
			break;

		case SQLITE_LOCKED:
			for ( int i = 0; i < DEL_STATEMENT_COUNT; i++ )
				sqlite3_finalize(s[i]);

			return DB_LOCKED;
			break;

		default:
			explode2(s, begin_failed);
	}

	int n_sk = 0;
	int n_pk = 0;
	
	if ( sk ) {
		if ( sqlite3_step(cnt_sk) == SQLITE_ROW ) {
			n_sk = sqlite3_column_int(cnt_sk, 0);
		} else {
			explode2(s, count_sk_failed);
		}
	}

	if ( pk ) {
    	if ( sqlite3_step(cnt_pk) == SQLITE_ROW ) {
			n_pk = sqlite3_column_int(cnt_pk, 0);
		} else {
			explode2(s, count_pk_failed);
		}
	}

	if ( !force && !((sk && n_sk) || (pk && n_pk)) ) { 
		for ( int i = 0; i < DEL_STATEMENT_COUNT; i++ ) if (i != ROLLBACK )
			sqlite3_finalize(s[i]);
		
		if ( sqlite3_step(rollback) != SQLITE_DONE ) {
			explode2(s, rollback_failed);
		}
		sqlite3_finalize(rollback);
		
		return NOT_DELETED;
	}
	
	if ( n_sk && sqlite3_step(del_sk) != SQLITE_DONE ) {
		sqlite3_step(rollback);
		explode2(s, delete_sk_failed);
	} else {
		rc |= SK_DELETED;
	}

	if ( n_pk && sqlite3_step(del_pk) != SQLITE_DONE ) {
		sqlite3_step(rollback);
		explode2(s, delete_pk_failed);
	} else {
		rc |= PK_DELETED;
	}

	if ( sqlite3_step(commit) != SQLITE_DONE ) {
		sqlite3_step(rollback);
		explode2(s, commit_failed);
	}

	for ( int i = 0; i < DEL_STATEMENT_COUNT; i++ ) {
		sqlite3_finalize(s[i]);
	}
        
	return rc;
}

enum rc list_kp(list_f f) {
	enum rc rc;

	sqlite3_stmt *select = NULL;
	if ( sqlite3_prepare_v2(db, select_all, strlen(select_all) + sizeof('\0'), &select, NULL) != SQLITE_OK ) {
    	explode(select, prepare_select_all_failed);
	}

	do {
    	switch ( sqlite3_step(select) ) {
        	case SQLITE_DONE:
				rc = OK;
				break;

		case SQLITE_ROW: {
			const unsigned char *const name  = sqlite3_column_text (select, 0);
			const void          *const p     = sqlite3_column_blob (select, 1);
			const int                  p_len = sqlite3_column_bytes(select, 1);
			const void          *const s     = sqlite3_column_blob (select, 2);
			const int                  s_len = sqlite3_column_bytes(select, 2);
			      enum rc              found = NOT_FOUND;
			      struct kp            kp;
				
			if ( !name )
				explode(select, "Constraint violation (unnamed row).");

				if ( !p && !s )
					explode(select, "Constraint violation (name without any key)");

				if ( p && p_len != crypto_box_PUBLICKEYBYTES ) {
					explode(select, "Constraint violation (public key with invalid length).");
				}

				if ( s && s_len != crypto_box_SECRETKEYBYTES ) {
					explode(select, "Constraint violation (private key with invalid length).");
				}

		   		if ( p && s ) {
					found = KP_FOUND;
					memcpy(kp.pk.pk, p, crypto_box_PUBLICKEYBYTES);
					memcpy(kp.sk.sk, s, crypto_box_SECRETKEYBYTES);
				} else if ( p ) {
					found = PK_FOUND;
					memcpy(kp.pk.pk, p, crypto_box_PUBLICKEYBYTES);
					memset(kp.sk.sk, 0, crypto_box_SECRETKEYBYTES);
				} else if ( s ) {
					found = SK_FOUND;
					memset(kp.pk.pk, 0, crypto_box_PUBLICKEYBYTES);
					memcpy(kp.sk.sk, s, crypto_box_SECRETKEYBYTES);
				}

				rc = f(found, name, &kp);
				if ( rc != OK ) {
					sqlite3_finalize(select);
					return rc;
				}
				rc = NOT_FOUND;
				
				break;
			}

			case SQLITE_LOCKED:
				sqlite3_finalize(select);
				return DB_LOCKED;
				break;

			case SQLITE_BUSY:
				sqlite3_finalize(select);
				return DB_BUSY;
				break;
			
			default:
				explode(select, select_all_failed);
				break;
		}
	} while ( rc != OK );

	sqlite3_finalize(select);
	return OK;
}
