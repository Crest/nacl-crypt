#ifndef _NACL_CRYPT_DB_H
#define _NACL_CRYPT_DB_H

#include "types.h"

enum rc define_schema();
enum rc open_db(const char *restrict db_path);
void close_db();

typedef enum rc (*list_f) (enum rc rc, const unsigned char *name, const struct kp *kp);

// search keys by name.
enum rc get_pk(const char *restrict name, struct pk *pk);
enum rc get_sk(const char *restrict name, struct sk *sk);
enum rc get_kp(const char *restrict name, struct kp *kp);

// return error on name collision
enum rc set_pk(const char *restrict name, const struct pk *pk);
enum rc set_sk(const char *restrict name, const struct sk *sk);
enum rc set_kp(const char *restrict name, const struct kp *kp);

// overwrite on name collision
enum rc put_pk(const char *restrict name, const struct pk *pk);
enum rc put_sk(const char *restrict name, const struct sk *sk);
enum rc put_kp(const char *restrict name, const struct kp *kp);

enum rc del_pk(const char *restrict name, bool force);
enum rc del_sk(const char *restrict name, bool force);
enum rc del_kp(const char *restrict name, bool force);

enum rc list_kp(list_f callback);

#endif /* NACL_CRYPT_DB_H */
