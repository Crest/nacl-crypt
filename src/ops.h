#ifndef _NACLCRYPT_OPS_H
#define _NACLCRYPT_OPS_H

int dispatch();
int generate_key();
int export_key();
int import_key();
int delete_key();
int list_keys();
int encrypt();
int decrypt();

#endif /* _NACLCRYPT_OPS_H */
