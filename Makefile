NACL_SHA256=4f277f89735c8b0b8a6bbd043b3efb3fa1cc68a9a5da6a076507d067fc3b3bf8
NACL_VERSION=20110221
SQLITE_SHA256=bd96d66c8a140776720c028f2eb09d4ff4b0bf9bde2f4f4cb707e26aad873b9a
SQLITE_VERSION=3070603
TMP?=tmp
LIB?=lib
BIN?=bin
OUT?=out
SRC?=src
SHARE?=share
INC?=include
NACL_TMP=$(TMP)/nacl-$(NACL_VERSION)
SQLITE_TMP=$(TMP)/sqlite-autoconf-$(SQLITE_VERSION)

NACL_URI=http://hyperelliptic.org/nacl/nacl-$(NACL_VERSION).tar.bz2
SQLITE_URI=http://www.sqlite.org/sqlite-autoconf-$(SQLITE_VERSION).tar.gz

SHORT_HOSTNAME=`hostname | sed 's/\..*//' | tr -cd '[a-z][A-Z][0-9]'`

CC=clang

ABI=`PATH=$(BIN):$${PATH} okabi | head -n 1`
CWARN+=-Wall -pedantic
CINC+=-I$(INC) -I$(INC)/$(ABI)
CLD+=-L$(LIB) -L$(LIB)/$(ABI)
CFLAGS+=-std=c99 $(CWARN) $(CINC) -D_POSIX_C_SOURCE=200809
LFLAGS+=`[ $(STATIC) ] && echo '-static'` $(CWARN) $(CLD)


all:: env nenc
env:: $(BIN)/.dummy $(LIB)/.dummy $(INC)/.dummy

hostname::
	echo $(SHORT_HOSTNAME)

$(NACL_TMP).tar.bz2:
	mkdir -p $(TMP)
	if which fetch >/dev/null 2>/dev/null; then fetch -o $@ $(NACL_URI); else wget -O $@ $(NACL_URI); fi
	which sha256 >/dev/null 2>/dev/null && [ `sha256 < $@` = $(NACL_SHA256) ] || which openssl >/dev/null 2>/dev/null && [ `openssl dgst -sha256 < $@ | sed 's/.*=[^a-fA-F0-9]*//'` = $(NACL_SHA256) ] || (echo "$@ is corrupted."; exit 1)

$(SQLITE_TMP).tar.gz:
	mkdir -p $(TMP)
	if which fetch >/dev/null 2>/dev/null; then fetch -o $@ $(SQLITE_URI); else wget -O $@ $(SQLITE_URI); fi
	which >/dev/null 2>/dev/null sha256 && [ `sha256 < $@` = $(SQLITE_SHA256) ] || which openssl >/dev/null 2>/dev/null && [ `openssl dgst -sha256 < $@ | sed 's/.*=[^a-fA-F0-9]*//'` = $(SQLITE_SHA256) ] || (echo "$@ is corrupted."; exit 1)

$(NACL_TMP): $(NACL_TMP).tar.bz2
	bunzip2 < $@.tar.bz2 | tar -x -C $(TMP) -f -
	touch $@

$(SQLITE_TMP): $(SQLITE_TMP).tar.gz
	gunzip < $@.tar.gz | tar -x -C $(TMP) -f -
	touch $@

$(NACL_TMP).compiled: $(NACL_TMP)
	cd $(NACL_TMP) && ./do
	touch $@

$(SQLITE_TMP).compiled: $(SQLITE_TMP)
	mkdir -p $(BIN) $(LIB) $(INC) $(SHARE)
	cd $(SQLITE_TMP) && ./configure --prefix=$(PWD) --bindir=`cd $(PWD); cd $(BIN); pwd` --libdir=`cd $(PWD); cd $(LIB); pwd` --includedir=`cd $(PWD); cd $(INC); pwd` --datarootdir=`cd $(PWD); cd $(SHARE); pwd`
	cd $(SQLITE_TMP) && make
	cd $(SQLITE_TMP) && make install
	touch $@

$(BIN)/.dummy: $(NACL_TMP).compiled $(SQLITE_TMP).compiled
	mkdir -p $(BIN)
	cp $(NACL_TMP)/build/$(SHORT_HOSTNAME)/bin/* $(BIN)
	touch $@

$(INC)/.dummy: $(NACL_TMP).compiled $(SQLITE_TMP).compiled
	mkdir -p $(INC)
	cp -r $(NACL_TMP)/build/$(SHORT_HOSTNAME)/include/* $(INC)
	touch $@

$(LIB)/.dummy: $(NACL_TMP).compiled $(SQLITE_TMP).compiled
	mkdir -p $(LIB)
	cp -r $(NACL_TMP)/build/$(SHORT_HOSTNAME)/lib/* $(LIB)
	touch $@

$(OUT)/genkey.o: $(SRC)/genkey.c
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $(SRC)/genkey.c

$(OUT)/db.o: $(SRC)/db.c $(SRC)/db.h $(SRC)/types.h
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $(SRC)/db.c

$(OUT)/opts.o: $(SRC)/opts.c $(SRC)/opts.h $(SRC)/types.h $(SRC)/db.h
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $(SRC)/opts.c

$(OUT)/hdr.o: $(SRC)/hdr.c $(SRC)/hdr.h $(SRC)/types.h
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $(SRC)/hdr.c

$(OUT)/ops.o: $(SRC)/ops.c $(SRC)/ops.h $(SRC)/db.h $(SRC)/types.h 
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $(SRC)/ops.c

$(OUT)/ops_crypt.o: $(SRC)/ops_crypt.c $(SRC)/ops.h $(SRC)/opts.h $(SRC)/db.h $(SRC)/types.h $(SRC)/hdr.h
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $(SRC)/ops_crypt.c

$(OUT)/ops_keys.o: $(SRC)/ops_keys.c $(SRC)/ops.h $(SRC)/opts.h $(SRC)/db.h $(SRC)/types.h
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $(SRC)/ops_keys.c

$(OUT)/nenc.o: $(SRC)/nenc.c $(SRC)/types.h $(SRC)/opts.h $(SRC)/db.h $(SRC)/ops.h
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $(SRC)/nenc.c

$(BIN)/nenc: $(OUT)/nenc.o $(OUT)/db.o $(OUT)/opts.o $(OUT)/hdr.o $(OUT)/ops.o $(OUT)/ops_crypt.o $(OUT)/ops_keys.o
	$(CC) $(LFLAGS) -o $@ $(OUT)/nenc.o $(OUT)/db.o $(OUT)/opts.o $(OUT)/hdr.o $(OUT)/ops.o $(OUT)/ops_crypt.o $(OUT)/ops_keys.o $(LIB)/$(ABI)/*.o -lnacl -lsqlite3

genkey: $(BIN)/genkey

nenc: $(BIN)/nenc

################################################################################
# Clean up
################################################################################

cleanbin::
	rm -f $(BIN)/genkey $(BIN)/nenc

cleanout::
	rm -rf $(OUT)/* 

cleantmp::
	rm -f $(NACL_TMP).tar.bz2
	rm -rf $(NACL_TMP).compiled $(NACL_TMP)

cleanenv::
	rm -f $(BIN)/*
	rm -rf $(INC)/*
	rm -rf $(LIB)/*
	rm -rf $(OUT)/*

clean:: cleanbin cleanout

cleanall:: clean
	rm -rf $(TMP) $(INC) $(LIB) $(BIN) $(SHARE) $(OUT)

