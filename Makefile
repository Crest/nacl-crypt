NACL_SHA256=4f277f89735c8b0b8a6bbd043b3efb3fa1cc68a9a5da6a076507d067fc3b3bf8
NACL_VERSION=20110221
TMP?=tmp
LIB?=lib
BIN?=bin
OUT?=out
SRC?=src
INC?=include
NACL_TMP=$(TMP)/nacl-$(NACL_VERSION)

CC=clang

ABI!=if [ -x $(BIN)/okabi ]; then export PATH=$(BIN):$${PATH}; okabi; fi
CWARN+=-Wall -pedantic
CINC+=-I$(INC) -I$(INC)/$(ABI)
CLD+=-L$(LIB)/$(ABI)
CFLAGS+=-std=c99 $(CWARN) $(CINC)
LFLAGS+=-static $(CWARN) $(CLD)

env:: $(BIN) $(LIB) $(INC)

$(NACL_TMP).tar.bz2:
	mkdir -p $(TMP)
	fetch -o tmp/nacl-$(NACL_VERSION).tar.bz2 http://hyperelliptic.org/nacl/nacl-$(NACL_VERSION).tar.bz2
	[ `sha256 < tmp/nacl-$(NACL_VERSION).tar.bz2` = $(NACL_SHA256) ] || (echo "tmp/nacl-$(NACL_VERSION).tar.bz2 is corrupted."; exit 1)

$(NACL_TMP): $(NACL_TMP).tar.bz2
	bunzip2 < $(NACL_TMP).tar.bz2 | tar -x -C $(TMP) -f -
	touch $(NACL_TMP)

$(NACL_TMP).compiled: $(NACL_TMP)
	cd $(NACL_TMP) && ./do
	touch $(NACL_TMP).compiled

$(BIN): $(NACL_TMP).compiled
	mkdir -p $(BIN)
	cp $(NACL_TMP)/build/`hostname -s`/bin/* $(BIN)

$(INC): $(NACL_TMP).compiled
	mkdir -p $(INC)
	cp -r $(NACL_TMP)/build/`hostname -s`/include/* $(INC)

$(LIB): $(NACL_TMP).compiled
	mkdir -p $(LIB)
	cp -r $(NACL_TMP)/build/`hostname -s`/lib/* $(LIB)

$(OUT)/genkey.o: $(SRC)/genkey.c
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $>

$(BIN)/genkey: $(OUT)/genkey.o
	$(CC) $(LFLAGS) -o $@ $(OUT)/genkey.o $(LIB)/$(ABI)/*.o -lnacl

cleantmp::
	rm -f $(NACL_TMP).tar.bz2
	rm -rf $(NACL_TMP).compiled $(NACL_TMP)

clean:: cleantmp
	rm -f $(BIN)/*
	rm -rf $(INC)/*
	rm -rf $(LIB)/*

cleanall:: clean
	rm -rf $(TMP) $(INC) $(LIB) $(BIN)
	
foo::
	echo $(ABI)
