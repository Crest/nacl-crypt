NACL_SHA256=4f277f89735c8b0b8a6bbd043b3efb3fa1cc68a9a5da6a076507d067fc3b3bf8
NACL_VERSION=20110221
TMP?=tmp
LIB?=lib
BIN?=bin
INCLUDE?=include
NACL_TMP=$(TMP)/nacl-$(NACL_VERSION)

env:: $(BIN) $(LIB) $(INCLUDE)

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

$(INCLUDE): $(NACL_TMP).compiled
	mkdir -p $(INCLUDE)
	cp -r $(NACL_TMP)/build/`hostname -s`/include/* $(INCLUDE)

$(LIB): $(NACL_TMP).compiled
	mkdir -p $(LIB)
	cp -r $(NACL_TMP)/build/`hostname -s`/lib/* $(LIB)


cleantmp::
	rm -f $(NACL_TMP).tar.bz2
	rm -rf $(NACL_TMP).compiled $(NACL_TMP)

clean:: cleantmp
	rm -f $(BIN)/*
	rm -rf $(INCLUDE)/*
	rm -rf $(LIB)/*

cleanall:: clean
	rm -rf $(TMP) $(INCLUDE) $(LIB) $(BIN)
	
