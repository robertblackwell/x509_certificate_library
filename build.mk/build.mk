# 
# Builds the library x509.a and all the test executables
# 
TEST_DIR=$(realpath ../tests)
TESTS=\
	test_data_init \
	test_x509 \
	test_builder \
	test_handshake 
# 	test_cert_server \
# 	test_cert_store \
# 	test_server

all: LIB BUILDER INIT HANDSHAKE X509

.PHONY: LIB
LIB:
	make -f build.mk/lib.mk all 

.PHONY: X509
X509: LIB
	make -f build.mk/test.mk t_all T=test_x509

.PHONY: BUILDER
BUILDER: LIB
	make -f build.mk/test.mk t_all T=test_builder

.PHONY: CERT_SERVER
CERT_SERVER: LIB
	make -f build.mk/test.mk t_all T=test_cert_server

.PHONY: CERTSTORE
CERTSTORE: LIB
	make -f build.mk/test.mk t_all T=test_cert_store

.PHONY: INIT
INIT: LIB
	make -f build.mk/test.mk t_all T=test_data_init

.PHONY: HANDSHAKE
HANDSHAKE: LIB
	make -f build.mk/test.mk t_all T=test_handshake

.PHONY: SERVER
SERVER: LIB
	make -f build.mk/test.mk t_all T=test_server

.PHONY: run
run:
	@for i in $(TESTS) ; do \
	make -f build.mk/test.mk t_run T=$$i ;	\
	done

.PHONY: build
build: LIB
	@for i in $(TESTS) ; do \
	make -f build.mk/test.mk t_all T=$$i ;	\
	done


.PHONY: clean
clean:
	@for i in $(TESTS) ; do \
	make -f build.mk/test.mk clean T=$$i ;	\
	done

.PHONY: dump
dump: dump_test_x509 dump_test_builder dump_test_cert_server
	echo dump

