bin=./DerivedData/x509/Build/Products/Debug
.PHONY: run
run:
	$(bin)/test_data_init
	$(bin)/test_x509
	$(bin)/test_handshaker
	$(bin)/test_builder
# 	./tests/test_server/test_server
# 	./tests/test_cert_store/test_cert_store
# 	./tests/test_cert_server/test_cert_server


.PHONY: all
tests_all: clean build

.PHONY: clean
clean:
	xcodebuild -scheme x509 clean
	xcodebuild -scheme test_x509 clean
	xcodebuild -scheme test_cert_store clean
	xcodebuild -scheme test_handshaker clean
	xcodebuild -scheme test_builder clean
	xcodebuild -scheme test_data_init clean
	xcodebuild -scheme test_server clean


.PHONY: build
build:
	xcodebuild -quiet -scheme x509 build
	xcodebuild -quiet -scheme test_x509 build
	xcodebuild -quiet -scheme test_cert_store build
	xcodebuild -quiet -scheme test_handshaker build
	xcodebuild -quiet -scheme test_builder build
	xcodebuild -quiet -scheme test_data_init build
	xcodebuild -quiet -scheme test_server build

