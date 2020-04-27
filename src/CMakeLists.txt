
# Optionally glob, but only for CMake 3.12 or later:
file(GLOB CERT_LIB_HEADERS CONFIGURE_DEPENDS "${PROJECT_DIR}/include/cert/*.hpp")
# set(HEADER_LIST "${CertificateLibrary_SOURCE_DIR}/include/cert/x509/cert.hpp")
message("HEADER_LIST ${HEADER_LIST}")
# Make an automatic library - will be static or dynamic based on user setting
set(CERT_LIB_SOURCES 
	./handshaker/cert_handshaker.cpp
	./handshaker/cert_handshaker_result.cpp
	./cert_authority/cert_authority.cpp
	./cert_authority/cert_auth_helper.cpp
	./store/cert_mozilla.cpp
	./store/cert_keychain.cpp
	./store/cert_store_host.cpp
	./store/cert_store_locator.cpp
	./store/cert_store_store.cpp
	./x509/name.cpp
	./x509/alt_names.cpp
	./x509/cert_check_host.cpp
	./x509/extension.cpp
	./x509/cert_impl.cpp
	./x509/error.cpp
	./x509/nid.cpp
	./x509/x509_req.cpp
	./x509/bio_utes.cpp
	./x509/serial.cpp
	./x509/chain.cpp
	./x509/create.cpp
	./x509/cert.cpp
	./x509/pkey.cpp
	./x509/x509_conf.cpp
	./x509/time.cpp
	./oo/cert_chain.cpp
	./oo/cert_builder.cpp
	./oo/cert_certificate.cpp
	./oo/cert_evp_pkey.cpp
	./oo/cert_identity.cpp
	./helpers/helpers_fs.cpp
	)

message("Sources: ${CERT_LIB_SOURCES}")

add_library(${CERT_LIBRARY_NAME} STATIC ${CERT_LIB_SOURCES} ${CERT_LIB_HEADERS})

# We need this directory, and users of our library will need it too
target_include_directories(
	${CERT_LIBRARY_NAME} 
		PUBLIC 
			${CERT_INCLUDE_DIR} 
		PRIVATE 
			${CERT_VENDOR_INCLUDEDIR}
			${CERT_VENDOR_SRCDIR}
)
