
# Note that headers are optional, and do not affect add_library, but they will not
# show up in IDEs unless they are listed in add_library.
message("CertificateLibrary_SOURCE_DIR: ${CertificateLibrary_SOURCE_DIR}")
message("Vendir Dir: ${VENDOR_DIR}")
set(PROJECT_DIR ${CertificateLibrary_SOURCE_DIR})

set(CMAKE_BUILD_TYPE Debug)

# Optionally glob, but only for CMake 3.12 or later:
file(GLOB HEADER_LIST CONFIGURE_DEPENDS "${PROJECT_DIR}/include/cert/*.hpp")
# set(HEADER_LIST "${CertificateLibrary_SOURCE_DIR}/include/cert/x509/cert.hpp")
message("HEADER_LIST ${HEADER_LIST}")
# Make an automatic library - will be static or dynamic based on user setting
set(SOURCES 
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
	# ./store/cert_mozilla.cpp
	# ./store/cert_keychain.cpp
	# ./store/cert_store_locator.cpp
	# ./store/cert_store_store.cpp
	# ./store/cert_store_host.cpp
	# )


# file (GLOB SOURCESX 
# 	${PROJECT_DIR}/src/cert_authority/*.cpp
# 	${PROJECT_DIR}/src/handshaker/*.cpp
# 	${PROJECT_DIR}/src/helpers/*.cpp
# 	${PROJECT_DIR}/src/oo/*.cpp
# 	${PROJECT_DIR}/src/store/*.cpp
# 	${PROJECT_DIR}/src/x509/*.cpp)

message("Sources: ${SOURCES}")

add_library(${CERT_LIBRARY_NAME} STATIC ${SOURCES} ${HEADER_LIST})

# We need this directory, and users of our library will need it too
target_include_directories(${CERT_LIBRARY_NAME} PUBLIC ${PROJECT_DIR}/include PRIVATE ${VENDOR_DIR}/include)
# This depends on (header only) boost
# target_link_libraries(cert_library PRIVATE Boost::boost)


# IDEs should put the headers in a nice place
# source_group(TREE "${PROJECT_SOURCE_DIR}/include" PREFIX "Header Files" FILES ${HEADER_LIST})
# source_group(headers FILES ${HEADER_LIST})
# source_group(headers REGULAR_EXPRESSION include/cert/*.hpp})
