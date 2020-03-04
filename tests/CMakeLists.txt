set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(TEST_INCLUDE_DIRS ${TEST_DIR} ${PROJECT_DIR}/include/cert ${PROJECT_DIR}/include SYSTEM ${VENDOR_DIR}/include)
set(TEST_LINK_LIBS ${CERT_LIBRARY_NAME} ${VENDOR_DIR}/lib/libcrypto.a ${VENDOR_DIR}/lib/libssl.a ${VENDOR_DIR}/lib/libboost_filesystem.a)
set(TEST_DIR_COMMON_SOURCE ${TEST_DIR}/test_fixture_new.cpp)

message("TestDir Common Source ${TEST_DIR_COMMON_SOURCE}")

set(TEST_LIB_SOURCES
	test_fixture_new.cpp 
	test_fixture_new.hpp)
	# ../src/store/cert_mozilla.cpp
	# ../src/store/cert_keychain.cpp
	# ../src/store/cert_store_locator.cpp
	# ../src/store/cert_store_store.cpp
	# ../src/store/cert_store_host.cpp

add_library(test_lib STATIC 
	test_fixture_new.cpp 
	test_fixture_new.hpp 
	test_helpers.hpp
	# ../src/store/cert_mozilla.cpp
	# ../src/store/cert_keychain.cpp
	# ../src/store/cert_store_locator.cpp
	# ../src/store/cert_store_store.cpp
	# ../src/store/cert_store_host.cpp
	)
target_include_directories(test_lib PUBLIC ${TEST_INCLUDE_DIRS})
target_compile_features(test_lib PUBLIC cxx_std_11)

# add_library(test_lib INTERFACE )
# target_include_directories(test_lib INTERFACE ${TEST_DIR})
# target_sources(test_lib INTERFACE  ${TEST_DIR}/test_fixture_new.hpp)
# source_group(test_lib FILES ${TEST_DIR}/test_fixture_new.hpp)


add_subdirectory(test_exception)
add_subdirectory(test_x509)
add_subdirectory(test_builder)
add_subdirectory(test_handshaker)
add_subdirectory(test_objects)
