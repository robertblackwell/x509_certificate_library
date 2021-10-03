set(CERT_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set(CERT_TEST_INCLUDE_DIRS ${CERT_TEST_DIR} ${CERT_INCLUDE_DIR} 
	SYSTEM ${CERT_VENDOR_INCLUDEDIR} ${CERT_VENDOR_SRCDIR}
)

# 	Threads::Threads 
# 	${CMAKE_DL_LIBS}
# 	${CERT_LIBRARY_NAME} 
# 	${CERT_VENDOR_LIBDIR}/libcrypto.a 
# 	${CERT_VENDOR_LIBDIR}/libssl.a 
# 	${CERT_VENDOR_LIBDIR}/libboost_filesystem.a
# 	${CMAKE_DL_LIBS}
# 	${DL_LIB_SO}
# )

	# ${CMAKE_DL_LIBS}
	# ${VENDOR_DIR}/lib/libcrypto.a 
	# ${VENDOR_DIR}/lib/libssl.a 
	# ${VENDOR_DIR}/lib/libboost_filesystem.a 
	# ${VENDOR_DIR}/lib/libboost_system.a
	# ${VENDOR_DIR}/lib/libcert_library.a
	# ${CMAKE_DL_LIBS}
	# ${DL_LIB_SO}


set(CERT_TEST_DIR_COMMON_SOURCE ${CERT_TEST_DIR}/test_fixture_new.cpp)

message("TestDir Common Source ${TEST_DIR_COMMON_SOURCE}")

set(CERT_TEST_LIB_SOURCES
	test_fixture_new.cpp 
	test_fixture_new.hpp
)

add_library(test_lib STATIC 
	test_fixture_new.cpp 
	test_fixture_new.hpp 
	test_helpers.hpp
)
target_include_directories(test_lib 
	PUBLIC ${CERT_TEST_INCLUDE_DIRS}
)

set(CERT_TEST_LINK_LIBS test_lib ${CERT_LIBRARY_NAME} ${CERT_LINK_LIBRARIES}) 

add_subdirectory(test_fixture_build)
add_subdirectory(test_standalone)
add_subdirectory(test_exception)
add_subdirectory(test_x509)
add_subdirectory(test_builder)
add_subdirectory(test_handshaker)
add_subdirectory(test_objects)
