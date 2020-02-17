file(GLOB SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

set(TARGET test_x509)

add_executable(${TARGET} 
	test_cert_get_set.cpp
	test_ext.cpp
	test_name.cpp
	test_nid.cpp
	test_oo_cert.cpp
	test_the_helper.cpp
	test_time.cpp
	test_x509_main.cpp
	)
target_include_directories(${TARGET} PUBLIC ${TEST_INCLUDE_DIRS})
target_compile_features(${TARGET} PRIVATE cxx_std_17)
target_link_libraries(${TARGET} PUBLIC cert_library test_lib ${TEST_LINK_LIBS})

add_test(${TARGET} ${TARGET})
SET_TESTS_PROPERTIES(${TARGET}
    PROPERTIES ENVIRONMENT "SSL_CERT_FILE=/usr/local/etc/openssl@1.1/cert.pem")

# set_tests_properties(${TARGET}
# 	PROPERTIES
# 	PASS_REGULAR_EXPRESSION "Test passed")
# set_tests_properties(${TARGET}
# 	PROPERTIES
# 	FAIL_REGULAR_EXPRESSION "(Exception|Test failed)")
# set_tests_properties(${TARGET}
# 	PROPERTIES
# 	TIMEOUT 120)