file(GLOB SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

set(TARGET test_builder)

add_executable(${TARGET} ${SOURCES})
target_include_directories(${TARGET} PUBLIC ${TEST_INCLUDE_DIRS})
target_compile_features(${TARGET} PRIVATE cxx_std_17)
target_link_libraries(${TARGET} PUBLIC cert_library test_lib ${TEST_LINK_LIBS})

add_test(${TARGET} ${TARGET})
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