message("test_exception")
message("CERT_TEST_INCLUDE_DIRS                      ${CERT_TEST_INCLUDE_DIRS}")
message("CERT_TEST_LINK_LIBS                         ${CERT_TEST_LINK_LIBS}")
set(TARGET test_exception)
add_executable(${TARGET} test_exception.cpp)
target_include_directories(${TARGET} PUBLIC ${CERT_TEST_INCLUDE_DIRS})
target_link_libraries(${TARGET} PUBLIC cert_library test_lib ${CERT_TEST_LINK_LIBS})

add_test(${TARGET} ${TARGET})
