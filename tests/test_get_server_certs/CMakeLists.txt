
set(TARGET test_get_server_certs)
add_executable(${TARGET} test_main.cpp)
target_include_directories(${TARGET} PUBLIC ${CERT_TEST_INCLUDE_DIRS})
target_link_libraries(${TARGET} PUBLIC cert_library test_lib ${CERT_TEST_LINK_LIBS})

# add_test(${TARGET} ${TARGET})
