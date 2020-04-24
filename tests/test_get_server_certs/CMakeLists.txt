
set(TARGET test_get_server_certs)
add_executable(${TARGET} test_main.cpp)
target_include_directories(${TARGET} PUBLIC ${TEST_INCLUDE_DIRS})
target_compile_features(${TARGET} PRIVATE cxx_std_17)
target_link_libraries(${TARGET} PUBLIC cert_library test_lib ${TEST_LINK_LIBS})

add_test(${TARGET} ${TARGET})
