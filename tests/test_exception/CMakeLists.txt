
set(TARGET test_exception)
add_executable(${TARGET} test_exception.cpp)
target_include_directories(${TARGET} PUBLIC ${TEST_INCLUDE_DIRS})
target_link_libraries(${TARGET} PUBLIC cert_library test_lib ${TEST_LINK_LIBS})

add_test(${TARGET} ${TARGET})
add_test(${TARGET} ${TARGET})
