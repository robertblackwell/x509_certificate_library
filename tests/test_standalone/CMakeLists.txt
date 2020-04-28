set(TARGET test_standalone)
add_executable(${TARGET} 
    test_standalone.cpp
)
target_include_directories(${TARGET} PUBLIC ${CERT_TEST_INCLUDE_DIRS})
target_link_libraries(${TARGET} PUBLIC cert_library ${CERT_TEST_LINK_LIBS})

add_test(${TARGET} ${TARGET})
