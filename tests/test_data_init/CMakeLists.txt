file(GLOB SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp )
set(TARGET test_data_init)
add_executable(${TARGET} ${SOURCES})
target_include_directories(${TARGET} PUBLIC ${TEST_INCLUDE_DIRS})
target_link_libraries(${TARGET} PUBLIC cert_library ${TEST_LINK_LIBS})

add_test(${TARGET} ${TARGET})
add_test(${TARGET} ${TARGET})
