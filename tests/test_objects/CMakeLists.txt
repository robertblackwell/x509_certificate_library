file(GLOB SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp )
set(TARGET test_objects)
add_executable(${TARGET} 
	test_objects_main.cpp
	)
target_include_directories(${TARGET} PUBLIC ${TEST_INCLUDE_DIRS})
target_compile_features(${TARGET} PRIVATE cxx_std_17)
target_link_libraries(${TARGET} PUBLIC cert_library ${TEST_LINK_LIBS})

add_test(${TARGET} ${TARGET})
