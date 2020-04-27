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
target_include_directories(${TARGET} PUBLIC ${CERT_TEST_INCLUDE_DIRS})
target_link_libraries(${TARGET} PUBLIC cert_library test_lib ${CERT_TEST_LINK_LIBS})

add_test(${TARGET} ${TARGET})

# find_program(VALGRIND "valgrind")
# if(VALGRIND)
# 	set(X "$<TARGET_FILE:test_x509>")
# 	message("VALGRIND      ${VALGRIND}")
# 	message("test_x509     ${X}")
# 	add_test(valgrind_x509 ${VALGRIND} --leak-check=yes ./test_x509)
#     # add_custom_target(valgrind_x509
# 	# 	COMMAND "${VALGRIND}" --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes $<TARGET_FILE:test_x509>
# 	# )
# 	# add_test(valgrind_x509 valgrind_x509 )
# endif()
