include(CTest)
include(Dart)

# I'm sure I could do this better but I don't want to spend my time on cmake really
function(toxext_test test_name)
	add_executable(${test_name} ${ARGN})
	# we use gnu11 for the tests so we can use the container_of macro for inheritance a la linux
	# Force _DEBUG for tests since we use the assert() macro to crash the tests
	target_compile_options(${test_name} PRIVATE -ftest-coverage -fprofile-arcs -D_DEBUG -UNDEBUG)
	#target_link_options(${test_name} PRIVATE -fprofile-arcs -ftest-coverage)
	target_link_libraries(${test_name} gcov Mock)
	target_include_directories(${test_name} PRIVATE ${TOXCORE_INCLUDEDIR})
	add_test(${test_name} ${test_name})
endfunction(toxext_test)

toxext_test(peer_no_extension peer_no_extension.c)
toxext_test(peer_no_toxext peer_no_toxext.c)
toxext_test(peer_sometimes_no_extension peer_sometimes_no_extension.c)
toxext_test(mismatched_extension_ids mismatched_extension_ids.c)
toxext_test(simple_extension_test simple_extension_test.c)
toxext_test(multiple_big_packets multiple_big_packets.c)
