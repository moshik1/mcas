cmake_minimum_required (VERSION 3.5.1 FATAL_ERROR)

project(component-hstore CXX)

include(${CMAKE_SOURCE_DIR}/mk/avoid_boost_type_to_string_bug.cmake)

add_compile_options("$<$<CONFIG:Debug>:-O0>")

add_subdirectory(./unit_test)

add_definitions(-DCONFIG_DEBUG) # P{LOG,DEG,INF,WRN,ERR} control
add_definitions(-DDM_REGION_LOG_GRAIN_SIZE=${DM_REGION_LOG_GRAIN_SIZE})

set(SOURCES
	src/allocator_cc.cpp
	src/allocator_co.cpp
	src/alloc_key.cpp
	src/allocator_rc.cpp
	src/as_pin.cpp
	src/atomic_controller.cpp
	src/bad_alloc_cc.cpp
	src/bits_to_ints.cpp
	src/bucket_aligned.cpp
	src/bucket_control_unlocked.cpp
	src/cond_print.cpp
	src/construction_mode.cpp
	src/content.cpp
	src/cptr.cpp
	src/dummy_shared_mutex.cpp
	src/fixed_string.cpp
	src/hash_bucket.cpp
	src/heap_co.cpp
	src/heap_access.cpp
	src/histogram_log2.cpp
	src/hop_hash_debug.cpp
	src/hstore_alloc_type.cpp
	src/hstore_config.cpp
	src/hstore_kv_types.cpp
	src/hstore_nupm.cpp
	src/hstore_nupm_types.cpp
	src/hstore_open_pool.cpp
	src/is_locked.cpp
	src/key_not_found.cpp
	src/logging.cpp
	src/mod_control.cpp
	src/monitor_emplace.cpp
	src/monitor_pin.cpp
	src/persist_fixed_string.cpp
	src/persist_map.cpp
	src/pobj_bad_alloc.cpp
	src/persist_atomic.cpp
	src/persist_controller.cpp
	src/persist_data.cpp
	src/persistent.cpp
	src/persister_cc.cpp
	src/persister_nupm.cpp
	src/pointer_pobj.cpp
	src/pool_path.cpp
	src/pool_pobj.cpp
	src/pool_manager.cpp
	src/pstr_equal.cpp
	src/pstr_hash.cpp
	src/region.cpp
	src/rc_alloc_wrapper_lb.cpp
	src/segment_and_bucket.cpp
	src/segment_count.cpp
	src/segment_layout.cpp
	src/store_root.cpp
	src/test_flags.cpp
	src/trace_flags.cpp
	src/value_unstable.cpp

	src/as_emplace.cpp
	src/as_extend.cpp
	src/dax_manager.cpp
	src/heap_cc.cpp
	src/heap_cc_ephemeral.cpp
	src/heap_rc.cpp
	src/heap_rc_ephemeral.cpp
	src/hop_hash_log.cpp
	src/hstore.cpp
	src/hstore_factory.cpp
	src/hop_hash.cpp
	src/owner.cpp
	src/perishable.cpp
	src/perishable_expiry.cpp
	src/session.cpp
	src/tracked_header.cpp
)

#add_custom_target(format-hstore
#  COMMAND /usr/bin/clang-format
#  -style=file
#  -i
#  ${ALL_SOURCES})

# if(TEST_HSTORE_PERISHABLE)
#  add_compile_options(-DTEST_HSTORE_PERISHABLE=1)
# endif()

get_property(incdirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)
set(sysincludes "-I/usr/include/c++/5 -I/usr/include/x86_64-linux-gnu/c++/5/ -I/usr/include/linux")
# add -I prefix
string(REGEX REPLACE "([^;]+)" "-I\\1" istring "${incdirs}")

include_directories(${CMAKE_SOURCE_DIR}/src/components)
include_directories(${CMAKE_SOURCE_DIR}/src/components/api)
include_directories(${CMAKE_SOURCE_DIR}/src/lib/libpmem/include)
include_directories(${CMAKE_SOURCE_DIR}/src/lib/libnupm/include)
include_directories(${CMAKE_SOURCE_DIR}/src/lib/common/include)
include_directories(${CMAKE_SOURCE_DIR}/src/lib/libccpm/include)
#include_directories(${CMAKE_SOURCE_DIR}/src/lib/cityhash/cityhash/src)
include_directories(${CMAKE_INSTALL_PREFIX}/include)
include_directories(../../)

link_directories(${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}) # cityhash tbb tbbmalloc
link_directories(${CMAKE_INSTALL_PREFIX}/lib) # cityhash tbb tbbmalloc

set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--no-undefined")

# common version
add_library(${PROJECT_NAME} SHARED ${SOURCES})
target_compile_options(${PROJECT_NAME} PUBLIC "-fPIC" "$<$<BOOL:${TEST_HSTORE_PERISHABLE}>:-DMCAS_HSTORE_TEST_PERISHABLE=1>")
target_link_libraries(${PROJECT_NAME} common pthread numa dl rt boost_system boost_filesystem tbb nupm cityhash ccpm gcov)
add_dependencies(${PROJECT_NAME} common nupm)
set_target_properties(${PROJECT_NAME} PROPERTIES INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}:${CMAKE_INSTALL_PREFIX}/lib)

# no timestamp version
add_library(${PROJECT_NAME}-nt SHARED ${SOURCES})
target_compile_options(${PROJECT_NAME}-nt PUBLIC "-fPIC" "$<$<BOOL:${TEST_HSTORE_PERISHABLE}>:-DMCAS_HSTORE_TEST_PERISHABLE=1>" "-DENABLE_TIMESTAMP=0")
target_link_libraries(${PROJECT_NAME}-nt common pthread numa dl rt boost_system boost_filesystem tbb nupm cityhash ccpm)
add_dependencies(${PROJECT_NAME}-nt common nupm)
set_target_properties(${PROJECT_NAME}-nt PROPERTIES INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}:${CMAKE_INSTALL_PREFIX}/lib)

# crash-consistent allocator version
add_library(${PROJECT_NAME}-cc SHARED ${SOURCES})
target_compile_options(${PROJECT_NAME}-cc PUBLIC "-fPIC" "$<$<BOOL:${TEST_HSTORE_PERISHABLE}>:-DMCAS_HSTORE_TEST_PERISHABLE=1>" "-DMCAS_HSTORE_USE_CC_HEAP=4")
target_link_libraries(${PROJECT_NAME}-cc common pthread numa dl rt boost_system boost_filesystem tbb nupm cityhash ccpm)
add_dependencies(${PROJECT_NAME}-cc common nupm)
set_target_properties(${PROJECT_NAME}-cc PROPERTIES INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}:${CMAKE_INSTALL_PREFIX}/lib)

# crash-consistent with perishable expiry
add_library(${PROJECT_NAME}-cc-pe SHARED ${SOURCES})
target_compile_options(${PROJECT_NAME}-cc-pe PUBLIC "-fPIC" "-DMCAS_HSTORE_TEST_PERISHABLE=1" "-DMCAS_HSTORE_USE_CC_HEAP=4")
target_link_libraries(${PROJECT_NAME}-cc-pe common pthread numa dl rt boost_system boost_filesystem tbb nupm cityhash ccpm)
add_dependencies(${PROJECT_NAME}-cc-pe common nupm)
set_target_properties(${PROJECT_NAME}-cc-pe PROPERTIES INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}:${CMAKE_INSTALL_PREFIX}/lib)

# test that all trace options compile
add_library(${PROJECT_NAME}-cc-pe-tr SHARED ${SOURCES})
target_compile_options(${PROJECT_NAME}-cc-pe-tr PUBLIC "-fPIC" "-DMCAS_HSTORE_TEST_PERISHABLE=1" "-DMCAS_HSTORE_USE_CC_HEAP=4" "-DHSTORE_TRACE_ALL=1")
target_link_libraries(${PROJECT_NAME}-cc-pe-tr common pthread numa dl rt boost_system boost_filesystem tbb nupm cityhash ccpm)
add_dependencies(${PROJECT_NAME}-cc-pe-tr common nupm)
set_target_properties(${PROJECT_NAME}-cc-pe-tr PROPERTIES INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}:${CMAKE_INSTALL_PREFIX}/lib)



install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION lib)
install(TARGETS ${PROJECT_NAME}-nt LIBRARY DESTINATION lib)
install(TARGETS ${PROJECT_NAME}-cc LIBRARY DESTINATION lib)
install(TARGETS ${PROJECT_NAME}-cc-pe LIBRARY DESTINATION lib)
install(TARGETS ${PROJECT_NAME}-cc-pe-tr LIBRARY DESTINATION lib)
