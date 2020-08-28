list(APPEND ToxExtPublicHeaders toxext.h)
list(APPEND ToxExtPrivateHeaders toxext_util.h)

add_library(ToxExtObjs OBJECT toxext.c)
target_include_directories(ToxExtObjs PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    ${TOXCORE_INCLUDEDIR})

set_target_properties(ToxExtObjs PROPERTIES PUBLIC_HEADER "${ToxExtPublicHeaders}")
set_target_properties(ToxExtObjs PROPERTIES PRIVATE_HEADER "${ToxExtPrivateHeaders}")

add_library(ToxExt $<TARGET_OBJECTS:ToxExtObjs>)
target_link_libraries(ToxExt PUBLIC ${TOXCORE_STATIC_LIBRARIES})
target_include_directories(ToxExt PUBLIC "$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/include>;${TOXCORE_INCLUDEDIR}")
set_target_properties(ToxExt PROPERTIES PUBLIC_HEADER "${ToxExtPublicHeaders}")
set_target_properties(ToxExt PROPERTIES PRIVATE_HEADER "${ToxExtPrivateHeaders}")
set_target_properties(ToxExt PROPERTIES OUTPUT_NAME "toxext")

toxext_install(ToxExt)
