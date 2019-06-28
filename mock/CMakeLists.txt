list(APPEND MockPublicHeaders mock_fixtures.h mock_tox.h)

add_library(Mock $<TARGET_OBJECTS:ToxExtObjs> mock_tox.c mock_fixtures.c)

target_include_directories(Mock PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:$<TARGET_PROPERTY:ToxExtObjs,INCLUDE_DIRECTORIES>>
    PRIVATE "${TOXCORE_INCLUDEDIR}")

set_target_properties(Mock PROPERTIES OUTPUT_NAME "toxext_mock")

set_target_properties(
    Mock
    PROPERTIES PUBLIC_HEADER
    "${MockPublicHeaders}")

get_target_property(pubhead Mock PUBLIC_HEADER)

target_include_directories(Mock PRIVATE "${TOXCORE_INCLUDEDIR}")

toxext_install(Mock)
