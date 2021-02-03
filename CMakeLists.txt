project(toxext)
cmake_minimum_required(VERSION 2.8.12)

set(INSTALL_MOCKS CACHE BOOL OFF)

add_compile_options(-Wall -Wextra -Werror -std=gnu11)

find_package(PkgConfig REQUIRED)
pkg_search_module(TOXCORE REQUIRED toxcore)

function(toxext_install target)
    install(TARGETS ${target} EXPORT ToxExtConfig ARCHIVE DESTINATION lib PUBLIC_HEADER DESTINATION include/toxext)
endfunction()

add_subdirectory(src)
add_subdirectory(mock)

enable_testing()
add_subdirectory(test)

install(EXPORT ToxExtConfig DESTINATION lib/cmake/ToxExt NAMESPACE ToxExt::)
