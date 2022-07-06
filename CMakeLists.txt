cmake_minimum_required(VERSION 3.22)

project(msquic_h3)

find_path(MSQUIC_PATH msquic.h REQUIRED)
find_library(MSQUIC_LIBRARY NAMES msquic REQUIRED)

include_directories(${MSQUIC_PATH})

# Configure and build ls-qpack dependency.
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
option(LSQPACK_TESTS "Build tests" OFF)
option(LSQPACK_BIN "Build binaries" OFF)
add_subdirectory(ls-qpack)

add_executable(h3_client h3_client.cpp)
target_link_libraries(h3_client PRIVATE ${MSQUIC_LIBRARY} ls-qpack)
if (WIN32)
    find_file(MSQUIC_DLL NAMES msquic.dll)
    if (NOT MSQUIC_DLL STREQUAL "MSQUIC_DLL-NOTFOUND")
        add_custom_command(
            TARGET h3_client POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${MSQUIC_DLL} $<TARGET_FILE_DIR:h3_client>
            VERBATIM)
    endif()
endif()
