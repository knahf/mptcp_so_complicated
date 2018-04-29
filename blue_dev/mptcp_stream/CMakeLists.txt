cmake_minimum_required ( VERSION 2.8.11 )
project ( mptcp_stream CXX )

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
    set (
        CMAKE_SHARED_LINKER_FLAGS
        "${CMAKE_SHARED_LINKER_FLAGS} -undefined dynamic_lookup"
    )
endif ( APPLE )

add_subdirectory(proto)
include_directories(${CMAKE_CURRENT_BINARY_DIR} "/home/testuser/snort3/src")

set(CMAKE_INSTALL_PREFIX "/home/testuser/snort_bin/")
include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    mptcp_stream SHARED
        mptcp_stream.cc
)



TARGET_LINK_LIBRARIES(mptcp_stream proto ${PROTOBUF_LIBRARY} ${SNORT3_LIBRARY})


set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fPIC" )

target_include_directories (
    mptcp_stream PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS mptcp_stream
    LIBRARY DESTINATION "lib/${CMAKE_PROJECT_NAME}/inspectors"
)
