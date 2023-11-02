cmake_minimum_required(VERSION 3.15)

set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_MINSIZEREL
        CMAKE_CXX_FLAGS_RELWITHDEBINFO
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_MINSIZEREL
        CMAKE_C_FLAGS_RELWITHDEBINFO
        )
foreach(CompilerFlag ${CompilerFlags})
    string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
    set(${CompilerFlag} "${${CompilerFlag}}" CACHE STRING "msvc compiler flags" FORCE)
    message("MSVC flags: ${CompilerFlag}:${${CompilerFlag}}")
endforeach()

list(APPEND OPEN4TH_SOURCES "src/TCPTransmitter.cpp" "src/TCPReceiver.cpp" "src/UDPTransmitter.cpp" "src/UDPReceiver.cpp" "src/crypto/Open4th_RSA.cpp" "src/crypto/Open4th_AES.cpp")
list(APPEND OPEN4TH_HEADERS "Open4th.h" "src/PlatformDetection.h" "src/TCPTransmitter.h" "src/TCPReceiver.h" "src/UDPTransmitter.h" "src/UDPReceiver.h" "src/Request.h" "src/crypto/Open4th_RSA.h" "src/crypto/Open4th_AES.h")

add_library(Open4th STATIC ${OPEN4TH_HEADERS} ${OPEN4TH_SOURCES})

target_include_directories(Open4th
    PUBLIC "vendor"
)
target_link_directories(Open4th
    PUBLIC "vendor/cryptopp"
    "vendor/cryptopp/x64/Output"
)
target_link_libraries(Open4th PUBLIC cryptlib)

install(TARGETS Open4th DESTINATION lib)
install(FILES ${OPEN4TH_HEADERS} DESTINATION include)

