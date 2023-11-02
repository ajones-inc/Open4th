cmake_minimum_required(VERSION 3.15)

add_executable(Open4th_Hello_World Open4th.cpp)

target_include_directories(Open4th_Hello_World
    PUBLIC ${EXTRA_INCLUDE_DIRS}
)

target_link_directories(Open4th_Hello_World
    PUBLIC ${EXTRA_LIB_DIRS}
)

target_link_libraries(Open4th_Hello_World PUBLIC ${EXTRA_LINKS})