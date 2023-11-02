cmake_minimum_required(VERSION 3.15)

project(Open4th VERSION 1.1)

#           DOWNLOAD ALL THE SUBMODULES
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
# Update submodules as needed
    option(GIT_SUBMODULE "Check submodules during build" ON)
    if(GIT_SUBMODULE)
        message(STATUS "Submodule update")
        execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
                        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                        RESULT_VARIABLE GIT_SUBMOD_RESULT)
        if(NOT GIT_SUBMOD_RESULT EQUAL "0")
            message(FATAL_ERROR "git submodule update --init failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
        endif()
    endif()
endif()


add_subdirectory(Open4th)
list(APPEND EXTRA_LIB_DIRS "Open4th")
list(APPEND EXTRA_INCLUDE_DIRS "Open4th" "Open4th/Debug")
list(APPEND EXTRA_LINKS Open4th)

add_subdirectory(Open4th/examples)

configure_file(Open4thConfig.h.in Open4thConfig.h)

install(FILES "${PROJECT_BINARY_DIR}/Open4thConfig.h" DESTINATION include)

include(InstallRequiredSystemLibraries)
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION_MAJOR "${OPEN4TH_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${OPEN4TH_VERSION_MINOR}")
include(CPack)