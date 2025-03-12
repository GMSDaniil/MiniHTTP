<<<<<<< HEAD
project(untitled) # Der Name unseres Projekts
cmake_minimum_required(VERSION 3.5) # Minimale CMake-Version 3.5
set(CMAKE_C_STANDARD 11) # Wir verwenden C-Version C11
add_executable(webserver webserver.c)
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES ${CMAKE_BINARY_DIR} /\\..*$)
set(CPACK_VERBATIM_VARIABLES YES)
include(CPack)
=======
cmake_minimum_required(VERSION 3.5)
project(RN-Praxis)
set(CMAKE_C_STANDARD 11)

add_executable(webserver webserver.c http.c util.c data.c)
target_compile_options(webserver PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(webserver PRIVATE -lm)

# Packaging
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES ${CMAKE_BINARY_DIR} /\\..*$)
set(CPACK_VERBATIM_VARIABLES YES)
include(CPack)
>>>>>>> master
