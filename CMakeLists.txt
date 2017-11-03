cmake_minimum_required(VERSION 3.2)

set(default_build_type "Release")
if(EXISTS "${CMAKE_SOURCE_DIR}/.git")
  set(default_build_type "Debug")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
    STRING "Choose the type of build." FORCE)
# Set the possible values of build type for cmake-gui
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
  "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(paillier CXX)

if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_library(GMP gmp)
find_library(GMPXX gmpxx)

include_directories(/usr/local/include include src)

add_library(paillier SHARED
            src/impl.cpp
            src/io.cpp
            src/secure_dot_product.cpp
            src/tools.cpp)
target_link_libraries(paillier ${GMP} ${GMPXX})
set_target_properties(paillier PROPERTIES
                      LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

add_executable(secure_dot_product
               example/main.cpp)
target_link_libraries(secure_dot_product paillier)
set_target_properties(secure_dot_product PROPERTIES
                      RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

enable_testing()

add_executable(add test/add.cpp)
target_link_libraries(add paillier)

add_executable(mult test/mult.cpp)
target_link_libraries(mult paillier)
add_test(Tester add)
add_test(Tester mult)
