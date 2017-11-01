cmake_minimum_required(VERSION 3.2)

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

include_directories(/usr/local/include)

add_executable(paillier
               src/io.cpp
               src/main.cpp
               src/paillier.cpp
               src/secure_dot_product.cpp
               src/tools.cpp)

target_link_libraries(paillier ${GMP} ${GMPXX})
