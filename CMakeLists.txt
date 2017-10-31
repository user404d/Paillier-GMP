cmake_minimum_required(VERSION 3.2)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

project(paillier C)

if (MSVC)
	add_compile_options(/W4)
	else()
		add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_library(GMP gmp)
find_library(PTHREAD pthread)

include_directories(/usr/include
                    /usr/local/include)

add_executable(paillier
               src/main.c
               src/paillier.c
               src/paillier_io.c
               src/paillier_manage_keys.c
               src/tools.c)

target_link_libraries(paillier ${GMP} ${PTHREAD})
