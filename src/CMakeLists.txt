cmake_minimum_required(VERSION 3.10)

project(ratelimit)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_INSTALL_PREFIX "/ratelimit")

set(SOURCE_FILES 
    ratelimit_user.c
    main.c
)

add_executable(ratelimit ${SOURCE_FILES})
target_link_libraries(ratelimit bpf)

install(TARGETS ratelimit
    RUNTIME DESTINATION bin)
install(FILES ratelimit.sh
    DESTINATION bin PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
install(FILES ratelimit_kern.o
    DESTINATION bin)