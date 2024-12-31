add_executable(test-ip-reassemble ip-reassemble.cpp)
target_link_libraries(test-ip-reassemble PRIVATE tiny-sniffer-core)
