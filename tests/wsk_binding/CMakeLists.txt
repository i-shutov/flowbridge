cmake_minimum_required(VERSION 3.24)
project(FlowBridgeWskBindingSourceTests LANGUAGES CXX)

add_executable(FlowBridgeWskClaimTest test_claim.cpp)
target_compile_features(FlowBridgeWskClaimTest PRIVATE cxx_std_17)

if(MSVC)
  target_compile_options(FlowBridgeWskClaimTest PRIVATE /W4 /WX /wd4505)
else()
  target_compile_options(FlowBridgeWskClaimTest PRIVATE
    -Wall -Wextra -Werror -Wno-unused-function -Wno-missing-field-initializers)
endif()

enable_testing()
add_test(NAME WskKernelAuthoritySourceFixtures COMMAND FlowBridgeWskClaimTest)
