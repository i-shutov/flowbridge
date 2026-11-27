cmake_minimum_required(VERSION 3.24)
project(FlowBridgeWskBindingSourceTests LANGUAGES CXX)

add_executable(FlowBridgeWskClaimTest test_claim.cpp)
add_executable(FlowBridgeWskLifecycleTest test_lifecycle.cpp)
add_executable(FlowBridgeWskOwnerTest test_owner.cpp)

foreach(target IN ITEMS FlowBridgeWskClaimTest FlowBridgeWskLifecycleTest FlowBridgeWskOwnerTest)
  target_compile_features(${target} PRIVATE cxx_std_17)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX /wd4505)
  else()
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Werror -Wno-unused-function -Wno-missing-field-initializers)
  endif()
endforeach()

enable_testing()
add_test(NAME WskKernelAuthoritySourceFixtures COMMAND FlowBridgeWskClaimTest)
add_test(NAME WskLifecycleSourceFixtures COMMAND FlowBridgeWskLifecycleTest)
add_test(NAME WskOwnerRundownSourceFixtures COMMAND FlowBridgeWskOwnerTest)
