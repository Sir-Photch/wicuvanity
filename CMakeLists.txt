cmake_minimum_required(VERSION 3.10)

project(wicuvanity LANGUAGES CXX CUDA)

set(CMAKE_CXX_STANDARD 20)

add_executable(${PROJECT_NAME} main.cu)

set_property(TARGET ${PROJECT_NAME} PROPERTY CUDA_ARCHITECTURES native)
#set cuda optimization options
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -Xptxas -O3,-v")

#link against curand
find_package(CUDAToolkit REQUIRED)
find_package(cxxopts REQUIRED)
target_link_libraries(${PROJECT_NAME} CUDA::curand)
