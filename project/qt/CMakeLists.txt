# cmake -B asset/build -G "Visual Studio 17 2022" -DCMAKE_PREFIX_PATH=your_qtsdk_path
# cmake --build asset/build --config RelWithDebInfo  # crash if link Qt5Cored.dll, so build with release
cmake_minimum_required(VERSION 3.7.0)

project(qttool VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_DEBUG_POSTFIX "")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

find_package(Qt5 COMPONENTS Core REQUIRED)

add_library(version SHARED
    src/qfile_dump.cpp
    src/compat/winversion_v100.def
)
target_include_directories(version PRIVATE src/compat)
target_link_libraries(version Qt5::Core)
if(EXISTS src/compat)
    target_compile_definitions(version PRIVATE USECOMPAT)
endif()