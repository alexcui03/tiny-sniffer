cmake_minimum_required(VERSION 3.5)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(PROJECT_SOURCES
    MainWindow.hpp
    MainWindow.cpp
    main.cpp
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(tiny-sniffer-gui MANUAL_FINALIZATION ${PROJECT_SOURCES})
else()
    add_executable(tiny-sniffer-gui ${PROJECT_SOURCES})
endif()

target_link_libraries(tiny-sniffer-gui PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

if(${QT_VERSION_MAJOR} EQUAL 6)
    qt_finalize_executable(tiny-sniffer-gui)
endif()
