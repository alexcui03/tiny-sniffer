cmake_minimum_required(VERSION 3.5)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(PROJECT_SOURCES
    ListenerWorker.cpp
    MainWindow.cpp
    main.cpp
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(tiny-sniffer-gui MANUAL_FINALIZATION ${PROJECT_SOURCES})
else()
    add_executable(tiny-sniffer-gui ${PROJECT_SOURCES})
endif()

target_link_libraries(tiny-sniffer-gui PRIVATE tiny-sniffer-core Qt${QT_VERSION_MAJOR}::Widgets)

include(GNUInstallDirs)
install(TARGETS tiny-sniffer-gui
    BUNDLE DESTINATION .
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

if(${QT_VERSION_MAJOR} EQUAL 6)
    qt_finalize_executable(tiny-sniffer-gui)
endif()
