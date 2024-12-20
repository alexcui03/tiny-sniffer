#[=======================================================================[.rst:
FindPcap
-----------

Find the libpcap library and its include dir.

Imported Targets
^^^^^^^^^^^^^^^^

This module defines the following :prop_tgt:`IMPORTED` targets:

``Pcap::Pcap``
  The libpcap library.

Result Variables
^^^^^^^^^^^^^^^^

This module defines the following variables:

``PCAP_FOUND``
  True if headers and libraries were found.
``PCAP_VERSION``
  The version of libpcap library which was found.
``PCAP_INCLUDE_DIRS``
  libpcap include directories.
``PCAP_LIBRARIES``
  Libraries needed to link.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``PCAP_INCLUDE_DIR``
  The directory containing ``pcap.h``.
``PCAP_LIBRARY``
  The path to the libpcap library.
``PCAP_LIBRARY_STATIC``
  The path to the libpcap static library.
#]=======================================================================]

find_library(
  PCAP_LIBRARY
  NAMES pcap
)

find_path(
  PCAP_INCLUDE_DIR
  NAMES pcap.h
)

mark_as_advanced(PCAP_INCLUDE_DIR)
mark_as_advanced(PCAP_LIBRARY)

# Extract version number
set(_REGEX_MAJOR "^#[ \\t]*define[ \\t]+PCAP_VERSION_MAJOR[ \\t]+([0-9]+)$")
set(_REGEX_MINOR "^#[ \\t]*define[ \\t]+PCAP_VERSION_MINOR[ \\t]+([0-9]+)$")
if(PCAP_INCLUDE_DIR AND EXISTS "${PCAP_INCLUDE_DIR}/pcap/pcap.h")
  file(STRINGS "${PCAP_INCLUDE_DIR}/pcap/pcap.h" _RESULT REGEX ${_REGEX_MAJOR})
  string(REGEX MATCH ${_REGEX_MAJOR} _MATCH ${_RESULT})
  set(PCAP_VERSION_MAJOR ${CMAKE_MATCH_1})

  file(STRINGS "${PCAP_INCLUDE_DIR}/pcap/pcap.h" _RESULT REGEX ${_REGEX_MINOR})
  string(REGEX MATCH ${_REGEX_MINOR} _MATCH ${_RESULT})
  set(PCAP_VERSION_MINOR ${CMAKE_MATCH_1})

  set(PCAP_VERSION "${PCAP_VERSION_MAJOR}.${PCAP_VERSION_MINOR}")

  unset(_RESULT)
  unset(_MATCH)
else()
  set(PCAP_VERSION_MAJOR 0)
  set(PCAP_VERSION_MINOR 0)
  set(PCAP_VERSION "")
endif()
unset(_REGEX_MAJOR)
unset(_REGEX_MINOR)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  Pcap
  FOUND_VAR PCAP_FOUND
  REQUIRED_VARS PCAP_LIBRARY PCAP_INCLUDE_DIR 
  VERSION_VAR PCAP_VERSION
)

if(PCAP_FOUND)
  set(PCAP_LIBRARIES ${PCAP_LIBRARY})
  set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})

  if(NOT TARGET Pcap::Pcap)
    add_library(Pcap::Pcap UNKNOWN IMPORTED)
    set_target_properties(
      Pcap::Pcap PROPERTIES
      IMPORTED_LOCATION "${PCAP_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
      IMPORTED_LINK_INTERFACE_LANGUAGES "C"
    )
  endif()
endif()
