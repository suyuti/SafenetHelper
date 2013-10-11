# - Try to find Cryptoki
# Once done, this will define
#
#  Cryptoki_FOUND - system has Cryptoki
#  Cryptoki_INCLUDE_DIRS - the Cryptoki include directories
#  Cryptoki_LIBRARIES - link these to use Cryptoki

#include(LibFindMacros)

# Dependencies
#libfind_package(Cryptoki GObject)

# Use pkg-config to get hints about paths
#libfind_pkg_check_modules(Cryptoki_PKGCONF Cryptoki)

# Main include dir
set(Cryptoki_INCLUDE_DIR /opt/ETcpsdk/include)
#find_path(Cryptoki_INCLUDE_DIR
#  NAMES  /opt/ETcpsdk/include
#  PATHS ${Atk_PKGCONF_INCLUDE_DIRS}
#  PATH_SUFFIXES atk-1.0
#)

# Find the library
LINK_DIRECTORIES(/opt/PTK/lib)
#set(Cryptoki_LIBRARY /opt/PTK/lib/libcryptoki)
#find_library(Cryptoki_LIBRARY
#  NAMES atk-1.0
#  PATHS ${Atk_PKGCONF_LIBRARY_DIRS}
#)

# Set the include dir variables and the libraries and let libfind_process do the rest.
# NOTE: Singular variables for this library, plural for libraries this this lib depends on.
#set(Cryptoki_PROCESS_INCLUDES Cryptoki_INCLUDE_DIR)
#set(Cryptoki_PROCESS_LIBS Cryptoki_LIBRARY GObject_LIBRARIES)
#libfind_process(Cryptoki)
