# Works with 3.11 and tested through 3.15
cmake_minimum_required(VERSION 3.16)

##
## Project
## name versio
##
##
# Project name and a few useful settings. Other commands can pick up the results
project(CertificateLibrary VERSION 0.1  LANGUAGES CXX)

##
## Includes
##
##

##
## find packages
##
##
find_package(Threads REQUIRED)
find_program(BASH_PROG bash)
message("BASH_PROG-NOTFOUND       ${BASH_PROG-NOTFOUND}")
message("BASH_PROG                ${BASH_PROG}")
## not sure any of these work for the moment so turn them OFF
if(OFF)
find_package(boost)
find_package(openssl)
find_package(trog)
endif()

##
## options
##
option(CERT_BuildTests "Build the tests when enabled" ON )
option(CERT_Install_Targets "Installs targets as well as files if set" OFF)
option(CERT_Package "Install as a CMake package - not implemented" OFF)
option(CERT_Verbose "Print a lot of diagnostic stuff" ON)
option(CERT_DebugBuild "Perform build as type Debug" ON)


## ============================================================================
## The stuff below - I am not sure about ======================================
##

# this is a fix for a problem with boost libraries see https://github.com/Microsoft/vcpkg/issues/4497
# also a hack and breaks "best practices" as per Damiel Pfeiffer's presentation https://www.youtube.com/watch?v=rLopVhns4Zs&feature=youtu.be
set(other_flags "${other_flags} -frtti -fvisibility-inlines-hidden")
set(other_flags "${other_flags} -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${other_flags}")

set(THREADS_PREFER_PTHREAD_FLAG ON)
# Let's nicely support folders in IDE's
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
# allow scheme porperties in xcode - particularly environment variables
set_property(GLOBAL PROPERTY XCODE_GENERATE_SCHEME ON)
set(XCODE_GENERATE_SCHEME ON)
##
## The stuff below - I am not sure about ====================================
## ==========================================================================

##
## Configuration
##
##
include (GNUInstallDirs)

if (CERT_DebugBuild)
	set(CMAKE_BUILD_TYPE Debug)
endif()
set(CMAKE_CXX_STANDARD 14)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)
# set(CMAKE_CXX_EXTENSIONS OFF)
if(DEFINED CMAKE_DL_LIBS)
    set(CERT_DL_LIB_SO libdl.so)
endif()

set(CERT_PROJECT_DIR     ${CertificateLibrary_SOURCE_DIR})
set(CERT_LIBRARY_NAME    "cert_library")

## location of project header and source files
set(CERT_SOURCE_NAME       src)
set(CERT_INCLUDE_NAME      include)
set(CERT_SOURCE_DIR        ${CERT_PROJECT_DIR}/${CERT_SOURCE_NAME})
set(CERT_INCLUDE_DIR       ${CERT_PROJECT_DIR}/${CERT_INCLUDE_NAME})
## location of other/3rd party headers, src and libs
set(CERT_VENDOR_NAME		vendor)
set(CERT_VENDOR_DIR        ${CERT_PROJECT_DIR}/${CERT_VENDOR_NAME})


if(DEFINED STAGE_DIR) 
    message ("building after install stage_dir ${STAGE_DIR}")
    set(VENDOR_DIR ${STAGE_DIR})
    set(CERT_VENDOR_DIR ${STAGE_DIR})
    message("vendor dir  ${VENDOR_DIR}")
    message("cert vendor dir  ${CERT_VENDOR_DIR}")
endif()



set(CERT_VENDOR_INCLUDEDIR ${CERT_VENDOR_DIR}/include)
set(CERT_VENDOR_LIBDIR     ${CERT_VENDOR_DIR}/lib)
set(CERT_VENDOR_SRCDIR     ${CERT_VENDOR_DIR}/src)

## used by all compile steps to find headers
set(CERT_INCLUDE_PATHS 
	${CERT_INCLUDE_DIR}
	# ${CERT_INCLUDE_DIR}
	# ${CERT_SOURCE_DIR}
	${CERT_VENDOR_INCLUDEDIR}
	${CERT_VENDOR_SRCDIR}
)
set(CERT_LINK_LIBRARIES 
	Threads::Threads 
	${CMAKE_DL_LIBS}
	${CERT_VENDOR_LIBDIR}/libboost_filesystem.a 
	${CERT_VENDOR_LIBDIR}/libboost_system.a
	${CERT_VENDOR_LIBDIR}/libboost_program_options.a
	${CERT_VENDOR_LIBDIR}/libssl.a 
	${CERT_VENDOR_LIBDIR}/libcrypto.a 
	${CMAKE_DL_LIBS}
	${DL_LIB_SO}
	)


set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set_property(GLOBAL PROPERTY XCODE_GENERATE_SCHEME ON)

if (CERT_Verbose)
	message("Project Name                    ${CMAKE_PROJECT_NAME}")
	message("Cert Library name               ${CERT_LIBRARY_NAME}")
	message("Build Type                      ${CMAKE_BUILD_TYPE}")
	message("CMAKE_CXX_STANDARD              ${CMAKE_CXX_STANDARD}")
	message("CMAKE_DL_LIBS                   ${CMAKE_DL_LIBS}")
	message("CERT_PROJECT_DIR                ${CERT_PROJECT_DIR}")
	message("CERT_SOURCE_DIR                 ${CERT_SOURCE_DIR}")
	message("CERT_INCLUDE_DIR                ${CERT_INCLUDE_DIR}")
	message("CERT_VENDOR_NAME                ${CERT_VENDOR_NAME}")
	message("CERT_VENOR_DIR                  ${CERT_VENDOR_DIR}")
	message("CERT_VENDOR_INCLUDEDIR          ${CERT_VENDOR_INCLUDEDIR}")
	message("CERT_VENDOR_LIBDIR              ${CERT_VENDOR_LIBDIR}")
	message("CERT_VENDOR_SRCDIR              ${CERT_VENDOR_SRCDIR}")
	message("CERT_VENDOR_SRCDIR              ${CERT_VENDOR_SRCDIR}")
	message("CERT_DL_LIB_SO                  ${CERT_DL_LIB_SO}")
	message("CERT_INCLUDE_PATHS              ${CERT_INCLUDE_PATHS}")
	message("CERT_LINK_LIBRARIES             ${CERT_LINK_LIBRARIES}")
	message("CMAKE_INSTALL_PREFIX            ${CMAKE_INSTALL_PREFIX}")
	message("CMAKE_INSTALL_FULL_INCLUDEDIR   ${CMAKE_INSTALL_FULL_INCLUDEDIR}")
	message("CMAKE_INSTALL_INCLUDEDIR        ${CMAKE_INSTALL_INCLUDEDIR}")
endif()


# set(CERT_LIBRARY_NAME "cert_library")


# set(CMAKE_CXX_STANDARD 14)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)
# set(CMAKE_CXX_EXTENSIONS OFF)

# set_property(GLOBAL PROPERTY USE_FOLDERS ON)

include(CTest) 
enable_testing()


# set(PROJECT_DIR ${CertificateLibrary_SOURCE_DIR})

# # allow the vendor dir to be set on the command line so that the library can be built 
# # in the stage directory during an installation local to a project

# if(NOT DEFINED VENDOR_DIR)
#     set(VENDOR_DIR ${PROJECT_DIR}/vendor)
# endif()

# if(${CMAKE_DL_LIBS})
#     set(DL_LIB_SO libdl.so)
# endif()


# message(Module Path : ${CMAKE_MODULE_PATH})
# set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} /usr/local/Cellar/cmake3.16.3/share/cmake/Modules)

add_subdirectory(src)
add_subdirectory(tests)

##
## Installation
##
##
source_group(headers REGULAR_EXPRESSION include/cert/*.hpp})

set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY true)

install(TARGETS ${CERT_LIBRARY_NAME}
        EXPORT ${CERT_LIBRARY_NAME}
        LIBRARY DESTINATION ${STAGE_DIR}/lib
        ARCHIVE DESTINATION ${STAGE_DIR}/lib
        RUNTIME DESTINATION ${STAGE_DIR}/bin
        PUBLIC_HEADER DESTINATION ${STAGE_DIR}/include
        )

# set(CMAKE_INSTALL_PREFIX ${PROJECT_DIR})
# install(TARGETS ${CERT_LIBRARY_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
install(FILES 
    include/cert/constants.hpp
    include/cert/macros.hpp
    include/cert/error.hpp
    include/cert/version_check.hpp
    include/cert/bio_utes.hpp
    include/cert/cert.hpp
    include/cert/cert_helpers.hpp
    include/cert/cert_evp_pkey.hpp
    include/cert/cert_auth_helper.hpp
    include/cert/cert_identity.hpp
    include/cert/cert_helpers_fs.hpp
    include/cert/cert_authority.hpp
    include/cert/cert_builder.hpp
    include/cert/cert_certificate.hpp
    include/cert/cert_handshaker.hpp
    include/cert/cert_mozilla.hpp
    include/cert/cert_keychain.hpp
    include/cert/cert_store.hpp
    include/cert/cert_store_host.hpp
    include/cert/cert_store_locator.hpp
    include/cert/cert_store_store.hpp
    include/cert/cert_store_types.hpp
    include/cert/x5zero9.hpp
    include/cert/x509.hpp
    include/cert/x509_serial.hpp
    include/cert/x509_time.hpp
    include/cert/x509_pkey.hpp
    include/cert/x509_chain.hpp
    include/cert/x509_cert.hpp
    include/cert/x509_cert_impl.hpp
    include/cert/x509_req.hpp
    include/cert/x509_name.hpp
    include/cert/x509_ext.hpp
    include/cert/x509_nid.hpp
    include/cert/x509_types.hpp
    include/cert/x509_create.hpp
    include/cert/x509_conf.hpp
    include/cert/cert_chain.hpp

    # include/cert/cert_store.hpp
    # include/cert/cert_store_host.hpp
    # include/cert/cert_store_locator.hpp
    # include/cert/cert_store_types.hpp
    # include/cert/cert_store_store.hpp
    # include/cert/cert_mozilla.hpp

    DESTINATION ${STAGE_DIR}/include/cert)


# # Testing -- see the CMakeLists.txt in each of the test directories

