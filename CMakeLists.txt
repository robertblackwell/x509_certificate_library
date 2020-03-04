# Works with 3.11 and tested through 3.15
cmake_minimum_required(VERSION 3.11...3.16)

set(THISFILE_DEBUG 0)

# Project name and a few useful settings. Other commands can pick up the results
project(CertificateLibrary
    VERSION 0.1
    DESCRIPTION "A library for making ssl X509 certificates for a MITM proxy that desires inspects the content "
    LANGUAGES CXX)


# this is a fix for a problem with boost libraries see https://github.com/Microsoft/vcpkg/issues/4497
# also a hack and breaks "best practices" as per Damiel Pfeiffer's presentation https://www.youtube.com/watch?v=rLopVhns4Zs&feature=youtu.be
set(other_flags "${other_flags} -frtti -fvisibility-inlines-hidden")
set(other_flags "${other_flags} -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${other_flags}")

set(CERT_LIBRARY_NAME "cert_library")

# Only do these if this is the main project, and not if it is included through add_subdirectory
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)

    # Optionally set things like CMAKE_CXX_STANDARD, CMAKE_POSITION_INDEPENDENT_CODE here
    # Let's ensure -std=c++xx instead of -std=g++xx
    set(CMAKE_CXX_EXTENSIONS OFF)

    # Let's nicely support folders in IDE's
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)

    include(CTest) 
    enable_testing()

endif()

set(PROJECT_DIR ${CertificateLibrary_SOURCE_DIR})

# allow the vendor dir to be set on the command line so that the library can be built 
# in the stage directory during an installation local to a project

if(NOT DEFINED VENDOR_DIR)
    set(VENDOR_DIR ${PROJECT_DIR}/vendor)
endif()

message(Module Path : ${CMAKE_MODULE_PATH})
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} /usr/local/Cellar/cmake3.16.3/share/cmake/Modules)

add_subdirectory(src)
add_subdirectory(tests)
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
    include/cert/cert_keychain.hpp
    include/cert/cert_helpers_fs.hpp
    include/cert/cert_authority.hpp
    include/cert/x5zero9.hpp
    include/cert/cert_builder.hpp
    include/cert/cert_certificate.hpp
    include/cert/cert_handshaker.hpp
    include/cert_mozilla.hpp
    include/cert_keychain.hpp
    include/cert_store.hpp
    include/cert_store_host.hpp
    include/cert_store_locator.hpp
    include/cert_store_types.hpp

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

