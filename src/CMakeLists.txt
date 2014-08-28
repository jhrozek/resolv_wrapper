project(libresolv_wrapper C)

include_directories(${CMAKE_BINARY_DIR})
add_library(resolv_wrapper SHARED resolv_wrapper.c)
target_link_libraries(resolv_wrapper ${NWRAP_REQUIRED_LIBRARIES})

set_target_properties(
  resolv_wrapper
    PROPERTIES
      VERSION
        ${LIBRARY_VERSION}
      SOVERSION
        ${LIBRARY_SOVERSION}
)

install(
  TARGETS
    resolv_wrapper
  RUNTIME DESTINATION ${BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)

# This needs to be at the end
if (POLICY CMP0026)
    cmake_policy(SET CMP0026 OLD)
endif()
get_target_property(RWRAP_LOCATION resolv_wrapper LOCATION)
set(RESOLV_WRAPPER_LOCATION ${RWRAP_LOCATION} PARENT_SCOPE)
