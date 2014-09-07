project(tests C)

include_directories(
  ${CMAKE_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/src
  ${CMOCKA_INCLUDE_DIR}
)

set(TESTSUITE_LIBRARIES ${RWRAP_REQUIRED_LIBRARIES} ${CMOCKA_LIBRARY})
if (HAVE_LIBRESOLV)
    set(TESTSUITE_LIBRARIES ${TESTSUITE_LIBRARIES} resolv)
endif()

set(RWRAP_TESTS
    test_res_init)

foreach(_RWRAP_TEST ${RWRAP_TESTS})
    add_cmocka_test(${_RWRAP_TEST} ${_RWRAP_TEST}.c ${TESTSUITE_LIBRARIES})

    if (OSX)
        set_property(
            TEST
                ${_RWRAP_TEST}
            PROPERTY
                ENVIRONMENT DYLD_FORCE_FLAT_NAMESPACE=1;DYLD_INSERT_LIBRARIES=${RESOLV_WRAPPER_LOCATION})
    else ()
        set_property(
            TEST
                ${_RWRAP_TEST}
            PROPERTY
                ENVIRONMENT LD_PRELOAD=${RESOLV_WRAPPER_LOCATION})
    endif()
endforeach()
