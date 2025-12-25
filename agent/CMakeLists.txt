cmake_minimum_required(VERSION 3.18)

project(MicroSentinelAgent LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable debug symbols for C and C++ builds
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)

set(MS_HAVE_LIBBPF OFF)
set(MS_AGENT_INCLUDE_DIRS "")
set(MS_AGENT_LIBS Threads::Threads)
set(MS_BPF_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../bpf)

set(MS_LIBBPF_ROOT $ENV{LIBBPF_ROOT})
if(NOT MS_LIBBPF_ROOT)
    set(MS_LIBBPF_ROOT "/home/hjjiang/tools/libbpf")
endif()
set(MS_LIBBPF_SYSROOT "${MS_LIBBPF_ROOT}/src/build/root")
set(MS_LIBBPF_STAGE_PREFIX "${MS_LIBBPF_SYSROOT}/usr")
set(MS_LIBBPF_STAGE_INCLUDE "${MS_LIBBPF_STAGE_PREFIX}/include")
set(MS_LIBBPF_STAGE_INCLUDE_BPF "${MS_LIBBPF_STAGE_INCLUDE}/bpf")
set(MS_LIBBPF_STAGE_LIB "${MS_LIBBPF_STAGE_PREFIX}/lib64/libbpf.so")

if(EXISTS "${MS_LIBBPF_STAGE_LIB}")
    set(MS_HAVE_LIBBPF ON)
    list(APPEND MS_AGENT_INCLUDE_DIRS
        "${MS_LIBBPF_STAGE_INCLUDE}"
        "${MS_LIBBPF_STAGE_INCLUDE_BPF}"
    )
    list(APPEND MS_AGENT_LIBS "${MS_LIBBPF_STAGE_LIB}" elf z)
endif()

if(NOT MS_HAVE_LIBBPF)
    set(MS_LIBBPF_PKGCONFIG "${MS_LIBBPF_ROOT}/src/build/root/usr/lib64/pkgconfig")
    if(EXISTS "${MS_LIBBPF_PKGCONFIG}/libbpf.pc")
        if(DEFINED ENV{PKG_CONFIG_PATH} AND NOT "$ENV{PKG_CONFIG_PATH}" STREQUAL "")
            set(ENV{PKG_CONFIG_PATH} "${MS_LIBBPF_PKGCONFIG}:$ENV{PKG_CONFIG_PATH}")
        else()
            set(ENV{PKG_CONFIG_PATH} "${MS_LIBBPF_PKGCONFIG}")
        endif()
        set(ENV{PKG_CONFIG_SYSROOT_DIR} "${MS_LIBBPF_SYSROOT}")
    endif()

    if(PkgConfig_FOUND)
        pkg_check_modules(LIBBPF QUIET libbpf>=1.3)
        if(LIBBPF_FOUND)
            pkg_check_modules(LIBELF QUIET libelf)
            find_package(ZLIB QUIET)
            set(MS_HAVE_LIBBPF ON)
            if(LIBBPF_INCLUDE_DIRS)
                list(APPEND MS_AGENT_INCLUDE_DIRS ${LIBBPF_INCLUDE_DIRS})
            endif()
            list(APPEND MS_AGENT_LIBS ${LIBBPF_LIBRARIES})
            if(LIBELF_FOUND)
                list(APPEND MS_AGENT_LIBS ${LIBELF_LIBRARIES})
            else()
                list(APPEND MS_AGENT_LIBS elf)
            endif()
            if(ZLIB_FOUND)
                list(APPEND MS_AGENT_LIBS ZLIB::ZLIB)
            else()
                list(APPEND MS_AGENT_LIBS z)
            endif()
        endif()
    endif()
endif()

if(NOT MS_HAVE_LIBBPF)
    message(WARNING "libbpf not found; building agent in mock mode")
endif()
set(AGENT_CORE_SOURCES
    src/bpf_orchestrator.cpp
    src/runtime.cpp
    src/perf_consumer.cpp
    src/aggregator.cpp
    src/skew_adjuster.cpp
    src/monitoring_targets.cpp
    src/symbolizer.cpp
    src/fs_detector.cpp
    src/remote_dram_analyzer.cpp
    src/mode_controller.cpp
    src/pmu_rotator.cpp
    src/metrics_exporter.cpp
    src/clickhouse_sink.cpp
    src/config_loader.cpp
    src/control_plane.cpp
    src/interference.cpp
    src/bucket_update.cpp
    src/anomaly_monitor.cpp
    src/tsc_calibrator.cpp
    src/json.cpp
)

add_library(ms_agent_core OBJECT ${AGENT_CORE_SOURCES})

set_target_properties(ms_agent_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(ms_agent_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MS_BPF_DIR}
    ${MS_AGENT_INCLUDE_DIRS}
)

target_compile_definitions(ms_agent_core PRIVATE MS_AGENT_LIB)

if(MS_HAVE_LIBBPF)
    target_compile_definitions(ms_agent_core PRIVATE MS_WITH_LIBBPF)
endif()

target_link_libraries(ms_agent_core PRIVATE ${MS_AGENT_LIBS})

add_executable(micro_sentinel_agent src/main.cpp $<TARGET_OBJECTS:ms_agent_core>)

target_include_directories(micro_sentinel_agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MS_BPF_DIR}
    ${MS_AGENT_INCLUDE_DIRS}
)

if(MS_HAVE_LIBBPF)
    target_compile_definitions(micro_sentinel_agent PRIVATE MS_WITH_LIBBPF)
endif()

target_link_libraries(micro_sentinel_agent PRIVATE ${MS_AGENT_LIBS})

add_executable(ms_agent_tests
    tests/test_token_bucket.cpp
    tests/test_json.cpp
    tests/test_skew_adjuster.cpp
    tests/test_monitoring_targets.cpp
    $<TARGET_OBJECTS:ms_agent_core>)

target_include_directories(ms_agent_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MS_BPF_DIR}
    ${MS_AGENT_INCLUDE_DIRS}
)

if(MS_HAVE_LIBBPF)
    target_compile_definitions(ms_agent_tests PRIVATE MS_WITH_LIBBPF)
endif()

target_link_libraries(ms_agent_tests PRIVATE ${MS_AGENT_LIBS})

include(CTest)
add_test(NAME TokenBucket COMMAND ms_agent_tests)
