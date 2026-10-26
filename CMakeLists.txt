cmake_minimum_required(VERSION 3.20)
project(p2p-overlay
    VERSION 0.1.0
    LANGUAGES CXX
    DESCRIPTION "Secure decentralized P2P overlay network with Kademlia DHT"
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─── Dependencies ─────────────────────────────────────────────────────
find_package(asio CONFIG QUIET)
if(NOT asio_FOUND)
    # Standalone Asio fallback
    find_path(ASIO_INCLUDE_DIR asio.hpp)
    if(ASIO_INCLUDE_DIR)
        add_library(asio::asio INTERFACE IMPORTED)
        target_include_directories(asio::asio INTERFACE ${ASIO_INCLUDE_DIR})
        target_compile_definitions(asio::asio INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED)
        if(WIN32)
            target_link_libraries(asio::asio INTERFACE ws2_32 mswsock)
        endif()
    else()
        message(FATAL_ERROR "Asio not found. Install via vcpkg: vcpkg install asio")
    endif()
endif()

find_package(unofficial-sodium CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(tomlplusplus CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)

# ─── Main library (all node logic) ───────────────────────────────────
add_library(p2p_core STATIC
    # Common
    src/common/types.hpp

    # Transport
    src/transport/message_types.hpp
    src/transport/frame.hpp
    src/transport/frame.cpp
    src/transport/tcp_connection.hpp
    src/transport/tcp_connection.cpp
    src/transport/tcp_listener.hpp
    src/transport/tcp_listener.cpp

    # Identity
    src/identity/node_id.hpp
    src/identity/node_id.cpp
    src/identity/keypair.hpp
    src/identity/keypair.cpp

    # Config
    src/config/config.hpp
    src/config/config.cpp

    # DHT
    src/dht/k_bucket.hpp
    src/dht/k_bucket.cpp
    src/dht/routing_table.hpp
    src/dht/routing_table.cpp
    src/dht/dht_messages.hpp
    src/dht/dht_messages.cpp
    src/dht/lookup_engine.hpp
    src/dht/lookup_engine.cpp
    src/dht/node_record.hpp
    src/dht/node_record.cpp
    src/dht/record_store.hpp
    src/dht/record_store.cpp

    # Security (Stage 4)
    src/security/crypto_utils.hpp
    src/security/crypto_utils.cpp
    src/security/ake_messages.hpp
    src/security/ake_messages.cpp
    src/security/replay_cache.hpp
    src/security/replay_cache.cpp
    src/security/secure_session.hpp
    src/security/secure_session.cpp

    # Node
    src/node.hpp
    src/node.cpp
)

target_include_directories(p2p_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(p2p_core PUBLIC ASIO_STANDALONE ASIO_NO_DEPRECATED)

if(WIN32)
    target_compile_definitions(p2p_core PUBLIC _WIN32_WINNT=0x0A00)
endif()

target_link_libraries(p2p_core PUBLIC
    asio::asio
    unofficial-sodium::sodium
    nlohmann_json::nlohmann_json
    tomlplusplus::tomlplusplus
    spdlog::spdlog
)

if(WIN32)
    target_link_libraries(p2p_core PUBLIC ws2_32 mswsock)
endif()

# ─── Main executable ─────────────────────────────────────────────────
add_executable(p2p_node src/main.cpp)
target_link_libraries(p2p_node PRIVATE p2p_core)

# ─── Tests ────────────────────────────────────────────────────────────
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    enable_testing()
    find_package(Catch2 CONFIG REQUIRED)

    add_executable(test_frame tests/unit/test_frame.cpp)
    target_link_libraries(test_frame PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_frame COMMAND test_frame)

    add_executable(test_node_id tests/unit/test_node_id.cpp)
    target_link_libraries(test_node_id PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_node_id COMMAND test_node_id)

    add_executable(test_k_bucket tests/unit/test_k_bucket.cpp)
    target_link_libraries(test_k_bucket PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_k_bucket COMMAND test_k_bucket)

    add_executable(test_routing_table tests/unit/test_routing_table.cpp)
    target_link_libraries(test_routing_table PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_routing_table COMMAND test_routing_table)

    add_executable(test_lookup tests/unit/test_lookup.cpp)
    target_link_libraries(test_lookup PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_lookup COMMAND test_lookup)

    # E2-4: LRU eviction scenarios (live vs dead contact)
    add_executable(test_lru_scenarios tests/unit/test_lru_scenarios.cpp)
    target_link_libraries(test_lru_scenarios PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_lru_scenarios COMMAND test_lru_scenarios)

    # E2-2: Negative identity tests (key tampering and spoofing)
    add_executable(test_negative_identity tests/negative/test_negative_identity.cpp)
    target_link_libraries(test_negative_identity PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_negative_identity COMMAND test_negative_identity)

    # E2-5 & E2-7: Integration tests (FIND_NODE RPC correlation and 5-node cluster)
    add_executable(test_dht_integration tests/integration/test_dht_integration.cpp)
    target_link_libraries(test_dht_integration PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_dht_integration COMMAND test_dht_integration)

    # E1-6 & E1-7: Negative transport tests (protocol violation, oversized, abrupt disconnect, unsolicited PONG)
    add_executable(test_negative_transport tests/negative/test_negative_transport.cpp)
    target_link_libraries(test_negative_transport PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_negative_transport COMMAND test_negative_transport)

    # Stage 3: E3-1, E3-2, E3-8 NodeRecord unit & negative tests
    add_executable(test_node_record tests/unit/test_node_record.cpp)
    target_link_libraries(test_node_record PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_node_record COMMAND test_node_record)

    # Stage 3: E3-2, E3-6, E3-7 RecordStore local storage, anti-rollback & TTL purge tests
    add_executable(test_record_store tests/unit/test_record_store.cpp)
    target_link_libraries(test_record_store PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_record_store COMMAND test_record_store)

    # Stage 3: E3-3, E3-4, E3-5, E3-8 DHT storage cluster integration test (STORE, replication, keeper failure, FIND_VALUE)
    add_executable(test_dht_storage tests/integration/test_dht_storage.cpp)
    target_link_libraries(test_dht_storage PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_dht_storage COMMAND test_dht_storage)

    # Stage 4: E4-1..E4-6 AKE cryptographic handshake, replay cache, and secure session unit tests
    add_executable(test_ake tests/unit/test_ake.cpp)
    target_link_libraries(test_ake PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_ake COMMAND test_ake)

    # Stage 4: E4-7 Negative AKE tests (identity spoofing, replay attacks, bit-flipping, AAD tampering)
    add_executable(test_negative_ake tests/negative/test_negative_ake.cpp)
    target_link_libraries(test_negative_ake PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_negative_ake COMMAND test_negative_ake)

    # Stage 4: E4-8 Live network AKE handshake and transparent encrypted communication integration test
    add_executable(test_ake_integration tests/integration/test_ake_integration.cpp)
    target_link_libraries(test_ake_integration PRIVATE p2p_core Catch2::Catch2WithMain)
    add_test(NAME test_ake_integration COMMAND test_ake_integration)

    set_tests_properties(
        test_frame test_node_id test_k_bucket test_routing_table
        test_lookup test_lru_scenarios test_negative_identity test_negative_transport test_dht_integration
        test_node_record test_record_store test_dht_storage
        test_ake test_negative_ake test_ake_integration
        PROPERTIES TIMEOUT 30
    )
endif()
