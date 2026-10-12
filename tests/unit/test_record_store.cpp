/// @file test_record_store.cpp
/// @brief Unit tests for RecordStore: storage, anti-rollback, and TTL purge (E3-2, E3-6, E3-7).

#include "dht/record_store.hpp"
#include "identity/keypair.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <chrono>

using namespace p2p;
using namespace p2p::dht;

static NodeRecord create_test_record(const identity::Keypair& kp,
                                     uint64_t seq,
                                     uint64_t issued_at,
                                     uint64_t expires_at,
                                     const std::string& alias = "") {
    NodeRecord rec;
    rec.node_id = kp.node_id();
    rec.identity_public_key = kp.public_key();
    rec.addresses = { PeerAddress{.host = "127.0.0.1", .port = 9001} };
    rec.sequence_number = seq;
    rec.issued_at = issued_at;
    rec.expires_at = expires_at;
    rec.alias = alias;
    rec.sign(kp);
    return rec;
}

TEST_CASE("E3-2 & E3-6: RecordStore basic operations and anti-rollback", "[record_store][stage3]") {
    REQUIRE(sodium_init() >= 0);

    RecordStore store;
    auto kp = identity::Keypair::generate();
    uint64_t now = 1000;
    auto key = node_record_key(kp.node_id());

    SECTION("Put and get valid record") {
        auto rec1 = create_test_record(kp, 1, now, now + 180, "my-alias");
        auto err = store.put(key, rec1, now);
        REQUIRE(err == RecordValidationError::None);
        REQUIRE(store.size() == 1);

        auto fetched = store.get(key, now);
        REQUIRE(fetched.has_value());
        REQUIRE(fetched->node_id == kp.node_id());
        REQUIRE(fetched->sequence_number == 1);
        REQUIRE(fetched->alias == "my-alias");

        // Fetch by node_id
        auto fetched_by_id = store.get_by_node_id(kp.node_id(), now);
        REQUIRE(fetched_by_id.has_value());
        REQUIRE(fetched_by_id->sequence_number == 1);

        // Fetch by alias
        auto fetched_by_alias = store.get_by_alias("my-alias", now);
        REQUIRE(fetched_by_alias.has_value());
        REQUIRE(fetched_by_alias->node_id == kp.node_id());
    }

    SECTION("E3-6: Monotonic sequence_number and anti-rollback protection") {
        auto rec1 = create_test_record(kp, 1, now, now + 180);
        REQUIRE(store.put(key, rec1, now) == RecordValidationError::None);

        // Update with higher sequence_number (seq=2) succeeds
        auto rec2 = create_test_record(kp, 2, now + 10, now + 190);
        REQUIRE(store.put(key, rec2, now + 10) == RecordValidationError::None);

        auto current = store.get(key, now + 10);
        REQUIRE(current.has_value());
        REQUIRE(current->sequence_number == 2);

        // Anti-rollback: Rollback to seq=1 must be REJECTED!
        auto rollback_rec = create_test_record(kp, 1, now + 20, now + 200);
        REQUIRE(store.put(key, rollback_rec, now + 20) == RecordValidationError::RollbackDetected);

        // Anti-rollback: Replaying duplicate seq=2 must also be REJECTED!
        auto duplicate_rec = create_test_record(kp, 2, now + 25, now + 205);
        REQUIRE(store.put(key, duplicate_rec, now + 25) == RecordValidationError::RollbackDetected);

        // Current record must remain untouched at seq=2
        auto verified = store.get(key, now + 25);
        REQUIRE(verified.has_value());
        REQUIRE(verified->sequence_number == 2);
    }
}

TEST_CASE("E3-6 & E3-7: TTL expiration and purge", "[record_store][stage3][ttl]") {
    REQUIRE(sodium_init() >= 0);

    RecordStore store;
    auto kp1 = identity::Keypair::generate();
    auto kp2 = identity::Keypair::generate();

    uint64_t t0 = 1000;
    auto key1 = node_record_key(kp1.node_id());
    auto key2 = node_record_key(kp2.node_id());

    // rec1 expires at t0 + 20
    auto rec1 = create_test_record(kp1, 1, t0, t0 + 20);
    // rec2 expires at t0 + 100
    auto rec2 = create_test_record(kp2, 1, t0, t0 + 100);

    REQUIRE(store.put(key1, rec1, t0) == RecordValidationError::None);
    REQUIRE(store.put(key2, rec2, t0) == RecordValidationError::None);
    REQUIRE(store.size() == 2);

    SECTION("Records accessible before expiry") {
        REQUIRE(store.get(key1, t0 + 10).has_value());
        REQUIRE(store.get(key2, t0 + 10).has_value());
    }

    SECTION("Expired record is not served via get()") {
        // At t0 + 30, rec1 is expired
        REQUIRE(!store.get(key1, t0 + 30).has_value());
        // rec2 is still valid
        REQUIRE(store.get(key2, t0 + 30).has_value());
    }

    SECTION("E3-7: purge_expired removes only expired records") {
        // At t0 + 30, purge should evict rec1
        auto purged = store.purge_expired(t0 + 30);
        REQUIRE(purged == 1);
        REQUIRE(store.size() == 1);
        REQUIRE(store.get(key2, t0 + 30).has_value());

        // At t0 + 110, purge should evict rec2
        auto purged2 = store.purge_expired(t0 + 110);
        REQUIRE(purged2 == 1);
        REQUIRE(store.size() == 0);
    }
}
