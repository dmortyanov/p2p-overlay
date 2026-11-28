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

TEST_CASE("E3-2: Key-to-record binding and max_record_size enforcement", "[record_store][stage3][security]") {
    REQUIRE(sodium_init() >= 0);

    RecordStore store;
    auto attacker = identity::Keypair::generate();
    auto victim = identity::Keypair::generate();

    uint64_t now = 1000;
    auto rec = create_test_record(attacker, 1, now, now + 180, "attacker_alias");

    SECTION("Storing under victim's node_record_key is rejected with KeyMismatch") {
        auto victim_key = node_record_key(victim.node_id());
        CHECK(store.put(victim_key, rec, now) == RecordValidationError::KeyMismatch);
        CHECK(store.size() == 0);
    }

    SECTION("Storing under another alias key is rejected with KeyMismatch") {
        auto other_alias_key = alias_record_key("victim_alias");
        CHECK(store.put(other_alias_key, rec, now) == RecordValidationError::KeyMismatch);
        CHECK(store.size() == 0);
    }

    SECTION("Record exceeding max_record_size is rejected with InvalidSize") {
        auto own_key = node_record_key(attacker.node_id());
        CHECK(store.put(own_key, rec, now, 32) == RecordValidationError::InvalidSize);
        CHECK(store.size() == 0);
    }
}

TEST_CASE("E3-8: Conflicting alias records and owner-bound resolution", "[record_store][stage3][alias]") {
    REQUIRE(sodium_init() >= 0);

    RecordStore store;
    auto owner_a = identity::Keypair::generate();
    auto attacker_b = identity::Keypair::generate();

    uint64_t t0 = 1000;
    auto alias_key = alias_record_key("alice");

    // 1. Owner A claims "alice" with seq = 1, TTL = 60s
    auto rec_a1 = create_test_record(owner_a, 1, t0, t0 + 60, "alice");
    REQUIRE(store.put(alias_key, rec_a1, t0) == RecordValidationError::None);

    // 2. Attacker B tries to hijack "alice" with a MUCH higher sequence_number = 999
    auto rec_b = create_test_record(attacker_b, 999, t0 + 10, t0 + 120, "alice");
    CHECK(store.put(alias_key, rec_b, t0 + 10) == RecordValidationError::AliasConflict);

    // Verify "alice" still belongs to Owner A
    auto resolved = store.get_by_alias("alice", t0 + 10);
    REQUIRE(resolved.has_value());
    CHECK(resolved->node_id == owner_a.node_id());

    // 3. Owner A updates/republishes "alice" with seq = 2 -> accepted
    auto rec_a2 = create_test_record(owner_a, 2, t0 + 20, t0 + 80, "alice");
    CHECK(store.put(alias_key, rec_a2, t0 + 20) == RecordValidationError::None);

    // 4. After Owner A's record expires (t0 + 100 > t0 + 80), another node can legitimately claim "alice"
    auto rec_b_after = create_test_record(attacker_b, 1, t0 + 100, t0 + 200, "alice");
    CHECK(store.put(alias_key, rec_b_after, t0 + 100) == RecordValidationError::None);
    auto resolved_after = store.get_by_alias("alice", t0 + 105);
    REQUIRE(resolved_after.has_value());
    CHECK(resolved_after->node_id == attacker_b.node_id());
}

