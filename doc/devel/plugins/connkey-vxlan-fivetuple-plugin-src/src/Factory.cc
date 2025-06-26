// See the file "COPYING" in the main distribution directory for copyright.

#include "Factory.h"

#include <memory>

#include "zeek/ID.h"
#include "zeek/Val.h"
#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/fivetuple/Factory.h"
#include "zeek/util-types.h"

namespace zeek::conn_key::vxlan_vni_fivetuple {

class VxlanVniConnKey : public zeek::IPBasedConnKey {
public:
    VxlanVniConnKey() {
        // Ensure padding holes in the key struct are filled with zeroes.
        memset(static_cast<void*>(&key), 0, sizeof(key));
    }

    detail::PackedConnTuple& PackedTuple() override { return key.tuple; }

    const detail::PackedConnTuple& PackedTuple() const override { return key.tuple; }

protected:
    zeek::session::detail::Key DoSessionKey() const override {
        return {reinterpret_cast<const void*>(&key), sizeof(key), session::detail::Key::CONNECTION_KEY_TYPE};
    }

    void DoPopulateConnIdVal(zeek::RecordVal& conn_id) override {
        static int vxlan_vni_off = id::conn_id->FieldOffset("vxlan_vni");

        if ( conn_id.GetType() != id::conn_id )
            return;

        if ( (key.vxlan_vni & 0xFF000000) == 0 ) // High-bits unset: Have VNI
            conn_id.Assign(vxlan_vni_off, static_cast<int>(key.vxlan_vni));
        else
            conn_id.Remove(vxlan_vni_off);
    }

    // Extract VNI from most outer VXLAN layer.
    void DoInit(const Packet& pkt) override {
        static const auto& analyzer = zeek::packet_mgr->GetAnalyzer("VXLAN");

        // Set the high-bits: This is needed because keys can get reused.
        key.vxlan_vni = 0xFF000000;

        if ( ! analyzer || ! analyzer->IsEnabled() )
            return;

        auto spans = zeek::packet_mgr->GetAnalyzerData(analyzer);

        if ( spans.empty() || spans[0].size() < 8 )
            return;

        key.vxlan_vni = spans[0][4] << 16 | spans[0][5] << 8 | spans[0][6];
    }

private:
    friend class Factory;

    struct {
        struct detail::PackedConnTuple tuple;
        uint32_t vxlan_vni;
    } __attribute__((packed, aligned)) key; // packed and aligned due to usage for hashing
};

zeek::ConnKeyPtr Factory::DoNewConnKey() const { return std::make_unique<VxlanVniConnKey>(); }

zeek::expected<zeek::ConnKeyPtr, std::string> Factory::DoConnKeyFromVal(const zeek::Val& v) const {
    if ( v.GetType() != id::conn_id )
        return zeek::unexpected<std::string>{"unexpected value type"};

    auto ck = zeek::conn_key::fivetuple::Factory::DoConnKeyFromVal(v);
    if ( ! ck.has_value() )
        return ck;

    auto* k = static_cast<VxlanVniConnKey*>(ck.value().get());
    auto rt = v.GetType()->AsRecordType();
    auto* rv = v.AsRecordVal();

    static int vxlan_vni_off = rt->FieldOffset("vxlan_vni");
    if ( vxlan_vni_off < 0 )
        return zeek::unexpected<std::string>{"missing vlxan_vni field"};

    if ( rv->HasField(vxlan_vni_off) )
        k->key.vxlan_vni = rv->GetFieldAs<zeek::CountVal>(vxlan_vni_off);

    return ck;
}

} // namespace zeek::conn_key::vxlan_vni_fivetuple
