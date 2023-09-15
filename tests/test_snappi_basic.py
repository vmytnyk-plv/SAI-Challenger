import ipaddress
import pytest
import time
from saichallenger.common.sai_data import SaiObjType
import logging
import json

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

"""
Topology:

       --------          ------- 
      |        |        |       |
      |        |--------|       |
      |  TGEN  |--------|  DUT  |
      | SNAPPI |        |       |
      |        |        |       |
       --------          ------- 
       
"""

def check_flow_tx_rx_frames_stats(dataplane, flow_name):
    """
    This function checks if number of packets transmitted == number of
    packets recevied of a given flow.
    """
    req = dataplane.api.metrics_request()
    req.flow.flow_names = [flow_name]
    flow_stats = dataplane.api.get_metrics(req)
    log.debug("statistics : {}".format(flow_stats))
    frames_tx = sum([m.frames_tx for m in flow_stats.flow_metrics])
    frames_rx = sum([m.frames_rx for m in flow_stats.flow_metrics])
    assert frames_tx == frames_rx

@pytest.mark.parametrize("vlan_id", ["10", "100", "200"])
def test_l2_flood(testbed, npu, dataplane, vlan_id):
    """
    Description:
    Test that the packet received on a port is flooded to all VLAN members

    Test scenario:
    1. Create a VLAN 10
    2. Add two ports as untagged members to the VLAN
    3. Send packet on each port and verify that it only shows up on the other port
    """
    max_port = 2
    port_idx_offset = 28

    # Create VLAN
    vlan_oid = npu.create(SaiObjType.VLAN, ["SAI_VLAN_ATTR_VLAN_ID", vlan_id])
    testbed.push_teardown_callback(npu.remove, vlan_oid)

    # configure VLAN members
    for idx in range(max_port):
        br_port = npu.dot1q_bp_oids[idx + port_idx_offset]
        npu.remove_vlan_member(npu.default_vlan_oid, br_port)
        testbed.push_teardown_callback(npu.create_vlan_member,
	    npu.default_vlan_oid, br_port, "SAI_VLAN_TAGGING_MODE_UNTAGGED")
        vlan_mbr = npu.create_vlan_member(vlan_oid, br_port,
                                          #"SAI_VLAN_TAGGING_MODE_UNTAGGED")
                                          "SAI_VLAN_TAGGING_MODE_TAGGED")
        testbed.push_teardown_callback(npu.remove, vlan_mbr)

    # configure ports
    for idx in range(max_port):
        port = npu.port_oids[idx + port_idx_offset]
        npu.set(port, ["SAI_PORT_ATTR_PORT_VLAN_ID", vlan_id])
        testbed.push_teardown_callback(npu.set, port,
	    ["SAI_PORT_ATTR_PORT_VLAN_ID", npu.default_vlan_id])
        npu.set(npu.dot1q_bp_oids[idx + port_idx_offset], ["SAI_BRIDGE_PORT_ATTR_ADMIN_STATE", "true"])
        npu.set(port, ["SAI_PORT_ATTR_ADMIN_STATE", "true"])

    # flow 1: random unicast UDP packet
    f1 = dataplane.configuration.flows.flow(name="L2 unicast packet")[-1]
    f1.tx_rx.port.tx_name = dataplane.configuration.ports[0].name
    f1.tx_rx.port.rx_name = dataplane.configuration.ports[1].name
    f1.size.fixed = 64                        # fixed packet size
    f1.duration.fixed_packets.packets = 10    # send n packets and stop
    f1.metrics.enable = True
    f1.rate.pps = 100

    pkt_eth_hdr, pkt_ip_hdr, pkt_udp_hdr = (f1.packet.ethernet().ipv4().udp())
    pkt_eth_hdr.src.value = "00:11:22:33:44:55"
    pkt_eth_hdr.dst.value = "22:22:22:22:22:22"
    pkt_eth_hdr.ether_type.value = 2048

    pkt_ip_hdr.src.value = "192.168.0.1"
    pkt_ip_hdr.dst.value = "192.168.0.2"

    pkt_udp_hdr.src_port.value = 1234
    pkt_udp_hdr.dst_port.value = 5678

    # send traffic
    dataplane.set_config()
    dataplane.start_traffic([f1.name])
    while (not dataplane.is_traffic_stopped([f1.name])):
        time.sleep(0.1)
    dataplane.stop_traffic()

    # verify traffic
    check_flow_tx_rx_frames_stats(dataplane, f1.name)

@pytest.mark.parametrize("ip", ["10.10.10.2", "10.10.10.3"])
def test_l3_fwd(testbed, npu, dataplane, ip):
    """
    Description:
    Test that the packet received on a port is routed according L3 configuration

    Test scenario:
    1. Create router interfaces
    2. Create next-hop, neighbor, route entry
    3. Send packet on a port and verify that it only shows up on the other port
    """
    in_port_idx, out_port_idx = 28, 29

    # Remove ports from default vlan
    for idx in in_port_idx, out_port_idx:
        br_port, port = npu.dot1q_bp_oids[idx], npu.port_oids[idx]
        npu.remove_vlan_member(npu.default_vlan_oid, br_port)
        def recover_vlan_member(port_oid, br_port_oid):
            npu.create_vlan_member(npu.default_vlan_oid, br_port_oid,
                "SAI_VLAN_TAGGING_MODE_UNTAGGED")
            npu.set(port_oid, ["SAI_PORT_ATTR_PORT_VLAN_ID", npu.default_vlan_id])
        testbed.push_teardown_callback(recover_vlan_member, port, br_port)

        npu.remove(br_port)
        def recover_br_port(port_idx):
            bp_oid = npu.create(SaiObjType.BRIDGE_PORT, [
                    "SAI_BRIDGE_PORT_ATTR_TYPE", "SAI_BRIDGE_PORT_TYPE_PORT",
                    "SAI_BRIDGE_PORT_ATTR_PORT_ID", npu.port_oids[port_idx],
                    "SAI_BRIDGE_PORT_ATTR_ADMIN_STATE", "true"
                ])
            npu.dot1q_bp_oids[port_idx] = bp_oid
        testbed.push_teardown_callback(recover_br_port, idx)

    # Create RIFs on both interfaces
    rifs = []
    for idx in in_port_idx, out_port_idx:
        rif = npu.create(SaiObjType.ROUTER_INTERFACE, [
                  'SAI_ROUTER_INTERFACE_ATTR_TYPE', 'SAI_ROUTER_INTERFACE_TYPE_PORT',
                  'SAI_ROUTER_INTERFACE_ATTR_PORT_ID', npu.port_oids[idx],
                  'SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID', npu.default_vrf_oid,
              ])
        testbed.push_teardown_callback(npu.remove, rif)
        rifs.append(rif)
    rif_port_0 = rifs[0]

    # Create neigbor entry
    dmac = "00:11:22:33:44:56"
    neighbor_entry_t = 'SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:' + json.dumps({
                           "switch_id": npu.switch_oid,
                           "rif_id": rif_port_0,
                           "ip_address": ip})
    npu.create(neighbor_entry_t, ["SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS", dmac])
    testbed.push_teardown_callback(npu.remove, neighbor_entry_t)

    # Create next-hop
    nhop = npu.create(SaiObjType.NEXT_HOP, [
               "SAI_NEXT_HOP_ATTR_TYPE", "SAI_NEXT_HOP_TYPE_IP",
               "SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID", rif_port_0,
               "SAI_NEXT_HOP_ATTR_IP", ip])
    testbed.push_teardown_callback(npu.remove, nhop)
    log.debug(f'NHOP={nhop}')

    # Create route entry
    route_entry_t = 'SAI_OBJECT_TYPE_ROUTE_ENTRY:' + json.dumps({
                        "switch_id": npu.switch_oid,
                        "vr_id": npu.default_vrf_oid,
                        "destination": "10.10.10.0/24"})
    npu.create(route_entry_t, ["SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID", nhop])
    testbed.push_teardown_callback(npu.remove, route_entry_t)

    # configure and check ports
    for idx in in_port_idx, out_port_idx:
        npu.set(npu.port_oids[idx], ["SAI_PORT_ATTR_ADMIN_STATE", "true"])

    log.debug(f'Switch SMAC={npu.default_switch_smac}')

    # flow 1: random unicast UDP packet
    f1 = dataplane.configuration.flows.flow(name="L2 unicast packet")[-1]
    f1.tx_rx.port.tx_name = dataplane.configuration.ports[0].name
    f1.tx_rx.port.rx_name = dataplane.configuration.ports[1].name
    f1.size.fixed = 64                        # fixed packet size
    f1.duration.fixed_packets.packets = 10    # send n packets and stop
    f1.metrics.enable = True
    f1.rate.pps = 100

    pkt_eth_hdr, pkt_ip_hdr, pkt_udp_hdr = (f1.packet.ethernet().ipv4().udp())
    pkt_eth_hdr.src.value = "00:22:22:22:22:22"
    pkt_eth_hdr.dst.value = npu.default_switch_smac
    pkt_eth_hdr.ether_type.value = 2048

    pkt_ip_hdr.src.value = "192.168.0.1"
    pkt_ip_hdr.dst.value = ip

    pkt_udp_hdr.src_port.value = 1234
    pkt_udp_hdr.dst_port.value = 5678

    # send traffic
    dataplane.set_config()
    dataplane.start_traffic([f1.name])
    while (not dataplane.is_traffic_stopped([f1.name])):
        time.sleep(0.1)
    dataplane.stop_traffic()

    # verify traffic
    check_flow_tx_rx_frames_stats(dataplane, f1.name)
