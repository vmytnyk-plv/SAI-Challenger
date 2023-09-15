import pytest

from sai_thrift.sai_headers import *
from sai_thrift.sai_adapter import *
from sai_thrift.ttypes  import *

class Switch(object):
    def __init__(self, client):
        self.client = client

    def start_switch(self):
        hw_info_array = b'wm\0'
        hw_info = sai_thrift_s8_list_t(count=len(hw_info_array), int8list=hw_info_array)
        self.switch_id = sai_thrift_create_switch(
        self.client, init_switch=True, src_mac_address="00:11:22:33:44:55",
            switch_profile_id=0, switch_hardware_info=hw_info)
        assert(status == SAI_STATUS_SUCCESS)

    def remove_switch(self):
        status = sai_thrift_remove_switch(self.client)
        assert(status == SAI_STATUS_SUCCESS)

@pytest.fixture
def switch(saithrift_client):
    switch = Switch(saithrift_client)
    switch.start_switch()
    yield switch
    switch.remove_switch()

def test_sai_thrift_get_switch_attribute(saithrift_client, switch):
    attr = sai_thrift_get_switch_attribute(
        saithrift_client, number_of_active_ports=True)
    number_of_active_ports = attr['number_of_active_ports']

    print ("number_of_active_ports = %d" % number_of_active_ports)
    assert(number_of_active_ports != 0)

    attr = sai_thrift_get_switch_attribute(
        saithrift_client,
        port_list=sai_thrift_object_list_t(idlist=[], count=int(number_of_active_ports)))
    assert(number_of_active_ports == attr['port_list'].count)
    port_list = attr['port_list'].idlist
    print ("port list = ", ['0x%016x' % x for x in port_list])
    assert(port_list is not None)

    attr = sai_thrift_get_switch_attribute(
        saithrift_client, default_vlan_id=True)
    default_vlan_id = attr['default_vlan_id']
    print ("default_vlan_id = 0x%016x" % default_vlan_id)
    assert(default_vlan_id !=0)

    attr = sai_thrift_get_vlan_attribute(
        saithrift_client, default_vlan_id, vlan_id=True)
    vlan_id = attr['vlan_id']
    print ("vlan_id = 0x%016x" % vlan_id)
    assert(vlan_id !=0)

    attr = sai_thrift_get_switch_attribute(
        saithrift_client, default_1q_bridge_id=True)
    default_1q_bridge_id = attr['default_1q_bridge_id']
    print ("default_1q_bridge_id = 0x%016x" % default_1q_bridge_id)
    assert(default_1q_bridge_id != 0)

    attr = sai_thrift_get_switch_attribute(
        saithrift_client, default_virtual_router_id=True)
    default_virtual_router_id = attr['default_virtual_router_id']
    print ("default_virtual_router_id = 0x%016x" % default_virtual_router_id)
    assert(default_virtual_router_id !=0)
    
    attr = sai_thrift_get_switch_attribute(
        saithrift_client, cpu_port=True)
    cpu_port = attr['cpu_port']
    print ("cpu_port = 0x%016x" % cpu_port)
    assert(cpu_port is not None)
    
    attr = sai_thrift_get_port_attribute(
        saithrift_client, cpu_port, qos_number_of_queues=True)
    qos_number_of_queues = attr['qos_number_of_queues']
    print ("qos_number_of_queues = %d" % qos_number_of_queues)
    assert(qos_number_of_queues is not None)
    
    print ("test_sai_thrift_get_switch_attribute OK")
