# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Special vlan_id value in ovs_vlan_allocations table indicating flat network
FLAT_VLAN_ID = -1

# Topic for tunnel notifications between the plugin and agent
TUNNEL = 'tunnel'

# Values for network_type
TYPE_FLAT = 'flat'
TYPE_VLAN = 'vlan'
TYPE_GRE = 'gre'
TYPE_LOCAL = 'local'
TYPE_VXLAN = 'vxlan'
TYPE_NONE = 'none'
VXLAN_UDP_PORT = 4789

# Name prefixes for veth device pair linking the integration bridge
# with the physical bridge for a physical network
VETH_INTEGRATION_PREFIX = 'int-'
VETH_PHYSICAL_PREFIX = 'phy-'

# The minimum version of OVS which supports VXLAN tunneling
MINIMUM_OVS_VXLAN_VERSION = "1.10"

# The different types of tunnels
TUNNEL_NETWORK_TYPES = [TYPE_GRE, TYPE_VXLAN]

# Various tables for tunneling flows
PATCH_LV_TO_TUN = 1
GRE_TUN_TO_LV = 2
VXLAN_TUN_TO_LV = 3
LEARN_FROM_TUN = 50
EXTERNAL_LEARN_FROM_TUN = 51
EXTERNAL_LEARN_FROM_INT = 52
UCAST_TO_TUN = 60
UCAST_FROM_EXTERNAL = 61
FLOOD_TO_TUN = 22
# Map tunnel types to tables number
TUN_TABLE = {TYPE_GRE: GRE_TUN_TO_LV, TYPE_VXLAN: VXLAN_TUN_TO_LV}
ARP_RESPONDER=21
ARP_STORE=23
EXTERNAL_ROUTING_TUN = 25
FLOOD_TO_CONTROLLER = 31
EXTERNAL_OR_OVERLAY_FROM_INT = 12
EXTERNAL_OR_OVERLAY_FROM_TUN = 11

INT_TO_PATCH = 1
LEARN_FROM_INT = 10
UCAST_MCAST_CHECK = 2
UCAST_TO_INT = 20
FLOOD_TO_INT = 21
LOCAL_ARP_STORE=40
DST_SUBNET_GW_MAC = 3
ROUTING_TABLE_SRC = 30
ROUTING_TABLE_DST = 35
EXTERNAL_ROUTING = 50
PACKET_FROM_EXTERNAL = 4
CHANGE_SOURCE_MAC_TO_INTERNAL = 5


# EXT bridge
SNAT_DNAT_DECISION = 30
ROUTING_EXTERNAL_NETWORK = 31
EXTERNAL_NETWORK_ARP_CACHE = 20
LEARN_EXTERNAL_SESSION = 40
UPLINK_TO_EXT = 50
ARP_RESPONDER_EXTERNAL=21
ROUTING_AMONGST_VIRTUAL_ROUTERS = 13
