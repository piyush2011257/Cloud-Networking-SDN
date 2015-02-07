# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Nicira Networks, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Dan Wendlandt, Nicira Networks, Inc.
# @author: Dave Lapsley, Nicira Networks, Inc.
# @author: Aaron Rosen, Nicira Networks, Inc.
# @author: Seetharama Ayyadevara, Freescale Semiconductor, Inc.
# @author: Kyle Mestery, Cisco Systems, Inc.

import distutils.version as dist_version
import sys
import time

import netaddr

import eventlet
from oslo.config import cfg

from neutron.agent import l2population_rpc
from neutron.agent.linux import ip_lib
from neutron.agent.linux import ovs_lib
from neutron.agent.linux import utils
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as logging_config
from neutron.common import constants as q_const
from neutron.common import legacy
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron import context
from neutron.extensions import securitygroup as ext_sg
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common.rpc import common as rpc_common
from neutron.openstack.common.rpc import dispatcher
from neutron.plugins.openvswitch.common import config  # noqa
from neutron.plugins.openvswitch.common import constants


LOG = logging.getLogger(__name__)

# A placeholder for dead vlans.
DEAD_VLAN_TAG = str(q_const.MAX_VLAN_TAG + 1)
EXTERNAL_DEV_PREFIX = 'qg-'
DEV_NAME_LEN = 14


# A class to represent a VIF (i.e., a port that has 'iface-id' and 'vif-mac'
# attributes set).
class LocalVLANMapping:
    def __init__(self, vlan, network_type, physical_network, segmentation_id,
                 vif_ports=None):
        if vif_ports is None:
            vif_ports = {}
        self.vlan = vlan
        self.network_type = network_type
        self.physical_network = physical_network
        self.segmentation_id = segmentation_id
        self.vif_ports = vif_ports
        # set of tunnel ports on which packets should be flooded
        self.tun_ofports = set()

	self.integ_ofports= set()

    def __str__(self):
        return ("lv-id = %s type = %s phys-net = %s phys-id = %s" %
                (self.vlan, self.network_type, self.physical_network,
                 self.segmentation_id))


class Port(object):
    """Represents a neutron port.

    Class stores port data in a ORM-free way, so attributres are
    still available even if a row has been deleted.
    """

    def __init__(self, p):
        self.id = p.id
        self.network_id = p.network_id
        self.device_id = p.device_id
        self.admin_state_up = p.admin_state_up
        self.status = p.status

    def __eq__(self, other):
        '''Compare only fields that will cause us to re-wire.'''
        try:
            return (self and other
                    and self.id == other.id
                    and self.admin_state_up == other.admin_state_up)
        except Exception:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.id)


class OVSPluginApi(agent_rpc.PluginApi,
                   sg_rpc.SecurityGroupServerRpcApiMixin):
    pass


class OVSSecurityGroupAgent(sg_rpc.SecurityGroupAgentRpcMixin):
    def __init__(self, context, plugin_rpc, root_helper):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.root_helper = root_helper
        self.init_firewall()


class OVSNeutronAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin,
                      l2population_rpc.L2populationRpcCallBackMixin):
    '''Implements OVS-based tunneling, VLANs and flat networks.

    Two local bridges are created: an integration bridge (defaults to
    'br-int') and a tunneling bridge (defaults to 'br-tun'). An
    additional bridge is created for each physical network interface
    used for VLANs and/or flat networks.

    All VM VIFs are plugged into the integration bridge. VM VIFs on a
    given virtual network share a common "local" VLAN (i.e. not
    propagated externally). The VLAN id of this local VLAN is mapped
    to the physical networking details realizing that virtual network.

    For virtual networks realized as GRE tunnels, a Logical Switch
    (LS) identifier and is used to differentiate tenant traffic on
    inter-HV tunnels. A mesh of tunnels is created to other
    Hypervisors in the cloud. These tunnels originate and terminate on
    the tunneling bridge of each hypervisor. Port patching is done to
    connect local VLANs on the integration bridge to inter-hypervisor
    tunnels on the tunnel bridge.

    For each virtual networks realized as a VLANs or flat network, a
    veth is used to connect the local VLAN on the integration bridge
    with the physical network bridge, with flow rules adding,
    modifying, or stripping VLAN tags as necessary.
    '''

    # history
    #   1.0 Initial version
    #   1.1 Support Security Group RPC
    RPC_API_VERSION = '1.1'

    def __init__(self, integ_br, tun_br, local_ip,
                 bridge_mappings, root_helper,
		 ext_br, network_node_tunnel_ip,ext_if,
                 polling_interval, tunnel_types=None,
                 veth_mtu=None, l2_population=False ):
        '''Constructor.

        :param integ_br: name of the integration bridge.
        :param tun_br: name of the tunnel bridge.
        :param local_ip: local IP address of this hypervisor.
        :param bridge_mappings: mappings from physical network name to bridge.
        :param root_helper: utility to use when running shell cmds.
        :param polling_interval: interval (secs) to poll DB.
        :param tunnel_types: A list of tunnel types to enable support for in
               the agent. If set, will automatically set enable_tunneling to
               True.
        :param veth_mtu: MTU size for veth interfaces.
        '''
        self.veth_mtu = veth_mtu
        self.root_helper = root_helper
        self.available_local_vlans = set(xrange(q_const.MIN_VLAN_TAG,
                                                q_const.MAX_VLAN_TAG))
        self.tunnel_types = tunnel_types or []
        self.l2_pop = l2_population
        self.agent_state = {
            'binary': 'neutron-openvswitch-agent',
            'host': cfg.CONF.host,
            'topic': q_const.L2_AGENT_TOPIC,
            'configurations': {'bridge_mappings': bridge_mappings,
                               'tunnel_types': self.tunnel_types,
                               'tunneling_ip': local_ip,
                               'l2_population': self.l2_pop},
            'agent_type': q_const.AGENT_TYPE_OVS,
            'start_flag': True}

        # Keep track of int_br's device count for use by _report_state()
        self.int_br_device_count = 0

        self.int_br = ovs_lib.OVSBridge(integ_br, self.root_helper)
        self.setup_rpc()
        self.setup_integration_br()
        self.setup_physical_bridges(bridge_mappings)
        self.local_vlan_map = {}
        self.tun_br_ofports = {constants.TYPE_GRE: {},
                               constants.TYPE_VXLAN: {}}
	self.last_used_router_id=0
	self.router_local_map= {}
	self.snat_mac= {}

        self.eth_if=ext_if
	self.network_node_tunnel_ip=network_node_tunnel_ip                        # Currently hard-coded to identify the network node
        self.polling_interval = polling_interval
	self.ext_br=ext_br

        if tunnel_types:
            self.enable_tunneling = True
        else:
            self.enable_tunneling = False
        self.local_ip = local_ip
        self.tunnel_count = 0
        self.vxlan_udp_port = cfg.CONF.AGENT.vxlan_udp_port
        self._check_ovs_version()
        if self.enable_tunneling:
            self.setup_tunnel_br(tun_br)
            # Without tunneling no external connectivity!
	    LOG.debug(_("initialize external bridge"))
            if self.local_ip == self.network_node_tunnel_ip:
	        self.setup_external_bridge(ext_br)
		#self.external_br = ovs_lib.OVSBridge(ext_br, self.root_helper)
	    	self.initialize_tun_ext_link()
	LOG.debug(_("initialize integ br start"))
        self.initialize_integ_br()
        # Collect additional bridges to monitor
        self.ancillary_brs = self.setup_ancillary_bridges(integ_br, tun_br)

        # Security group agent supprot
        self.sg_agent = OVSSecurityGroupAgent(self.context,
                                              self.plugin_rpc,
                                              root_helper)

    def port_check(self, context):
	LOG.debug(_("success!!"))

    def _check_ovs_version(self):
        if constants.TYPE_VXLAN in self.tunnel_types:
            check_ovs_version(constants.MINIMUM_OVS_VXLAN_VERSION,
                              self.root_helper)

    def _report_state(self):
        # How many devices are likely used by a VM
        self.agent_state.get('configurations')['devices'] = (
            self.int_br_device_count)
        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def setup_rpc(self):
        mac = self.int_br.get_local_port_mac()
        self.agent_id = '%s%s' % ('ovs', (mac.replace(":", "")))
        self.topic = topics.AGENT
        self.plugin_rpc = OVSPluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.dispatcher = self.create_rpc_dispatcher()
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [constants.TUNNEL, topics.UPDATE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]
        if self.l2_pop:
            consumers.append([topics.L2POPULATION,
                              topics.UPDATE, cfg.CONF.host])
        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def get_net_uuid(self, vif_id):
        for network_id, vlan_mapping in self.local_vlan_map.iteritems():
            if vif_id in vlan_mapping.vif_ports:
                return network_id

    def network_delete(self, context, **kwargs):
        LOG.debug(_("network_delete called"))
        network_id = kwargs.get('network_id')
        LOG.debug(_("Delete %s"), network_id)
        # The network may not be defined on this agent
        lvm = self.local_vlan_map.get(network_id)
        if lvm:
            self.reclaim_local_vlan(network_id)
        else:
            LOG.debug(_("Network %s not used on agent."), network_id)
        LOG.debug(_("network_delete called over"))

    
    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:DEV_NAME_LEN]
    

    def _add_snat_router_gateway ( self, context, **kwargs ):
        LOG.debug(_("add_snat_router_gateway called"))
        LOG.debug(_("add_snat_router_gateway called context: %s"), context)
        LOG.debug(_("add_snat_router_gateway called kwargs: %s"), kwargs)
	port_context = kwargs.get('port')
        network_id = port_context['network_id']
        snat_mac_addr_str= port_context['mac_address']
        device_owner= port_context['device_owner']
        device_id= port_context['device_id']
        snat_ip_str = [tmp['ip_address'] for tmp in port_context['fixed_ips'] ]			# This is a single element list! As router has only one gateway ata time

        router_id_str= str(device_id)
        LOG.debug(_("router_id string  %s"), router_id_str)
	self.snat_mac[device_id]=snat_mac_addr_str						# Needed for DNAT port flow add
	
        if router_id_str in self.router_local_map.keys():
   		router_id=self.router_local_map[router_id_str]
        else:
                self.last_used_router_id += 1                           # Currenlty a direct mechanism to generate router_id. This can be optimized like getting VLAN ID's for networks
                self.router_local_map[router_id_str]=self.last_used_router_id
                router_id=self.last_used_router_id


        lvm = self.local_vlan_map.get(network_id)
        if not lvm:
                # if not managed then manage it, create a local VLAN for the networkID so that we can maintain its ARP_STORE and LOCAL_ARP_STORE. 
                net_type=kwargs['network_type']
                seg_id=kwargs['segmentation_id']
                phys=kwargs['physical_network']
                self.provision_local_vlan(network_id,net_type ,phys ,seg_id )

        lvid= self.local_vlan_map[network_id].vlan
        
	self.int_br.add_flow(table=constants.EXTERNAL_ROUTING,
                             priority=1,
                             reg1="%s" % router_id,
                             actions="mod_dl_dst:%s, mod_vlan_vid:%s, resubmit(,%s)" % (snat_mac_addr_str, lvid, constants.UCAST_MCAST_CHECK) )


	self.int_br.add_flow(table=constants.UCAST_MCAST_CHECK,
                             priority=1,
                             dl_type=0x0800,
                             dl_dst="%s" % snat_mac_addr_str,
                             vlan_tci="%s/0x0fff"  % lvid,
                             actions="load:%s->NXM_NX_REG0[], resubmit(,%s)" % (self.patch_tun_ofport, constants.FLOOD_TO_INT))

        self.int_br.add_flow(table=constants.PACKET_FROM_EXTERNAL,
                             priority=1,
                             dl_type=0x0800,
                             dl_src="%s" % snat_mac_addr_str,
			     vlan_tci="%s/0x0fff"  % lvid,
                             actions="load:%s->NXM_NX_REG2[], resubmit(,%s)" % (router_id, constants.CHANGE_SOURCE_MAC_TO_INTERNAL))

	if self.local_ip != self.network_node_tunnel_ip:
                self.tun_br.add_flow(table=constants.EXTERNAL_ROUTING_TUN,
                                     priority=1,
                                     dl_type=0x0800,
                                     dl_dst="%s" % snat_mac_addr_str,
				     vlan_tci="%s/0x0fff" % lvid,
                                     actions="resubmit(,%s)" % constants.FLOOD_TO_CONTROLLER)


                all_tun_ofports=self.tun_br_ofports[constants.TYPE_VXLAN]
                LOG.debug(_("tun_br_ofports details: %s"), all_tun_ofports)
                
                network_tun_ofport = all_tun_ofports[self.network_node_tunnel_ip]
                seg_id= self.local_vlan_map[network_id].segmentation_id
                self.tun_br.add_flow(table=constants.FLOOD_TO_CONTROLLER,
                                     priority=1,
                                     dl_type=0x0800,
                                     vlan_tci="%s/0x0fff" % lvid,
                                     dl_dst="%s" %  snat_mac_addr_str,
                                     actions="strip_vlan, set_tunnel:%s, output:%s" % (seg_id, network_tun_ofport))

        else:
	        self.tun_br.mod_flow(in_port=self.patch_ext_ofport_ingress,
         	                     priority=1,
                	             dl_type=0x0800,
                        	     dl_src="%s" % self.snat_mac[device_id],
				     vlan_tci="%s/0x0fff" % lvid,
				     actions="resubmit(,%s)" %
                             	     constants.UCAST_FROM_EXTERNAL ) 

                self.tun_br.add_flow(table=constants.EXTERNAL_OR_OVERLAY_FROM_TUN, 
                                     priority=1,
                                     dl_type=0x0800,
                                     dl_dst="%s" % snat_mac_addr_str,
				     vlan_tci="%s/0x0fff" % lvid,
                                     actions="resubmit(,%s)" % constants.EXTERNAL_LEARN_FROM_TUN)

                self.tun_br.add_flow(table=constants.EXTERNAL_OR_OVERLAY_FROM_INT, 
                                     priority=1,
                                     dl_type=0x0800,
                                     dl_dst="%s" % snat_mac_addr_str,
                                     vlan_tci="%s/0x0fff" % lvid,
                                     actions="resubmit(,%s)" % constants.EXTERNAL_LEARN_FROM_INT)

		
		eth_mac=port_context['mac_address']

		learn_flow_icmp=("table=%s,"
                       		 "priority=1,"
                        	 "hard_timeout=100,"
				 "dl_type=0x0800,"
                        	 "NXM_OF_IP_PROTO[],"
				 "NXM_OF_IP_SRC[]=NXM_OF_IP_DST[],"
				 "NXM_OF_ETH_DST[],"
				 "load:NXM_OF_VLAN_TCI[0..11]->NXM_OF_VLAN_TCI[0..11],"
                        	 "load:NXM_OF_IP_SRC[]->NXM_OF_IP_DST[],"
				 "load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],"
				 "load:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[],"
                        	 "output:NXM_NX_REG0[]" %
                        	 constants.LEARN_EXTERNAL_SESSION)

                learn_flow_tcp=( "table=%s,"
                                 "priority=1,"
                                 "dl_type=0x0800,"
                                 "hard_timeout=100,"
                                 "nw_proto=6,"
				 "NXM_OF_TCP_DST[]=NXM_OF_TCP_SRC[],"
                                 "NXM_OF_IP_SRC[]=NXM_OF_IP_DST[],"
                                 "NXM_OF_TCP_SRC[]=NXM_OF_TCP_DST[],"
                                 "NXM_OF_ETH_DST[],"
				 "load:NXM_OF_VLAN_TCI[0..11]->NXM_OF_VLAN_TCI[0..11],"
                                 "load:NXM_OF_IP_SRC[]->NXM_OF_IP_DST[],"
                                 "load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],"
                                 "load:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[],"
                                 "output:NXM_NX_REG0[]" %
                                 constants.LEARN_EXTERNAL_SESSION)

		for val in snat_ip_str:									# Single element list
	 	        LOG.debug(_("snat_ip_str value: %s"), val)
			
			self.external_br.add_flow ( table=constants.SNAT_DNAT_DECISION,
						    priority=5,
						    dl_type=0x0800,
						    nw_proto=1,
					            dl_dst="%s" % snat_mac_addr_str,
			                            vlan_tci="%s/0x0fff"  % lvid,
						    actions="learn(%s),mod_nw_src:%s,mod_dl_src:%s,resubmit(,%s)"
                                                    % ( learn_flow_icmp, val, self.snat_mac[device_id], constants.ROUTING_AMONGST_VIRTUAL_ROUTERS))
        
                        self.external_br.add_flow ( table=constants.SNAT_DNAT_DECISION,
                                                    priority=5,
                                                    dl_type=0x0800,
                                                    nw_proto=6,
                                                    dl_dst="%s" %  snat_mac_addr_str,
                                                    vlan_tci="%s/0x0fff"  % lvid,
                                                    actions="learn(%s),mod_nw_src:%s,mod_dl_src:%s,resubmit(,%s)"
                                                    % ( learn_flow_tcp, val, eth_mac, constants.ROUTING_AMONGST_VIRTUAL_ROUTERS))

        		self.external_br.add_flow( table=constants.UPLINK_TO_EXT,
						   dl_type=0x0800,
						   priority=5,
                        		           dl_dst="%s" % eth_mac,
						   nw_dst="%s" % val,
                                                   actions="resubmit(,%s)" % constants.LEARN_EXTERNAL_SESSION )

                        self.external_br.add_flow( table=constants.UPLINK_TO_EXT,
                                                   dl_type=0x0806,
                                                   priority=10,
                                                   #dl_dst="%s" % eth_mac,
                                                   arp_tpa="%s" % val,
                                                   actions="resubmit(,%s)" % constants.ARP_RESPONDER_EXTERNAL)


			mac = netaddr.EUI(snat_mac_addr_str, dialect=netaddr.mac_unix)
        		ip = netaddr.IPAddress(val)
            		action = ('move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],'
                       		   'mod_dl_src:%(mac)s,'
                       		   'load:0x2->NXM_OF_ARP_OP[],'
                       		   'move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],'
                       		   'move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],'
                       		   'load:%(mac)#x->NXM_NX_ARP_SHA[],'
                       		   'load:%(ip)#x->NXM_OF_ARP_SPA[],'
                       		   'in_port' % {'mac': mac, 'ip': ip})

			self.external_br.add_flow(table=constants.ARP_RESPONDER_EXTERNAL,
                        		          priority=1,
                                		  proto='arp',
                                		  nw_dst='%s' % ip,
                                		  actions=action)

                        self.external_br.add_flow ( table=constants.ROUTING_AMONGST_VIRTUAL_ROUTERS,
                                                    priority=5,
                                                    dl_type=0x0800,
                                                    vlan_tci="%s/0x0fff"  % lvid,
                                                    nw_dst="%s" % val,
                                                    actions="mod_dl_dst:%s,resubmit(,%s)"
                                                    % ( self.snat_mac[device_id], constants.LEARN_EXTERNAL_SESSION))

                        self.external_br.add_flow ( table=constants.ROUTING_AMONGST_VIRTUAL_ROUTERS,
                                                    priority=10,
                                                    dl_type=0x0800,
                                                    vlan_tci="%s/0x0fff"  % lvid,
                                                    nw_dst="%s" % val,
                                                    nw_src="%s" % val, 
						    actions="drop")


        LOG.debug(_("add_snat_router_gateway called over"))


    def port_update(self, context, **kwargs):
        LOG.debug(_("port_update called context: %s"), context)
        LOG.debug(_("port_update called kwargs: %s"), kwargs)

        LOG.debug(_("port_update called"))
        port = kwargs.get('port')
        
	# Validate that port is on OVS
        vif_port = self.int_br.get_vif_port_by_id(port['id'])
        LOG.debug(_("port_update called vif_port: %s"), vif_port)

        if not vif_port:
            return

        if ext_sg.SECURITYGROUPS in port:
            self.sg_agent.refresh_firewall()
        network_type = kwargs.get('network_type')
        segmentation_id = kwargs.get('segmentation_id')
        physical_network = kwargs.get('physical_network')
        self.treat_vif_port(vif_port, port['id'], port['network_id'],
                            network_type, physical_network,
                            segmentation_id, port['admin_state_up'])
        try:
            if port['admin_state_up']:
                # update plugin about port status
                self.plugin_rpc.update_device_up(self.context, port['id'],
                                                 self.agent_id,
                                                 cfg.CONF.host)
            else:
                # update plugin about port status
                self.plugin_rpc.update_device_down(self.context, port['id'],
                                                   self.agent_id,
                                                   cfg.CONF.host)
        except rpc_common.Timeout:
            LOG.error(_("RPC timeout while updating port %s"), port['id'])
        LOG.debug(_("port_update called over"))


    def tunnel_update(self, context, **kwargs):
        LOG.debug(_("tunnel_update called: %s"), kwargs)
        if not self.enable_tunneling:
            return
        tunnel_ip = kwargs.get('tunnel_ip')
        tunnel_id = kwargs.get('tunnel_id', tunnel_ip)
        if not tunnel_id:
            tunnel_id = tunnel_ip
        tunnel_type = kwargs.get('tunnel_type')
        if not tunnel_type:
            LOG.error(_("No tunnel_type specified, cannot create tunnels"))
            return
        if tunnel_type not in self.tunnel_types:
            LOG.error(_("tunnel_type %s not supported by agent"), tunnel_type)
            return
        if tunnel_ip == self.local_ip:
            return
        tun_name = '%s-%s' % (tunnel_type, tunnel_id)
        self.setup_tunnel_port(tun_name, tunnel_ip, tunnel_type)
	#if not self.l2_pop:
        #    self.setup_tunnel_port(tun_name, tunnel_ip, tunnel_type)
        LOG.debug(_("tunnel_update called over"))


    def update_integ_br ( self, mac_str, ip_str, lvm, ofport ):
        LOG.debug(_("update_integ_br called"))
        lvid=lvm.vlan
	vlan_ports=lvm.integ_ofports

        LOG.debug(_("add ingress packet flow for new port"))
        self.int_br.add_flow(table=0,
                             priority=1,
                             in_port=ofport,
			     actions="resubmit(,%s)" %
                             constants.INT_TO_PATCH)
 
        
        LOG.debug(_("add vlan translation flow"))
	self.int_br.add_flow(table=constants.INT_TO_PATCH,
                              priority=1,
                              in_port=ofport,
                              vlan_tci="0x0000",
			      actions="mod_vlan_vid:%s, resubmit(,%s)" % (lvid, constants.LEARN_FROM_INT))
	# Packet should be untagged not a VLAN Tag of 0
        
        LOG.debug(_("add ARP Store flow"))
	self.int_br.add_flow(table=constants.LOCAL_ARP_STORE,
                              priority=1,
                              dl_type=0x0800,
			      vlan_tci="%s/0x0fff" % lvid,
                              nw_dst="%s" % ip_str,
			      actions="mod_dl_dst=%s, resubmit(,%s)" % ( mac_str, constants.UCAST_MCAST_CHECK))

	self.int_br.add_flow(table=constants.FLOOD_TO_INT,
				reg0="%s" % ofport,
				priority=1,
				vlan_tci="%s/0x0fff" % lvid,
				actions="strip_vlan, output:%s" % ofport )
	
        vlan_tagged_ports= ','.join(vlan_ports)
        LOG.debug(_("vlan_tagged_ports: %s"),vlan_tagged_ports)

        if self.enable_tunneling:
		self.int_br.add_flow(table=constants.FLOOD_TO_INT,
                	                reg0=0x0,
					priority=1,
                        	        vlan_tci="%s/0x0fff" % lvid,
                                	actions="output:%s, strip_vlan, output:%s" % (self.patch_tun_ofport, vlan_tagged_ports ))
	else:
		self.int_br.add_flow(table=constants.FLOOD_TO_INT,
                                        reg0=0x0,
					priority=1,
                                        vlan_tci="%s/0x0fff" % lvid,
                                        actions="strip_vlan, output:%s" % vlan_tagged_ports )
        
        LOG.debug(_("update_integ_br called over"))

	
	
    def _update_routing_entry_integ_br ( self, lvid, mac_str, ip_str, subnet_cidr_str, device_id, network_id ):
        LOG.debug(_("_update_routing_entry_integ_br called"))

        router_id_str= str(device_id)
        LOG.debug(_("router_id string  %s"), router_id_str)

        if router_id_str in self.router_local_map.keys():
                router_id=self.router_local_map[router_id_str]
        else:
                self.last_used_router_id += 1                           # Currenlty a direct mechanism to generate router_id. This can be optimized like getting VLAN ID's for networks
                self.router_local_map[router_id_str]=self.last_used_router_id
                router_id=self.last_used_router_id
       
	
	self.int_br.add_flow(table=constants.DST_SUBNET_GW_MAC,
                             priority=1,
                             vlan_tci="%s/0x0fff" % lvid,
                             dl_dst="%s" % mac_str,
                             actions="resubmit(,%s)" 
                             % constants.ROUTING_TABLE_SRC )

        self.int_br.add_flow(table=constants.CHANGE_SOURCE_MAC_TO_INTERNAL,
                             priority=1,
                             dl_type=0x0800,
                             nw_dst="%s" % subnet_cidr_str,
			     reg2="%s" % router_id,
                             actions="mod_dl_src:%s, mod_vlan_vid:%s, resubmit(,%s)"
                             % (mac_str, lvid, constants.DST_SUBNET_GW_MAC ))
        
	
	LOG.debug(_("Subnet CIDR to be added %s"), subnet_cidr_str)
	router_id_str= str(device_id)
        LOG.debug(_("router_id string  %s"), router_id_str)
	
	self.int_br.add_flow(table=constants.ROUTING_TABLE_SRC,
                             priority=1,
                             dl_type=0x0800,
                             vlan_tci="%s/0x0fff" % lvid,
                             nw_src="%s" % subnet_cidr_str,
                             actions="load:%s->NXM_NX_REG1[], resubmit(,%s)"
			     % ( router_id, constants.ROUTING_TABLE_DST ) )

        self.int_br.add_flow(table=constants.ROUTING_TABLE_DST,
                             priority=1,
                             dl_type=0x0800,
                             nw_dst="%s" % subnet_cidr_str,
                             reg1="%s" % router_id,
			     actions="strip_vlan,mod_vlan_vid:%s,mod_dl_src:%s,resubmit(,%s)"
                             % ( lvid, mac_str, constants.LOCAL_ARP_STORE ) )
        
	
	self.int_br.mod_flow(table=constants.LOCAL_ARP_STORE,
                             priority=1,
                             dl_type=0x0800,
                             vlan_tci="%s/0x0fff" % lvid,
                             nw_dst="%s" % ip_str,
                             actions="drop" )
	LOG.debug(_("_update_routing_entry_integ_br called over"))

	
    def fip_port_update ( self, context, fixed_ip, floating_ip, fixed_mac, fixed_network_id, floating_network_id, router_id, floatingip_id, floatingip_mac ):
	# DNAT possible only when router gateway set, hence network is already provisioned here!!
	LOG.debug(_("fip_port_update called fixed_ip: %s"), fixed_ip)
        LOG.debug(_("fip_port_update called floating_ip: %s"), floating_ip)
        LOG.debug(_("fip_port_update called fixed_mac: %s"), fixed_mac)
        LOG.debug(_("fip_port_update called fixed_network_id: %s"), fixed_network_id)
        LOG.debug(_("fip_port_update called floating_network_id: %s"), floating_network_id)
        LOG.debug(_("fip_port_update called router_id: %s"), router_id)

        lvid=self.local_vlan_map[floating_network_id].vlan

	snat_mac=self.snat_mac[router_id]
        LOG.debug(_("fip_port_update called snat_mac: %s"), snat_mac)
        LOG.debug(_("fip_port_update called lvid: %s"), lvid)

	eth_mac=floatingip_mac				# floatingip_mac != snat_mac of the router. It is the mac of port in neutron port-list. All DNAT Ports share same link having different IP's

        if self.local_ip != self.network_node_tunnel_ip:
		return

        LOG.debug(_("fip_port_update called eth_mac: %s"), eth_mac)

	self.external_br.add_flow(table=constants.UPLINK_TO_EXT,
				  priority=10,
				  dl_type=0x0800,
				  dl_dst="%s" % snat_mac,
				  nw_dst="%s" % floating_ip,
				  actions="mod_vlan_vid:%s, mod_dl_src:%s, mod_dl_dst:%s,mod_nw_dst:%s, output:%s"
				  % ( lvid, snat_mac, fixed_mac, fixed_ip, self.patch_tun_ex_ofport_egress)) 

        self.external_br.add_flow(table=constants.SNAT_DNAT_DECISION,
                                  priority=10,
                                  dl_type=0x0800,
                                  dl_dst="%s" % snat_mac,
				  vlan_tci="%s/0x0fff" % lvid,
				  nw_src="%s" % fixed_ip,
                                  actions=" mod_nw_src:%s, mod_dl_src:%s, resubmit(,%s)"
                                  % ( floating_ip, snat_mac, constants.ROUTING_AMONGST_VIRTUAL_ROUTERS))

       	self.tun_br.add_flow(table=constants.UCAST_FROM_EXTERNAL,
			     priority=0,
			     dl_type=0x0800,
			     vlan_tci="%s/0x0fff" % lvid,
			     nw_dst="%s" % fixed_ip,
			     actions="output:%s, resubmit(,%s)" % (self.patch_tun_ofport, constants.FLOOD_TO_TUN))


        mac = netaddr.EUI(snat_mac, dialect=netaddr.mac_unix)
        ip = netaddr.IPAddress(floating_ip)
        actions = ('move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],'
                   'mod_dl_src:%(mac)s,'
                   'load:0x2->NXM_OF_ARP_OP[],'
                   'move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],'
                   'move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],'
                   'load:%(mac)#x->NXM_NX_ARP_SHA[],'
                   'load:%(ip)#x->NXM_OF_ARP_SPA[],'
                   'in_port' % {'mac': mac, 'ip': ip})

        self.external_br.add_flow(table=constants.ARP_RESPONDER_EXTERNAL,
                                  priority=1,
                                  proto='arp',
                                  nw_dst='%s' % ip,
                                  actions=actions)

	self.external_br.add_flow ( table=constants.ROUTING_AMONGST_VIRTUAL_ROUTERS,
                                    priority=5,
                                    dl_type=0x0800,
                                    vlan_tci="%s/0x0fff"  % lvid,
                                    nw_dst="%s" % ip,
                                    actions="mod_dl_dst:%s,resubmit(,%s)"
                                    % ( snat_mac, constants.UPLINK_TO_EXT))
				  
    def fdb_add(self, context, fdb_entries):
        LOG.debug(_("fdb_add called fdb_entries: %s"), fdb_entries)
        for network_id, values in fdb_entries.items():
            device_owner = values.get('device_owner')
	    is_external = values.get('router:external')
	    if is_external == True:
		LOG.debug(_("External_network port detail. NO need of provisioning local VLAN for external network"))
		continue
	    lvm = self.local_vlan_map.get(network_id)
            if not lvm:
		# if not managed then manage it, create a local VLAN for the networkID so that we can maintain its ARP_STORE and LOCAL_ARP_STORE
                net_type=values.get('network_type')
                seg_id=values.get('segment_id')
                phys=values.get('physical_network')
                self.provision_local_vlan(network_id,net_type ,phys ,seg_id )
                lvm = self.local_vlan_map[network_id]
                # Agent doesn't manage any port in this network
                #continue


	    if device_owner == "network:dhcp" and self.local_ip != self.network_node_tunnel_ip:
		self.add_dhcp_flow(network_id)				# Tap port for a network will come up only once

	    # Get details of ports that are local to this host
            agent_ports = values.get('ports')
	    
	    # Only other_fdb_entries() has port_id as a field - This message has only the details of the new upcoming port + constants.FLODDING_ENTRY
	    port_uid= values.get('port_id','0')
	    # Differentiate between other_fdb entries and agent_fdb_entries

            LOG.debug(_("Agent_ports: %s"), agent_ports)

	    if port_uid != "0":						# came from other_fdb_entries. Details about a port
                LOG.debug(_("Enter testing"))
                # This if is executed if the fdb_entries belong to other_fdb_entries context and the new port that came up was locacl to this host

                if self.local_ip in agent_ports.keys():
                        LOG.debug(_("local_ip port detail present that is the new port came up on this host"))
                        local_ports_list=agent_ports.get(self.local_ip)
                        LOG.debug(_("local_ip port detail present that is the new port came up on this host"))
                        LOG.debug(_("local_ports_list in fdb_add %s and port_id %s"),local_ports_list, port_uid)
                        self.int_br.defer_apply_on()
                        # local_ports_list is never empty. It has 2 entries- constant.FLOODING_ENTRY and new_port details
                        for k1 in local_ports_list:
                                LOG.debug(_("local_port_MAC %s local_port_IP %s"), k1[0], k1[1])
                                if k1  != q_const.FLOODING_ENTRY:
                                        LOG.debug(_("local_port_MAC %s local_port_IP %s"), k1[0], k1[1])
                                        loc_vlan_id=lvm.vlan
                                        integ_ofport=lvm.vif_ports[port_uid].ofport
                                        LOG.debug(_("local_port_vlan %s local_port_ofport %s"),loc_vlan_id, integ_ofport)
                                        lvm.integ_ofports.add(str(integ_ofport))
                                        self.update_integ_br(k1[0], k1[1], lvm, integ_ofport)   # loc_vlan_id, integ_ofport, lvm.integ_ofports)
                                        
                                        
                                        device_owner= values.get('device_owner')
                                        device_id= values.get('device_id')
                                        subnet_cidr= values.get('subnet_cidr')
                                        LOG.debug(_("device_owner  %s"),device_owner)
                                        LOG.debug(_("device_id  %s"),device_id)
                                        LOG.debug(_("subnet_cidr  %s"), subnet_cidr)
                                        if device_owner == "network:router_interface":
                                                # The port whoch came up on this host is a router interface / subnet gateway interface on router
                                                for each_subnet_cidr in subnet_cidr:
                                                        self._update_routing_entry_integ_br(loc_vlan_id, k1[0], k1[1], each_subnet_cidr, device_id, network_id)
							self._set_arp_responder('add', loc_vlan_id, k1[0], k1[1])		# ARP responder for local router interface on tunnel
                        self.int_br.defer_apply_off()

            agent_ports.pop(self.local_ip, None)
            if len(agent_ports):
                self.tun_br.defer_apply_on()
                for agent_ip, ports in agent_ports.items():
                    # Ensure we have a tunnel port with this remote agent
                    ofport = self.tun_br_ofports[
                        lvm.network_type].get(agent_ip)
                    if not ofport:
                        port_name = '%s-%s' % (lvm.network_type, agent_ip)
                        ofport = self.setup_tunnel_port(port_name, agent_ip,
                                                        lvm.network_type)
                        if ofport == 0:
                            continue
                    for port in ports:
                        self._add_fdb_flow(port, agent_ip, lvm, ofport)
                        # local_ports_list is never empty. It has 2 entries- constant.FLOODING_ENTRY and new_port details
                        if port  != q_const.FLOODING_ENTRY:
                                LOG.debug(_("local_port_MAC %s local_port_IP %s"), port[0], port[1])
                                loc_vlan_id=lvm.vlan
                                device_owner= values.get('device_owner')
                                device_id= values.get('device_id')
                                subnet_cidr= values.get('subnet_cidr')
                                LOG.debug(_("device_owner  %s"),device_owner)
                                LOG.debug(_("device_id  %s"),device_id)
                                LOG.debug(_("subnet_cidr  %s"), subnet_cidr)
                                if device_owner == "network:router_interface":
                                        # The port whoch came up on this host is a router interface / subnet gateway interface on router
                                        for each_subnet_cidr in subnet_cidr:
                                                self._update_routing_entry_integ_br(loc_vlan_id, port[0], port[1], each_subnet_cidr, device_id, network_id)

                self.tun_br.defer_apply_off()
        LOG.debug(_("fdb_add called over"))

    def fdb_remove(self, context, fdb_entries):
        LOG.debug(_("fdb_remove called"))
        for network_id, values in fdb_entries.items():
            lvm = self.local_vlan_map.get(network_id)
            if not lvm:
                # Agent doesn't manage any more ports in this network
                continue
            agent_ports = values.get('ports')
            agent_ports.pop(self.local_ip, None)
            if len(agent_ports):
                self.tun_br.defer_apply_on()
                for agent_ip, ports in agent_ports.items():
                    ofport = self.tun_br_ofports[
                        lvm.network_type].get(agent_ip)
                    if not ofport:
                        continue
                    for port in ports:
                        self._del_fdb_flow(port, agent_ip, lvm, ofport)
                self.tun_br.defer_apply_off()
        LOG.debug(_("fdb_removed called over"))

    def _set_arp_responder(self, action, lvid, mac_str, ip_str):
        '''Set the ARP respond entry.
        
                When the l2 population mechanism driver and OVS supports to edit ARP
                fields, a table (ARP_RESPONDER) to resolve ARP locally is added to the
                tunnel bridge.

                :param action: add or remove ARP entry.
                :param lvid: local VLAN map of network's ARP entry.
                :param mac_str: MAC string value.
                :param ip_str: IP string value.
        '''
        LOG.debug(_("_set_arp_responder called"))

        mac = netaddr.EUI(mac_str, dialect=netaddr.mac_unix)
        ip = netaddr.IPAddress(ip_str)

        if action == 'add':
            actions = ('move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],'
                       'mod_dl_src:%(mac)s,'
                       'load:0x2->NXM_OF_ARP_OP[],'
                       'move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],'
                       'move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],'
                       'load:%(mac)#x->NXM_NX_ARP_SHA[],'
                       'load:%(ip)#x->NXM_OF_ARP_SPA[],'
                       'in_port' % {'mac': mac, 'ip': ip})
            self.tun_br.add_flow(table=constants.ARP_RESPONDER,
                                 priority=1,
                                 proto='arp',
                                 dl_vlan=lvid,
                                 nw_dst='%s' % ip,
                                 actions=actions)
        else:
            LOG.warning(_('Action %s not supported'), action)
        LOG.debug(_("_set_arp_responder called over"))


    def _set_arp_store(self, action, lvid, segid,  mac_str, ip_str, of_port):
        '''
	Update ARP Cache on BR-INT
	'''
	LOG.debug(_("_set_arp_store called"))
        mac = netaddr.EUI(mac_str, dialect=netaddr.mac_unix)
        ip = netaddr.IPAddress(ip_str)

        if action == 'add':
            self.int_br.add_flow(table=constants.LOCAL_ARP_STORE,
                                 priority=1,
                                 dl_type=0x0800,
                                 vlan_tci="%s/0x0fff" % lvid,
                                 nw_dst="%s" % ip_str,
                                 actions="mod_dl_dst=%s, resubmit(,%s)" % ( mac_str, constants.UCAST_MCAST_CHECK))

        else:
            LOG.warning(_('Action %s not supported'), action)
        LOG.debug(_("_set_arp_store called over"))

    def _add_fdb_flow(self, port_info, agent_ip, lvm, ofport):
        LOG.debug(_("_add_fdb_flow called"))
        if port_info == q_const.FLOODING_ENTRY:
            lvm.tun_ofports.add(ofport)
            ofports = ','.join(lvm.tun_ofports)
            self.tun_br.mod_flow(table=constants.FLOOD_TO_TUN,
                                 priority=1,
                                 dl_vlan=lvm.vlan,
                                 actions="strip_vlan,set_tunnel:%s,"
                                 "output:%s" % (lvm.segmentation_id, ofports))
        else:
            self._set_arp_responder('add', lvm.vlan, port_info[0], port_info[1])
            self._set_arp_store('add',lvm.vlan, lvm.segmentation_id , port_info[0], port_info[1], ofport)
            # TODO(feleouet): add ARP responder entry
            self.tun_br.add_flow(table=constants.UCAST_TO_TUN,
                                 priority=2,
                                 dl_vlan=lvm.vlan,
                                 dl_dst=port_info[0],
                                 actions="strip_vlan,set_tunnel:%s,output:%s" %
                                 (lvm.segmentation_id, ofport))
        LOG.debug(_("_add_fdb_flow called over"))

    def _del_fdb_flow(self, port_info, agent_ip, lvm, ofport):
        return
	if port_info == q_const.FLOODING_ENTRY:
            lvm.tun_ofports.remove(ofport)
            if len(lvm.tun_ofports) > 0:
                ofports = ','.join(lvm.tun_ofports)
                self.tun_br.mod_flow(table=constants.FLOOD_TO_TUN,
                                     priority=1,
                                     dl_vlan=lvm.vlan,
                                     actions="strip_vlan,"
                                     "set_tunnel:%s,output:%s" %
                                     (lvm.segmentation_id, ofports))
            else:
                # This local vlan doesn't require any more tunelling
                self.tun_br.delete_flows(table=constants.FLOOD_TO_TUN,
                                         dl_vlan=lvm.vlan)
            # Check if this tunnel port is still used
            self.cleanup_tunnel_port(ofport, lvm.network_type)
        else:
            #TODO(feleouet): remove ARP responder entry
            self.tun_br.delete_flows(table=constants.UCAST_TO_TUN,
                                     dl_vlan=lvm.vlan,
                                     dl_dst=port_info[0])

    def fdb_update(self, context, fdb_entries):
        LOG.debug(_("fdb_update called"))
        for action, values in fdb_entries.items():
            method = '_fdb_' + action
            if not hasattr(self, method):
                raise NotImplementedError()

            getattr(self, method)(context, values)
        LOG.debug(_("fdb_update called over"))

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return dispatcher.RpcDispatcher([self])

    def provision_local_vlan(self, net_uuid, network_type, physical_network,
                             segmentation_id):
        '''Provisions a local VLAN.

        :param net_uuid: the uuid of the network associated with this vlan.
        :param network_type: the network type ('gre', 'vxlan', 'vlan', 'flat',
                                               'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        '''
        LOG.debug(_("provision_local_vlan called"))

        if not self.available_local_vlans:
            LOG.error(_("No local VLAN available for net-id=%s"), net_uuid)
            return
        lvid = self.available_local_vlans.pop()
        LOG.info(_("Assigning %(vlan_id)s as local vlan for "
                   "net-id=%(net_uuid)s"),
                 {'vlan_id': lvid, 'net_uuid': net_uuid})
        self.local_vlan_map[net_uuid] = LocalVLANMapping(lvid, network_type,
                                                         physical_network,
                                                         segmentation_id)

        if network_type in constants.TUNNEL_NETWORK_TYPES:
            if self.enable_tunneling:
                self.tun_br.defer_apply_on()
                # outbound broadcast/multicast
                ofports = ','.join(self.tun_br_ofports[network_type].values())
                if ofports:
                    self.tun_br.mod_flow(table=constants.FLOOD_TO_TUN,
                                         priority=1,
                                         dl_vlan=lvid,
                                         actions="strip_vlan,"
                                         "set_tunnel:%s,output:%s" %
                                         (segmentation_id, ofports))
                # inbound from tunnels: set lvid in the right table
                # and resubmit to Table LEARN_FROM_TUN for mac learning
	        
		if self.local_ip != self.network_node_tunnel_ip:
			self.tun_br.add_flow(table=constants.TUN_TABLE[network_type],
                        	             priority=1,
                                	     tun_id=segmentation_id,
                                     	     actions="mod_vlan_vid:%s,resubmit(,%s)" %
                                     	     (lvid, constants.LEARN_FROM_TUN))
		else:
			self.tun_br.add_flow(table=constants.TUN_TABLE[network_type],
                                             priority=1,
                                             tun_id=segmentation_id,
                                             actions="mod_vlan_vid:%s,resubmit(,%s)" %
                                             (lvid, constants.EXTERNAL_OR_OVERLAY_FROM_TUN))

			
                self.tun_br.defer_apply_off()
            else:
                LOG.error(_("Cannot provision %(network_type)s network for "
                          "net-id=%(net_uuid)s - tunneling disabled"),
                          {'network_type': network_type,
                           'net_uuid': net_uuid})
        elif network_type == constants.TYPE_FLAT:
            if physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[physical_network]
                br.add_flow(priority=4,
                            in_port=self.phys_ofports[physical_network],
                            dl_vlan=lvid,
                            actions="strip_vlan,normal")
                # inbound
                self.int_br.add_flow(
                    priority=3,
                    in_port=self.int_ofports[physical_network],
                    dl_vlan=0xffff,
                    actions="mod_vlan_vid:%s,normal" % lvid)
            else:
                LOG.error(_("Cannot provision flat network for "
                            "net-id=%(net_uuid)s - no bridge for "
                            "physical_network %(physical_network)s"),
                          {'net_uuid': net_uuid,
                           'physical_network': physical_network})
        elif network_type == constants.TYPE_VLAN:
            if physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[physical_network]
                br.add_flow(priority=4,
                            in_port=self.phys_ofports[physical_network],
                            dl_vlan=lvid,
                            actions="mod_vlan_vid:%s,normal" % segmentation_id)
                # inbound
                self.int_br.add_flow(priority=3,
                                     in_port=self.
                                     int_ofports[physical_network],
                                     dl_vlan=segmentation_id,
                                     actions="mod_vlan_vid:%s,normal" % lvid)
            else:
                LOG.error(_("Cannot provision VLAN network for "
                            "net-id=%(net_uuid)s - no bridge for "
                            "physical_network %(physical_network)s"),
                          {'net_uuid': net_uuid,
                           'physical_network': physical_network})
        elif network_type == constants.TYPE_LOCAL:
            # no flows needed for local networks
            pass
        else:
            LOG.error(_("Cannot provision unknown network type "
                        "%(network_type)s for net-id=%(net_uuid)s"),
                      {'network_type': network_type,
                       'net_uuid': net_uuid})
        LOG.debug(_("provision_local_vlan called over"))

    def reclaim_local_vlan(self, net_uuid):
        '''Reclaim a local VLAN.

        :param net_uuid: the network uuid associated with this vlan.
        :param lvm: a LocalVLANMapping object that tracks (vlan, lsw_id,
            vif_ids) mapping.
        '''

        lvm = self.local_vlan_map.pop(net_uuid, None)
        if lvm is None:
            LOG.debug(_("Network %s not used on agent."), net_uuid)
            return

        LOG.info(_("Reclaiming vlan = %(vlan_id)s from net-id = %(net_uuid)s"),
                 {'vlan_id': lvm.vlan,
                  'net_uuid': net_uuid})

        if lvm.network_type in constants.TUNNEL_NETWORK_TYPES:
            if self.enable_tunneling:
                self.tun_br.delete_flows(
                    table=constants.TUN_TABLE[lvm.network_type],
                    tun_id=lvm.segmentation_id)
                self.tun_br.delete_flows(dl_vlan=lvm.vlan)
                '''
		if self.l2_pop:
                    # Try to remove tunnel ports if not used by other networks
                    for ofport in lvm.tun_ofports:
                        self.cleanup_tunnel_port(ofport, lvm.network_type)
		'''
        elif lvm.network_type == constants.TYPE_FLAT:
            if lvm.physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[lvm.physical_network]
                br.delete_flows(in_port=self.phys_ofports[lvm.
                                                          physical_network],
                                dl_vlan=lvm.vlan)
                # inbound
                br = self.int_br
                br.delete_flows(in_port=self.int_ofports[lvm.physical_network],
                                dl_vlan=0xffff)
        elif lvm.network_type == constants.TYPE_VLAN:
            if lvm.physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[lvm.physical_network]
                br.delete_flows(in_port=self.phys_ofports[lvm.
                                                          physical_network],
                                dl_vlan=lvm.vlan)
                # inbound
                br = self.int_br
                br.delete_flows(in_port=self.int_ofports[lvm.physical_network],
                                dl_vlan=lvm.segmentation_id)
        elif lvm.network_type == constants.TYPE_LOCAL:
            # no flows needed for local networks
            pass
        else:
            LOG.error(_("Cannot reclaim unknown network type "
                        "%(network_type)s for net-id=%(net_uuid)s"),
                      {'network_type': lvm.network_type,
                       'net_uuid': net_uuid})

        self.available_local_vlans.add(lvm.vlan)

    def port_bound(self, port, net_uuid,
                   network_type, physical_network, segmentation_id):
        '''Bind port to net_uuid/lsw_id and install flow for inbound traffic
        to vm.

        :param port: a ovslib.VifPort object.
        :param net_uuid: the net_uuid this port is to be associated with.
        :param network_type: the network type ('gre', 'vlan', 'flat', 'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        '''
        LOG.debug(_("port_bound called"))
        if net_uuid not in self.local_vlan_map:
            self.provision_local_vlan(net_uuid, network_type,
                                      physical_network, segmentation_id)
        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ports[port.vif_id] = port

        self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                     str(lvm.vlan))
        #if int(port.ofport) != -1:
        #    self.int_br.delete_flows(in_port=port.ofport)
        LOG.debug(_("port_bound called over"))


    def port_unbound(self, vif_id, net_uuid=None):
        '''Unbind port.

        Removes corresponding local vlan mapping object if this is its last
        VIF.

        :param vif_id: the id of the vif
        :param net_uuid: the net_uuid this port is associated with.
        '''
        if net_uuid is None:
            net_uuid = self.get_net_uuid(vif_id)

        if not self.local_vlan_map.get(net_uuid):
            LOG.info(_('port_unbound() net_uuid %s not in local_vlan_map'),
                     net_uuid)
            return

        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ports.pop(vif_id, None)

        if not lvm.vif_ports:
            self.reclaim_local_vlan(net_uuid)

    def port_dead(self, port):
        '''Once a port has no binding, put it on the "dead vlan".

        :param port: a ovs_lib.VifPort object.
        '''
        self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                     DEAD_VLAN_TAG)
        self.int_br.add_flow(priority=2, in_port=port.ofport, actions="drop")

    def setup_integration_br(self):
        LOG.debug(_("setup_integ_br called"))
        # Assumed br-int already existant
	'''Setup the integration bridge.

        Create patch ports and remove all existing flows.

        :param bridge_name: the name of the integration bridge.
        :returns: the integration bridge
        '''
        self.int_br.delete_port(cfg.CONF.OVS.int_peer_patch_port)
        self.int_br.remove_all_flows()
        # switch all traffic using L2 learning
        # self.int_br.add_flow(priority=1, actions="normal")
        LOG.debug(_("setup_integ_br called over"))

    def initialize_integ_br (self ):
        # Table 0 (default) will sort incoming traffic depending on in_port
        LOG.debug(_("initialize_integ_br called"))
        
        if self.enable_tunneling:
                self.int_br.add_flow(table=0,
                                     priority=1,
                                     in_port=self.patch_tun_ofport,
                                     actions="resubmit(,%s)" %
                                     constants.LEARN_FROM_INT)
        self.int_br.add_flow(table=0, priority=0, actions="drop")
        # INT_TO_PATCH table will handle packets coming from various ports other than patch-tun port on Integration Bridge
        self.int_br.add_flow(table=constants.INT_TO_PATCH, priority=0, actions="drop")

        # UCAST_MCAST_CHECK decides if the packet is unicast then send it to LEARN_FROM_INT else to FLOOD_TO_INT for flooding
        self.int_br.add_flow(table=constants.UCAST_MCAST_CHECK,
                             dl_dst="00:00:00:00:00:00/01:00:00:00:00:00",
                             actions="resubmit(,%s), resubmit(,%s)" % (constants.UCAST_TO_INT, constants.FLOOD_TO_INT))
        
        LOG.debug(_("UCAST_MCAST check flow being added"))
        self.int_br.add_flow(table=constants.UCAST_MCAST_CHECK,
                             dl_dst="01:00:00:00:00:00/01:00:00:00:00:00",
                             actions="resubmit(,%s)" % constants.FLOOD_TO_INT)
        # LEARN_FROM_TUN table will have a single flow using a learn action to
        # dynamically set-up flows in UCAST_TO_INT corresponding to remote mac
        # adresses
        learned_flow = ("table=%s,"
                        "priority=1,"
                        "hard_timeout=100,"
                        "NXM_OF_VLAN_TCI[0..11],"
                        "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                        "load:NXM_OF_IN_PORT[]->NXM_NX_REG0[0..15]"
                        % constants.UCAST_TO_INT)
        # Once remote mac adresses are learnt, packet is outputed to patch_int
        LOG.debug(_("LEARN_FROM_INT flow being added"))
        self.int_br.add_flow(table=constants.LEARN_FROM_INT,
                             priority=1,
                             actions="learn(%s), resubmit(,%s)" %
                             (learned_flow, constants.PACKET_FROM_EXTERNAL))
        # FLOOD_TO_INT will handle flooding in tunnels based on lvid,
        # for now, add a default drop action
        
        self.int_br.add_flow(table=constants.PACKET_FROM_EXTERNAL,
                             priority=0,
                             actions="resubmit(,%s)" %
                             (constants.DST_SUBNET_GW_MAC))

        self.int_br.add_flow(table=constants.CHANGE_SOURCE_MAC_TO_INTERNAL,
                             priority=0,
                             actions="drop" )

        
	
	if self.enable_tunneling:
                self.int_br.add_flow(table=constants.FLOOD_TO_INT,
                                     reg0="%s" % self.patch_tun_ofport,
                                     actions="output:%s" 
                                     % self.patch_tun_ofport )
        
        self.int_br.add_flow(table=constants.DST_SUBNET_GW_MAC,
                             priority=10,
                             dl_dst="01:00:00:00:00:00/01:00:00:00:00:00",
			     actions="resubmit(,%s)" % constants.FLOOD_TO_INT)

        self.int_br.add_flow(table=constants.DST_SUBNET_GW_MAC,
                             priority=0,
                             actions="resubmit(,%s)" % constants.UCAST_MCAST_CHECK)

        self.int_br.add_flow(table=constants.ROUTING_TABLE_SRC,
                             priority=0,
                             actions="drop")

        self.int_br.add_flow(table=constants.ROUTING_TABLE_DST,
                             priority=0,
                             actions="resubmit(,%s)" % constants.EXTERNAL_ROUTING)

        self.int_br.add_flow(table=constants.EXTERNAL_ROUTING,
                             priority=0,
                             actions="drop")

	LOG.debug(_("initialize_integ_br called over"))


    def setup_ancillary_bridges(self, integ_br, tun_br):
        '''Setup ancillary bridges - for example br-ex.'''
        ovs_bridges = set(ovs_lib.get_bridges(self.root_helper))
        # Remove all known bridges
        ovs_bridges.remove(integ_br)
        if self.enable_tunneling:
            ovs_bridges.remove(tun_br)
        br_names = [self.phys_brs[physical_network].br_name for
                    physical_network in self.phys_brs]
        ovs_bridges.difference_update(br_names)
        # Filter list of bridges to those that have external
        # bridge-id's configured
        br_names = []
        for bridge in ovs_bridges:
            id = ovs_lib.get_bridge_external_bridge_id(self.root_helper,
                                                       bridge)
            if id != bridge:
                br_names.append(bridge)
        ovs_bridges.difference_update(br_names)
        ancillary_bridges = []
        for bridge in ovs_bridges:
            br = ovs_lib.OVSBridge(bridge, self.root_helper)
            LOG.info(_('Adding %s to list of bridges.'), bridge)
            ancillary_bridges.append(br)
        return ancillary_bridges

    def setup_external_bridge ( self, ext_br ):
	'''
	Setup external bridge
	'''
        # Bridge already configured by user like in case of BR-EXT
	self.external_br = ovs_lib.OVSBridge(ext_br, self.root_helper)		# This function just creates an object of class representing external bridge
	# RIGHT NOW MANUALLY ADD UPLINK. We need to add SCRIPT in /etc/sysconfig/network-interfaces : ifcfg-<up_link_name>
	# self.external_br.reset_bridge()					# This was the step that was actually creating new bridge and destroying the old

	patch1_name = "patch-tunbr"
	patch2_name = "patch-extbr"
	self.patch_ext_ofport = self.tun_br.add_patch_port(
            patch1_name, patch2_name)
        self.patch_tun_ex_ofport = self.external_br.add_patch_port(
            patch2_name, patch1_name)
        if int(self.patch_tun_ex_ofport) < 0 or int(self.patch_ext_ofport) < 0:
            LOG.error(_("Failed to create OVS patch port. Cannot have "
                        "external bridge linking on the tunnel "
                        "Agent terminated!"))
            exit(1)

        patch1_name = "patch-tunbr_egress"
        patch2_name = "patch-extbr_ingress"
        self.patch_ext_ofport_ingress = self.tun_br.add_patch_port(
            patch1_name, patch2_name)
        self.patch_tun_ex_ofport_egress = self.external_br.add_patch_port(
            patch2_name, patch1_name)
        if int(self.patch_tun_ex_ofport_egress) < 0 or int(self.patch_ext_ofport_ingress) < 0:
            LOG.error(_("Failed to create OVS patch port. Cannot have "
                        "external bridge linking on the tunnel "
                        "Agent terminated!"))
            exit(1)

        self.external_br.remove_all_flows()


    def setup_tunnel_br(self, tun_br):
        '''Setup the tunnel bridge.

        Creates tunnel bridge, and links it to the integration bridge
        using a patch port.

        :param tun_br: the name of the tunnel bridge.
        '''
        self.tun_br = ovs_lib.OVSBridge(tun_br, self.root_helper)
        self.tun_br.reset_bridge()
        self.patch_tun_ofport = self.int_br.add_patch_port(
            cfg.CONF.OVS.int_peer_patch_port, cfg.CONF.OVS.tun_peer_patch_port)
        self.patch_int_ofport = self.tun_br.add_patch_port(
            cfg.CONF.OVS.tun_peer_patch_port, cfg.CONF.OVS.int_peer_patch_port)
        if int(self.patch_tun_ofport) < 0 or int(self.patch_int_ofport) < 0:
            LOG.error(_("Failed to create OVS patch port. Cannot have "
                        "tunneling enabled on this agent, since this version "
                        "of OVS does not support tunnels or patch ports. "
                        "Agent terminated!"))
            exit(1)
        self.tun_br.remove_all_flows()

        # Table 0 (default) will sort incoming traffic depending on in_port
        self.tun_br.add_flow(priority=1,
                             in_port=self.patch_int_ofport,
                             actions="resubmit(,%s)" %
                             constants.PATCH_LV_TO_TUN)
        self.tun_br.add_flow(priority=0, actions="drop")
        # PATCH_LV_TO_TUN table will handle packets coming from patch_int
        # unicasts go to table UCAST_TO_TUN where remote adresses are learnt
        
	if self.local_ip != self.network_node_tunnel_ip:
	        self.tun_br.add_flow(table=constants.PATCH_LV_TO_TUN,
        	                     priority=0,
				     dl_dst="00:00:00:00:00:00/01:00:00:00:00:00",
                	             actions="resubmit(,%s)" % constants.UCAST_TO_TUN)
	else:
                self.tun_br.add_flow(table=constants.PATCH_LV_TO_TUN,
                                     priority=0,
				     dl_dst="00:00:00:00:00:00/01:00:00:00:00:00",
                                     actions="resubmit(,%s)" % constants.EXTERNAL_OR_OVERLAY_FROM_INT)
	
        # Broadcasts/multicasts go to table FLOOD_TO_TUN that handles flooding
        
	self.tun_br.add_flow(table=constants.PATCH_LV_TO_TUN,
                             priority=0,
			     dl_dst="01:00:00:00:00:00/01:00:00:00:00:00",
                             actions="resubmit(,%s)" % constants.FLOOD_TO_TUN)

        self.tun_br.add_flow(table=constants.PATCH_LV_TO_TUN,
                             priority=1,
			     dl_type=0x0806,
			     nw_proto=1,			# ARP Request
                             actions="resubmit(,%s)" % constants.ARP_RESPONDER)


        self.tun_br.add_flow(table=constants.ARP_RESPONDER,
                             priority=0,
                             dl_type=0x0806,
			     actions="resubmit(,%s)" % constants.FLOOD_TO_TUN)


        # Tables [tunnel_type]_TUN_TO_LV will set lvid depending on tun_id
        # for each tunnel type, and resubmit to table LEARN_FROM_TUN where
        # remote mac adresses will be learnt
        
	for tunnel_type in constants.TUNNEL_NETWORK_TYPES:
            self.tun_br.add_flow(table=constants.TUN_TABLE[tunnel_type],
                                 priority=0,
                                 actions="drop")

        if self.local_ip == self.network_node_tunnel_ip:
        	self.tun_br.add_flow(table=constants.EXTERNAL_OR_OVERLAY_FROM_TUN,
                                     priority=0,
                                     actions="resubmit(,%s)" %
                                     constants.LEARN_FROM_TUN)
                self.tun_br.add_flow(table=constants.EXTERNAL_OR_OVERLAY_FROM_INT,
                                     priority=0,
                                     actions="resubmit(,%s)" %
                                     constants.UCAST_TO_TUN)
	

        # LEARN_FROM_TUN table will have a single flow using a learn action to
        # dynamically set-up flows in UCAST_TO_TUN corresponding to remote mac
        # adresses (assumes that lvid has already been set by a previous flow)
        learned_flow_ip = ("table=%s,"
                        "priority=1,"
                        "dl_type=0x0800,"
                        "hard_timeout=100,"
                        "NXM_OF_VLAN_TCI[0..11],"
                        "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                        "NXM_OF_IP_DST[]=NXM_OF_IP_SRC[],"
                        "load:0->NXM_OF_VLAN_TCI[],"
                        "load:NXM_NX_TUN_ID[]->NXM_NX_TUN_ID[],"
                        "output:NXM_OF_IN_PORT[]" %
                        constants.UCAST_TO_TUN)

        learned_flow_arp = ("table=%s,"
                        "priority=2,"
                        "dl_type=0x0806,"
                        "hard_timeout=100,"
                        "NXM_OF_VLAN_TCI[0..11],"
                        "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                        "NXM_OF_ARP_TPA[]=NXM_OF_ARP_SPA[],"
                        "load:0->NXM_OF_VLAN_TCI[],"
                        "load:NXM_NX_TUN_ID[]->NXM_NX_TUN_ID[],"
                        "output:NXM_OF_IN_PORT[]" %
                        constants.UCAST_TO_TUN)

        # Once remote mac adresses are learnt, packet is outputed to patch_int
        self.tun_br.add_flow(table=constants.LEARN_FROM_TUN,
                             priority=1,
                             dl_type=0x0800,
                             actions="learn(%s),output:%s" %
                             (learned_flow_ip, self.patch_int_ofport))
        self.tun_br.add_flow(table=constants.LEARN_FROM_TUN,
                             priority=1,
                             dl_type=0x0806,
                             actions="learn(%s),output:%s" %
                             (learned_flow_arp, self.patch_int_ofport))

        # Egress unicast will be handled in table UCAST_TO_TUN, where remote
        # mac adresses will be learned. For now, just add a default flow that
        # will resubmit unknown unicasts to table FLOOD_TO_TUN to treat them
        # as broadcasts/multicasts

        if self.local_ip != self.network_node_tunnel_ip:
                # For compute nodes we use table EXTERNAL_ROUTING_TUN
                self.tun_br.add_flow(table=constants.UCAST_TO_TUN,
                                     priority=0,
                                     actions="resubmit(,%s)" %
                                     constants.EXTERNAL_ROUTING_TUN)

                self.tun_br.add_flow(table=constants.EXTERNAL_ROUTING_TUN,
                                     priority=0,
                                     actions="resubmit(,%s)" %
                                     constants.FLOOD_TO_TUN)
        else:
                # For network/controller node the table / flow changed
                self.tun_br.add_flow(table=constants.UCAST_TO_TUN,
                                     priority=0,
                                     actions="resubmit(,%s)" %
                                     constants.FLOOD_TO_TUN)


        # FLOOD_TO_TUN will handle flooding in tunnels based on lvid,
        # for now, add a default drop action
        self.tun_br.add_flow(table=constants.FLOOD_TO_TUN,
                             priority=0,
                             actions="drop")

    def initialize_tun_ext_link(self):
	self.up_link_ofport = self.external_br.add_port(self.eth_if)
	# Assume that config file is already configured
	learned_flow_ip = ( "table=%s,"
			    "priority=1,"
                            "hard_timeout=100,"
			    "NXM_OF_VLAN_TCI[0..11],"
			    "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
			    "dl_type=0x800,"
			    "NXM_OF_IP_DST[]=NXM_OF_IP_SRC[],"
			    "load:0->NXM_OF_VLAN_TCI[],"
			    "load:NXM_NX_TUN_ID[]->NXM_NX_TUN_ID[],"
			    "output:NXM_OF_IN_PORT[]" % constants.UCAST_FROM_EXTERNAL )

	self.tun_br.add_flow(table=constants.EXTERNAL_LEARN_FROM_TUN,
			     priority=1,
			     dl_type=0x0800,
			     actions="learn(%s), output:%s" % 
			     ( learned_flow_ip, self.patch_ext_ofport) )
	learned_flow_arp = ( "table=%s,"
			     "priority=1,"
                             "hard_timeout=100,"
			     "NXM_OF_VLAN_TCI[0..11],"
			     "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
			     "dl_type=0x806,"
			     "NXM_OF_ARP_TPA[]=NXM_OF_ARP_SPA[],"
		  	     "load:0->NXM_OF_VLAN_TCI[],"
			     "load:NXM_NX_TUN_ID[]->NXM_NX_TUN_ID[],"
			     "output:NXM_OF_IN_PORT[]" % constants.UCAST_FROM_EXTERNAL )

	self.tun_br.add_flow(table=constants.EXTERNAL_LEARN_FROM_TUN,
		   	     priority=1,
			     dl_type=0x0806,
			     actions="learn(%s), output:%s" % 
			     ( learned_flow_arp, self.patch_ext_ofport) )	

	learned_flow_ip = ( "table=%s,"
		   	    "priority=1,"
                            "hard_timeout=100,"
			    "NXM_OF_VLAN_TCI[0..11],"
			    "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
			    "dl_type=0x800,"
			    "NXM_OF_IP_DST[]=NXM_OF_IP_SRC[],"
			    "output:NXM_OF_IN_PORT[]" % constants.UCAST_FROM_EXTERNAL )

	self.tun_br.add_flow(table=constants.EXTERNAL_LEARN_FROM_INT,
		 	     priority=1,
			     dl_type=0x0800,
			     actions="learn(%s), output:%s" % 
			     ( learned_flow_ip, self.patch_ext_ofport)) 

	learned_flow_arp = ( "table=%s,"
			     "priority=1,"
                             "hard_timeout=100,"
			     "NXM_OF_VLAN_TCI[0..11],"
			     "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
			     "dl_type=0x806,"
			     "NXM_OF_ARP_TPA[]=NXM_OF_ARP_SPA[],"
			     "output:NXM_OF_IN_PORT[]" % constants.UCAST_FROM_EXTERNAL )
	
	self.tun_br.add_flow(table=constants.EXTERNAL_LEARN_FROM_INT,
			     priority=1,
	 		     dl_type=0x0806,
		     	     actions="learn(%s), output:%s" % 
		     	     ( learned_flow_arp, self.patch_ext_ofport))

	self.external_br.add_flow( priority=0,
				   actions="NORMAL")

        self.external_br.add_flow( priority=2,
                                   dl_type=0x0800,
				   nw_proto=1,
				   actions="drop")			# Currently we dont support ping to external network

        self.external_br.add_flow( priority=1,
                                   in_port="%s" % self.patch_tun_ex_ofport,
				   actions="load:%s->NXM_NX_REG0[],resubmit(,%s)" % (self.patch_tun_ex_ofport_egress, constants.SNAT_DNAT_DECISION))

	self.external_br.add_flow( priority=1,
                                   in_port="%s" % self.up_link_ofport,
                                   actions="resubmit(,%s)" % constants.UPLINK_TO_EXT)

        self.external_br.add_flow( table=constants.SNAT_DNAT_DECISION,
				   priority=0,
                                   actions="drop") 

        self.external_br.add_flow( table=constants.UPLINK_TO_EXT,
				   priority=0,
                                   actions="NORMAL")


        self.external_br.add_flow( table=constants.ARP_RESPONDER_EXTERNAL,
                                   priority=0,
                                   actions="NORMAL")

        self.external_br.add_flow( table=constants.ROUTING_AMONGST_VIRTUAL_ROUTERS,
                                   priority=0,
                                   actions="strip_vlan, resubmit(,%s)" % constants.EXTERNAL_NETWORK_ARP_CACHE)
	

    def setup_physical_bridges(self, bridge_mappings):
        '''Setup the physical network bridges.

        Creates physical network bridges and links them to the
        integration bridge using veths.

        :param bridge_mappings: map physical network names to bridge names.
        '''
        self.phys_brs = {}
        self.int_ofports = {}
        self.phys_ofports = {}
        ip_wrapper = ip_lib.IPWrapper(self.root_helper)
        for physical_network, bridge in bridge_mappings.iteritems():
            LOG.info(_("Mapping physical network %(physical_network)s to "
                       "bridge %(bridge)s"),
                     {'physical_network': physical_network,
                      'bridge': bridge})
            # setup physical bridge
            if not ip_lib.device_exists(bridge, self.root_helper):
                LOG.error(_("Bridge %(bridge)s for physical network "
                            "%(physical_network)s does not exist. Agent "
                            "terminated!"),
                          {'physical_network': physical_network,
                           'bridge': bridge})
                sys.exit(1)
            br = ovs_lib.OVSBridge(bridge, self.root_helper)
            br.remove_all_flows()
            br.add_flow(priority=1, actions="normal")
            self.phys_brs[physical_network] = br

            # create veth to patch physical bridge with integration bridge
            int_veth_name = constants.VETH_INTEGRATION_PREFIX + bridge
            self.int_br.delete_port(int_veth_name)
            phys_veth_name = constants.VETH_PHYSICAL_PREFIX + bridge
            br.delete_port(phys_veth_name)
            if ip_lib.device_exists(int_veth_name, self.root_helper):
                ip_lib.IPDevice(int_veth_name, self.root_helper).link.delete()
                # Give udev a chance to process its rules here, to avoid
                # race conditions between commands launched by udev rules
                # and the subsequent call to ip_wrapper.add_veth
                utils.execute(['/sbin/udevadm', 'settle', '--timeout=10'])
            int_veth, phys_veth = ip_wrapper.add_veth(int_veth_name,
                                                      phys_veth_name)
            self.int_ofports[physical_network] = self.int_br.add_port(int_veth)
            self.phys_ofports[physical_network] = br.add_port(phys_veth)

            # block all untranslated traffic over veth between bridges
            self.int_br.add_flow(priority=2,
                                 in_port=self.int_ofports[physical_network],
                                 actions="drop")
            br.add_flow(priority=2,
                        in_port=self.phys_ofports[physical_network],
                        actions="drop")

            # enable veth to pass traffic
            int_veth.link.set_up()
            phys_veth.link.set_up()

            if self.veth_mtu:
                # set up mtu size for veth interfaces
                int_veth.link.set_mtu(self.veth_mtu)
                phys_veth.link.set_mtu(self.veth_mtu)

    def update_ports(self, registered_ports):
        LOG.debug(_("update_ports called"))
        ports = self.int_br.get_vif_port_set()
        if ports == registered_ports:
            return
        self.int_br_device_count = len(ports)
        added = ports - registered_ports
        removed = registered_ports - ports
        return {'current': ports,
                'added': added,
                'removed': removed}
        LOG.debug(_("update_ports called over"))


    def update_ancillary_ports(self, registered_ports):
        ports = set()
        for bridge in self.ancillary_brs:
            ports |= bridge.get_vif_port_set()

        if ports == registered_ports:
            return
        added = ports - registered_ports
        removed = registered_ports - ports
        return {'current': ports,
                'added': added,
                'removed': removed}

    def treat_vif_port(self, vif_port, port_id, network_id, network_type,
                       physical_network, segmentation_id, admin_state_up):
        LOG.debug(_("treat_vif_port called"))
        if vif_port:
            if admin_state_up:
                self.port_bound(vif_port, network_id, network_type,
                                physical_network, segmentation_id)
            else:
                self.port_dead(vif_port)
        else:
            LOG.debug(_("No VIF port for port %s defined on agent."), port_id)
        LOG.debug(_("treat_vif_ports called over"))

    def setup_tunnel_port(self, port_name, remote_ip, tunnel_type):
        ofport = self.tun_br.add_tunnel_port(port_name,
                                             remote_ip,
                                             self.local_ip,
                                             tunnel_type,
                                             self.vxlan_udp_port)
        if ofport < 0:
            LOG.error(_("Failed to set-up %(type)s tunnel port to %(ip)s"),
                      {'type': tunnel_type, 'ip': remote_ip})
            return 0

        self.tun_br_ofports[tunnel_type][remote_ip] = ofport
        # Add flow in default table to resubmit to the right
        # tunelling table (lvid will be set in the latter)
        self.tun_br.add_flow(priority=1,
                             in_port=ofport,
                             actions="resubmit(,%s)" %
                             constants.TUN_TABLE[tunnel_type])

        ofports = ','.join(self.tun_br_ofports[tunnel_type].values())
        if ofports and not self.l2_pop:
            # Update flooding flows to include the new tunnel
            for network_id, vlan_mapping in self.local_vlan_map.iteritems():
                if vlan_mapping.network_type == tunnel_type:
                    self.tun_br.mod_flow(table=constants.FLOOD_TO_TUN,
                                         priority=1,
                                         dl_vlan=vlan_mapping.vlan,
                                         actions="strip_vlan,"
                                         "set_tunnel:%s,output:%s" %
                                         (vlan_mapping.segmentation_id,
                                          ofports))
        return ofport

    def cleanup_tunnel_port(self, tun_ofport, tunnel_type):
        # Check if this tunnel port is still used
        for lvm in self.local_vlan_map.values():
            if tun_ofport in lvm.tun_ofports:
                break
        # If not, remove it
        else:
            for remote_ip, ofport in self.tun_br_ofports[tunnel_type].items():
                if ofport == tun_ofport:
                    port_name = '%s-%s' % (tunnel_type, remote_ip)
                    self.tun_br.delete_port(port_name)
                    self.tun_br_ofports[tunnel_type].pop(remote_ip, None)

    def treat_devices_added(self, devices):
        LOG.debug(_("treat_devices_added called"))
        resync = False
        self.sg_agent.prepare_devices_filter(devices)
        for device in devices:
            LOG.info(_("Port %s added"), device)
            try:
                details = self.plugin_rpc.get_device_details(self.context,
                                                             device,
                                                             self.agent_id)
            except Exception as e:
                LOG.debug(_("Unable to get port details for "
                            "%(device)s: %(e)s"),
                          {'device': device, 'e': e})
                resync = True
                continue
            port = self.int_br.get_vif_port_by_id(details['device'])
            if 'port_id' in details:
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                self.treat_vif_port(port, details['port_id'],
                                    details['network_id'],
                                    details['network_type'],
                                    details['physical_network'],
                                    details['segmentation_id'],
                                    details['admin_state_up'])

                # update plugin about port status
                self.plugin_rpc.update_device_up(self.context,
                                                 device,
                                                 self.agent_id,
                                                 cfg.CONF.host)
            else:
                LOG.debug(_("Device %s not defined on plugin"), device)
                if (port and int(port.ofport) != -1):
                    self.port_dead(port)
        LOG.debug(_("treat_devices_added called over"))
        return resync

    def treat_ancillary_devices_added(self, devices):
        LOG.debug(_("treat_ancillary_devices_added called"))
        resync = False
        for device in devices:
            LOG.info(_("Ancillary Port %s added"), device)
            try:
                self.plugin_rpc.get_device_details(self.context, device,
                                                   self.agent_id)
            except Exception as e:
                LOG.debug(_("Unable to get port details for "
                            "%(device)s: %(e)s"),
                          {'device': device, 'e': e})
                resync = True
                continue

            # update plugin about port status
            self.plugin_rpc.update_device_up(self.context,
                                             device,
                                             self.agent_id,
                                             cfg.CONF.host)
        return resync
        LOG.debug(_("treat_ancillary_devices_added called over"))

    def treat_devices_removed(self, devices):
        resync = False
        self.sg_agent.remove_devices_filter(devices)
        for device in devices:
            LOG.info(_("Attachment %s removed"), device)
            try:
                self.plugin_rpc.update_device_down(self.context,
                                                   device,
                                                   self.agent_id,
                                                   cfg.CONF.host)
            except Exception as e:
                LOG.debug(_("port_removed failed for %(device)s: %(e)s"),
                          {'device': device, 'e': e})
                resync = True
                continue
            self.port_unbound(device)
        return resync

    def treat_ancillary_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info(_("Attachment %s removed"), device)
            try:
                details = self.plugin_rpc.update_device_down(self.context,
                                                             device,
                                                             self.agent_id,
                                                             cfg.CONF.host)
            except Exception as e:
                LOG.debug(_("port_removed failed for %(device)s: %(e)s"),
                          {'device': device, 'e': e})
                resync = True
                continue
            if details['exists']:
                LOG.info(_("Port %s updated."), device)
                # Nothing to do regarding local networking
            else:
                LOG.debug(_("Device %s not defined on plugin"), device)
        return resync

    def process_network_ports(self, port_info):
        LOG.debug(_("process_network_ports called"))
        resync_a = False
        resync_b = False
        if 'added' in port_info:
            resync_a = self.treat_devices_added(port_info['added'])
        if 'removed' in port_info:
            resync_b = self.treat_devices_removed(port_info['removed'])
        # If one of the above opertaions fails => resync with plugin
        LOG.debug(_("process_network_ports called over"))
        return (resync_a | resync_b)

    def process_ancillary_network_ports(self, port_info):
        resync_a = False
        resync_b = False
        if 'added' in port_info:
            resync_a = self.treat_ancillary_devices_added(port_info['added'])
        if 'removed' in port_info:
            resync_b = self.treat_ancillary_devices_removed(
                port_info['removed'])
        # If one of the above opertaions fails => resync with plugin
        return (resync_a | resync_b)

    def tunnel_sync(self):
        resync = False
        try:
            for tunnel_type in self.tunnel_types:
                details = self.plugin_rpc.tunnel_sync(self.context,
                                                      self.local_ip,
                                                      tunnel_type)
                LOG.debug(_("tunnel_sync details: %s"),details)
                '''
		if not self.l2_pop:
                    tunnels = details['tunnels']
                    for tunnel in tunnels:
                        if self.local_ip != tunnel['ip_address']:
                            tunnel_id = tunnel.get('id', tunnel['ip_address'])
                            tun_name = '%s-%s' % (tunnel_type, tunnel_id)
                            self.setup_tunnel_port(tun_name,
                                                   tunnel['ip_address'],
                                                   tunnel_type)

                '''
		tunnels = details['tunnels']
                #tunnels.append( {'ip_address': '192.168.122.158', 'udp_port': 4789})
		for tunnel in tunnels:
                    if self.local_ip != tunnel['ip_address']:
                        tunnel_id = tunnel.get('id', tunnel['ip_address'])
                        tun_name = '%s-%s' % (tunnel_type, tunnel_id)
                        self.setup_tunnel_port(tun_name,
                                               tunnel['ip_address'],
                                               tunnel_type)


        except Exception as e:
            LOG.debug(_("Unable to sync tunnel IP %(local_ip)s: %(e)s"),
                      {'local_ip': self.local_ip, 'e': e})
            resync = True
        return resync

    def rpc_loop(self):
        sync = True
        ports = set()
        ancillary_ports = set()
        tunnel_sync = True

        while True:
            try:
                start = time.time()
                if sync:
                    LOG.info(_("Agent out of sync with plugin!"))
                    ports.clear()
                    ancillary_ports.clear()
                    sync = False

                # Notify the plugin of tunnel IP
                if self.enable_tunneling and tunnel_sync:
                    LOG.info(_("Agent tunnel out of sync with plugin!"))
                    tunnel_sync = self.tunnel_sync()

                port_info = self.update_ports(ports)

                # notify plugin about port deltas
                if port_info:
                    LOG.debug(_("Agent loop has new devices!"))
                    # If treat devices fails - must resync with plugin
                    sync = self.process_network_ports(port_info)
                    ports = port_info['current']

                # Treat ancillary devices if they exist
                if self.ancillary_brs:
                    port_info = self.update_ancillary_ports(ancillary_ports)
                    if port_info:
                        rc = self.process_ancillary_network_ports(port_info)
                        ancillary_ports = port_info['current']
                        sync = sync | rc

            except Exception:
                LOG.exception(_("Error in agent event loop"))
                sync = True
                tunnel_sync = True

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug(_("Loop iteration exceeded interval "
                            "(%(polling_interval)s vs. %(elapsed)s)!"),
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})

    def daemon_loop(self):
        self.rpc_loop()


def check_ovs_version(min_required_version, root_helper):
    LOG.debug(_("Checking OVS version for VXLAN support"))
    installed_klm_version = ovs_lib.get_installed_ovs_klm_version()
    installed_usr_version = ovs_lib.get_installed_ovs_usr_version(root_helper)
    # First check the userspace version
    if installed_usr_version:
        if dist_version.StrictVersion(
                installed_usr_version) < dist_version.StrictVersion(
                min_required_version):
            LOG.error(_('Failed userspace version check for Open '
                        'vSwitch with VXLAN support. To use '
                        'VXLAN tunnels with OVS, please ensure '
                        'the OVS version is %s '
                        'or newer!'), min_required_version)
            sys.exit(1)
        # Now check the kernel version
        if installed_klm_version:
            if dist_version.StrictVersion(
                    installed_klm_version) < dist_version.StrictVersion(
                    min_required_version):
                LOG.error(_('Failed kernel version check for Open '
                            'vSwitch with VXLAN support. To use '
                            'VXLAN tunnels with OVS, please ensure '
                            'the OVS version is %s or newer!'),
                          min_required_version)
                raise SystemExit(1)
        else:
            LOG.warning(_('Cannot determine kernel Open vSwitch version, '
                          'please ensure your Open vSwitch kernel module '
                          'is at least version %s to support VXLAN '
                          'tunnels.'), min_required_version)
    else:
        LOG.warning(_('Unable to determine Open vSwitch version. Please '
                      'ensure that its version is %s or newer to use VXLAN '
                      'tunnels with OVS.'), min_required_version)
        raise SystemExit(1)


def create_agent_config_map(config):
    """Create a map of agent config parameters.

    :param config: an instance of cfg.CONF
    :returns: a map of agent configuration parameters
    """
    try:
        bridge_mappings = q_utils.parse_mappings(config.OVS.bridge_mappings)
    except ValueError as e:
        raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)

    kwargs = dict(
        integ_br=config.OVS.integration_bridge,
        tun_br=config.OVS.tunnel_bridge,
        local_ip=config.OVS.local_ip,
        bridge_mappings=bridge_mappings,
        root_helper=config.AGENT.root_helper,
        polling_interval=config.AGENT.polling_interval,
        tunnel_types=config.AGENT.tunnel_types,
        veth_mtu=config.AGENT.veth_mtu,
        l2_population=config.AGENT.l2_population,
        ext_br=config.OVS.external_bridge,
        network_node_tunnel_ip=config.OVS.network_node_tunnel_ip,
	ext_if=config.OVS.external_interface,
    )
    LOG.debug(_("INIPARSER- %s"), config.OVS.external_bridge)
    LOG.debug(_("INIPARSER- %s"), config.OVS.network_node_tunnel_ip)
    LOG.debug(_("INIPARSER- %s"), config.OVS.external_interface)

    # If enable_tunneling is TRUE, set tunnel_type to default to GRE
    if config.OVS.enable_tunneling and not kwargs['tunnel_types']:
        kwargs['tunnel_types'] = [constants.TYPE_GRE]

    # Verify the tunnel_types specified are valid
    for tun in kwargs['tunnel_types']:
        if tun not in constants.TUNNEL_NETWORK_TYPES:
            msg = _('Invalid tunnel type specificed: %s'), tun
            raise ValueError(msg)
        if not kwargs['local_ip']:
            msg = _('Tunneling cannot be enabled without a valid local_ip.')
            raise ValueError(msg)

    return kwargs


def main():
    eventlet.monkey_patch()
    cfg.CONF.register_opts(ip_lib.OPTS)
    cfg.CONF(project='neutron')
    logging_config.setup_logging(cfg.CONF)
    legacy.modernize_quantum_config(cfg.CONF)

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.error(_('%s Agent terminated!'), e)
        sys.exit(1)

    is_xen_compute_host = 'rootwrap-xen-dom0' in agent_config['root_helper']
    if is_xen_compute_host:
        # Force ip_lib to always use the root helper to ensure that ip
        # commands target xen dom0 rather than domU.
        cfg.CONF.set_default('ip_lib_force_root', True)

    plugin = OVSNeutronAgent(**agent_config)

    # Start everything.
    LOG.info(_("Agent initialized successfully, now running... "))
    plugin.daemon_loop()
    sys.exit(0)


if __name__ == "__main__":
    main()
