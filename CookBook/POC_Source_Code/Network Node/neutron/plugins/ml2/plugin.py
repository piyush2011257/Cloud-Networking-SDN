# Copyright (c) 2013 OpenStack Foundation
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

from oslo.config import cfg
from sqlalchemy import exc as sql_exc

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.common import constants as const
from neutron.common import exceptions as exc
from neutron.common import topics
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import models_v2
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import extra_dhcp_opt as edo_ext
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings
from neutron.extensions import providernet as provider
from neutron import manager
from neutron.openstack.common import db as os_db
from neutron.openstack.common import excutils
from neutron.openstack.common import importutils
from neutron.openstack.common import log
from neutron.openstack.common import rpc as c_rpc
from neutron.plugins.common import constants as service_constants
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import config  # noqa
from neutron.plugins.ml2 import db
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import managers
from neutron.plugins.ml2 import models
from neutron.plugins.ml2 import rpc


'''
#from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
#from neutron.common import constants as q_const
#Above already imported from another name. so make changes in L3 code below accordingly
from neutron.common import rpc as q_rpc
#from neutron.common import topics
from neutron.db import api as qdbapi
#from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_gwmode_db
from neutron.db import l3_rpc_base
from neutron.db import model_base
#from neutron.openstack.common import importutils
#from neutron.openstack.common import rpc
#Above already imported from another name. so make changes in L3 code below accordingly
#from neutron.plugins.common import constants
#Above already imported from another name. so make changes in L3 code below accordingly
'''


FLOATING_IP_CIDR_SUFFIX = '/32'
INTERNAL_DEV_PREFIX = 'qr-'
EXTERNAL_DEV_PREFIX = 'qg-'
from neutron.agent.linux import ip_lib
#from oslo.config import cfg
from neutron.agent.common import config
from neutron import interface
from neutron.db import l3_rpc_base
from neutron.openstack.common.rpc import common as rpc_common
import netaddr

LOG = log.getLogger(__name__)

# REVISIT(rkukura): Move this and other network_type constants to
# providernet.py?
TYPE_MULTI_SEGMENT = 'multi-segment'


class Ml2Plugin(db_base_plugin_v2.NeutronDbPluginV2,
                external_net_db.External_net_db_mixin,
                sg_db_rpc.SecurityGroupServerRpcMixin,
                agentschedulers_db.DhcpAgentSchedulerDbMixin,
                addr_pair_db.AllowedAddressPairsMixin,
                extradhcpopt_db.ExtraDhcpOptMixin,

		interface.OVSInterfaceDriver):

    '''
		extraroute_db.ExtraRoute_db_mixin,
                l3_gwmode_db.L3_NAT_db_mixin,
                l3_agentschedulers_db.L3AgentSchedulerDbMixin,
	

						):
    '''
    """Implement the Neutron L2 abstractions using modules.

    Ml2Plugin is a Neutron plugin based on separately extensible sets
    of network types and mechanisms for connecting to networks of
    those types. The network types and mechanisms are implemented as
    drivers loaded via Python entry points. Networks can be made up of
    multiple segments (not yet fully implemented).
    """

    # This attribute specifies whether the plugin supports or not
    # bulk/pagination/sorting operations. Name mangling is used in
    # order to ensure it is qualified by class
    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    # List of supported extensions
 
    
    _supported_extension_aliases = ["provider", "external-net", "binding",
                                    "quotas", "security-group", "agent",
                                    "dhcp_agent_scheduler",
                                    "multi-provider", "allowed-address-pairs",
                                    "extra_dhcp_opt"]
    '''
    _supported_extension_aliases = ["provider", "external-net", "router",
                                    "ext-gw-mode", "binding", "quotas",
                                    "security-group", "agent", "extraroute",
                                    "l3_agent_scheduler",
                                    "dhcp_agent_scheduler",
                                    "extra_dhcp_opt",
                                    "allowed-address-pairs",
				    "multi-provider"]
    '''
    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            sg_rpc.disable_security_group_extension_if_noop_driver(aliases)
            self._aliases = aliases
        return self._aliases

    def __init__(self):
        LOG.info(_("init called"))
	# First load drivers, then initialize DB, then initialize drivers
        self.type_manager = managers.TypeManager()
        self.mechanism_manager = managers.MechanismManager()
        db.initialize()
        self.type_manager.initialize()
        self.mechanism_manager.initialize()

        self._setup_rpc()

        # REVISIT(rkukura): Use stevedore for these?
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )


        self.conf = cfg.CONF
        self.root_helper = "sudo neutron-rootwrap /etc/neutron/rootwrap.conf"
	self.router_info = {}
        #self.router_namespace="neutron_router_namespace"                           # Common namespace for SNAT / DNAT Ports
        #self.snat_dnat_namespace="neutron_snat_dnat_namespace"

        LOG.info(_("Modular L2 Plugin initialization complete"))

    def _setup_rpc(self):
        self.notifier = rpc.AgentNotifierApi(topics.AGENT)
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )
        self.callbacks = rpc.RpcCallbacks(self.notifier, self.type_manager)
        self.topic = topics.PLUGIN
        self.conn = c_rpc.create_connection(new=True)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        self.conn.consume_in_thread()

    def _process_provider_segment(self, segment):
        LOG.info(_("process_provider_segment called"))
        LOG.info(_("process_provider_segment called segment: %s"), segment)
        network_type = self._get_attribute(segment, provider.NETWORK_TYPE)
        physical_network = self._get_attribute(segment,
                                               provider.PHYSICAL_NETWORK)
        segmentation_id = self._get_attribute(segment,
                                              provider.SEGMENTATION_ID)

        if attributes.is_attr_set(network_type):
            segment = {api.NETWORK_TYPE: network_type,
                       api.PHYSICAL_NETWORK: physical_network,
                       api.SEGMENTATION_ID: segmentation_id}
            self.type_manager.validate_provider_segment(segment)
            return segment

        msg = _("network_type required")
        raise exc.InvalidInput(error_message=msg)

    def _process_provider_create(self, network):
        LOG.info(_("process_provider_create called"))
        LOG.info(_("process_provider_create called network: %s"), network)
        segments = []

        if any(attributes.is_attr_set(network.get(f))
               for f in (provider.NETWORK_TYPE, provider.PHYSICAL_NETWORK,
                         provider.SEGMENTATION_ID)):
            # Verify that multiprovider and provider attributes are not set
            # at the same time.
            if attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
                raise mpnet.SegmentsSetInConjunctionWithProviders()

            network_type = self._get_attribute(network, provider.NETWORK_TYPE)
            physical_network = self._get_attribute(network,
                                                   provider.PHYSICAL_NETWORK)
            segmentation_id = self._get_attribute(network,
                                                  provider.SEGMENTATION_ID)
            segments = [{provider.NETWORK_TYPE: network_type,
                         provider.PHYSICAL_NETWORK: physical_network,
                         provider.SEGMENTATION_ID: segmentation_id}]
        elif attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
            segments = network[mpnet.SEGMENTS]
        else:
            return

        return [self._process_provider_segment(s) for s in segments]

    def _get_attribute(self, attrs, key):
        LOG.info(_("get_attributes called attrs: %s"), attrs)
        LOG.info(_("get_attributes called key: %s"), key)
        value = attrs.get(key)
        if value is attributes.ATTR_NOT_SPECIFIED:
            value = None
        return value

    def _extend_network_dict_provider(self, context, network):
        LOG.info(_("extend_network_dict_provider called"))
        LOG.info(_("extend_network_dict_provider called network: %s"), network)
        LOG.info(_("extend_network_dict_provider called context: %s"), context)
        id = network['id']
        segments = db.get_network_segments(context.session, id)
        if not segments:
            LOG.error(_("Network %s has no segments"), id)
            network[provider.NETWORK_TYPE] = None
            network[provider.PHYSICAL_NETWORK] = None
            network[provider.SEGMENTATION_ID] = None
        elif len(segments) > 1:
            network[mpnet.SEGMENTS] = [
                {provider.NETWORK_TYPE: segment[api.NETWORK_TYPE],
                 provider.PHYSICAL_NETWORK: segment[api.PHYSICAL_NETWORK],
                 provider.SEGMENTATION_ID: segment[api.SEGMENTATION_ID]}
                for segment in segments]
        else:
            segment = segments[0]
            network[provider.NETWORK_TYPE] = segment[api.NETWORK_TYPE]
            network[provider.PHYSICAL_NETWORK] = segment[api.PHYSICAL_NETWORK]
            network[provider.SEGMENTATION_ID] = segment[api.SEGMENTATION_ID]
        LOG.info(_("extend_network_dict_provider called over"))

    def _filter_nets_provider(self, context, nets, filters):
        # TODO(rkukura): Implement filtering.
        return nets

    def _process_port_binding(self, mech_context, attrs):
        LOG.debug(_(" process_port_binding_called"))
        LOG.debug(_(" process_port_binding_called mech_context: %s"), mech_context)
        LOG.debug(_(" process_port_binding_called attrs: %s"), attrs)

        binding = mech_context._binding
        port = mech_context.current
        LOG.debug(_(" process_port_binding_called binding: %s"), binding)
        LOG.debug(_(" process_port_binding_called port: %s"),port)

        self._update_port_dict_binding(port, binding)

        host = attrs and attrs.get(portbindings.HOST_ID)
        host_set = attributes.is_attr_set(host)

        if binding.vif_type != portbindings.VIF_TYPE_UNBOUND:
            LOG.debug(_(" binding.vif_type is not unbounded"))
            if (not host_set and binding.segment and
                self.mechanism_manager.validate_port_binding(mech_context)):
                return False
            LOG.debug(_(" mechanism_manager.unbind_port being called in db_base_plugin_v2"))
            self.mechanism_manager.unbind_port(mech_context)
            self._update_port_dict_binding(port, binding)

        if host_set:
            LOG.debug(_("process_port_binding called host_set is True"))
            binding.host = host
            port[portbindings.HOST_ID] = host

        if binding.host:
            LOG.debug(_(" process_port_binding clled binding.host not empty"))
            self.mechanism_manager.bind_port(mech_context)
            self._update_port_dict_binding(port, binding)

        LOG.debug(_(" process_port_binding_called over"))

        return True

    def _update_port_dict_binding(self, port, binding):
        LOG.info(_("update_port_disct_binding called"))
        port[portbindings.HOST_ID] = binding.host
        port[portbindings.VIF_TYPE] = binding.vif_type
        port[portbindings.CAPABILITIES] = {
            portbindings.CAP_PORT_FILTER: binding.cap_port_filter}
        LOG.info(_("update_port_disct_binding called host_id: %s"),binding.host)
        LOG.info(_("update_port_disct_binding called vif_type: %s"),binding.vif_type)
        LOG.info(_("update_port_disct_binding called over"))


    def _delete_port_binding(self, mech_context):
        LOG.info(_("delete_port_binding called"))
        binding = mech_context._binding
        port = mech_context.current
        self._update_port_dict_binding(port, binding)
        self.mechanism_manager.unbind_port(mech_context)
        self._update_port_dict_binding(port, binding)

    def _ml2_extend_port_dict_binding(self, port_res, port_db):
        LOG.info(_("_ml2_exten_port_dict called"))
        LOG.info(_("_ml2_exten_port_dict called port_res: %s"), port_res)
        LOG.info(_("_ml2_exten_port_dict called port_db: %s"),port_db)
        # None when called during unit tests for other plugins.
        if port_db.port_binding:
            self._update_port_dict_binding(port_res, port_db.port_binding)
        LOG.info(_("_ml2_exten_port_dict called over"))


    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.PORTS, ['_ml2_extend_port_dict_binding'])

    # Note - The following hook methods have "ml2" in their names so
    # that they are not called twice during unit tests due to global
    # registration of hooks in portbindings_db.py used by other
    # plugins.

    def _ml2_port_model_hook(self, context, original_model, query):
        LOG.info(_("ml2_port_model_hook called"))
        query = query.outerjoin(models.PortBinding,
                                (original_model.id ==
                                 models.PortBinding.port_id))
        LOG.info(_("ml2_port_model_hook called context: %s"), context)
        LOG.info(_("ml2_port_model_hook called original: %s"), original_model)
        LOG.info(_("ml2_port_model_hook called query: %s"), query)
        return query

    def _ml2_port_result_filter_hook(self, query, filters):
        LOG.info(_("ml2_port_result_filter_hook called"))
        LOG.info(_("ml2_port_result_filter_hook called query: %s"), query)
        LOG.info(_("ml2_port_result_filter_hook called filters: %s"),filters)
        values = filters and filters.get(portbindings.HOST_ID, [])
        if not values:
            return query
        return query.filter(models.PortBinding.host.in_(values))

    db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
        models_v2.Port,
        "ml2_port_bindings",
        '_ml2_port_model_hook',
        None,
        '_ml2_port_result_filter_hook')

    def _notify_port_updated(self, mech_context):
        LOG.info(_("notify_port_update called"))
        port = mech_context._port
        segment = mech_context.bound_segment
        if not segment:
            # REVISIT(rkukura): This should notify agent to unplug port
            network = mech_context.network.current
            LOG.warning(_("In _notify_port_updated(), no bound segment for "
                          "port %(port_id)s on network %(network_id)s"),
                        {'port_id': port['id'],
                         'network_id': network['id']})
            return

        nw= mech_context.network
	LOG.debug(_("Notify_port_update segment context: %s"), segment)
        LOG.debug(_("Notify_port_update port context: %s"), port)
        LOG.debug(_("Notify_port_update network.current context: %s"), nw.current)
        LOG.debug(_("Notify_port_update network.network_segment context: %s"), nw.network_segments)

	

        self.notifier.port_update(mech_context._plugin_context, port,
                                  segment[api.NETWORK_TYPE],
                                  segment[api.SEGMENTATION_ID],
                                  segment[api.PHYSICAL_NETWORK])

	
	
	
	if port['device_owner'] == "network:router_gateway":
		
		self.notifier.snat_port_update(mech_context._plugin_context, port,
                                  		segment[api.NETWORK_TYPE],
                                  		segment[api.SEGMENTATION_ID],
                                  		segment[api.PHYSICAL_NETWORK])
	

    # TODO(apech): Need to override bulk operations

    def create_network(self, context, network):
        LOG.info(_("create_network called"))
        LOG.info(_("create_network called context: %s"), context)
        LOG.info(_("create_network called network: %s"), network)
        net_data = network['network']
        segments = self._process_provider_create(net_data)
        tenant_id = self._get_tenant_id_for_create(context, net_data)

        session = context.session
        with session.begin(subtransactions=True):
            self._ensure_default_security_group(context, tenant_id)
            result = super(Ml2Plugin, self).create_network(context, network)
            network_id = result['id']
            self._process_l3_create(context, result, net_data)
            # REVISIT(rkukura): Consider moving all segment management
            # to TypeManager.
            if segments:
                for segment in segments:
                    self.type_manager.reserve_provider_segment(session,
                                                               segment)
                    db.add_network_segment(session, network_id, segment)
            else:
                segment = self.type_manager.allocate_tenant_segment(session)
                db.add_network_segment(session, network_id, segment)
            self._extend_network_dict_provider(context, result)
            mech_context = driver_context.NetworkContext(self, context,
                                                         result)
            self.mechanism_manager.create_network_precommit(mech_context)

        try:
            self.mechanism_manager.create_network_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager.create_network_postcommit "
                            "failed, deleting network '%s'"), result['id'])
                self.delete_network(context, result['id'])
        return result

    def update_network(self, context, id, network):
        LOG.debug(_( "update_network called"))
        provider._raise_if_updates_provider_attributes(network['network'])

        session = context.session
        with session.begin(subtransactions=True):
            original_network = super(Ml2Plugin, self).get_network(context, id)
            updated_network = super(Ml2Plugin, self).update_network(context,
                                                                    id,
                                                                    network)
            self._process_l3_update(context, updated_network,
                                    network['network'])
            self._extend_network_dict_provider(context, updated_network)
            mech_context = driver_context.NetworkContext(
                self, context, updated_network,
                original_network=original_network)
            self.mechanism_manager.update_network_precommit(mech_context)

        # TODO(apech) - handle errors raised by update_network, potentially
        # by re-calling update_network with the previous attributes. For
        # now the error is propogated to the caller, which is expected to
        # either undo/retry the operation or delete the resource.
        self.mechanism_manager.update_network_postcommit(mech_context)
        return updated_network

    def get_network(self, context, id, fields=None):
        LOG.info(_("get_network called network_id: %s"), id)
        LOG.info(_("get_network called context: %s"), context)
        session = context.session
        with session.begin(subtransactions=True):
            result = super(Ml2Plugin, self).get_network(context, id, None)
	    LOG.info(_("get_network called result: %s"), result)
            self._extend_network_dict_provider(context, result)

        LOG.info(_("get_network called over"))
        return self._fields(result, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None, page_reverse=False):
        LOG.info(_("get_networks called"))
        session = context.session
        with session.begin(subtransactions=True):
            nets = super(Ml2Plugin,
                         self).get_networks(context, filters, None, sorts,
                                            limit, marker, page_reverse)
            for net in nets:
                LOG.info(_("individual network called returner: %s"), net)
                self._extend_network_dict_provider(context, net)

            nets = self._filter_nets_provider(context, nets, filters)
            nets = self._filter_nets_l3(context, nets, filters)

        return [self._fields(net, fields) for net in nets]

    def delete_network(self, context, id):
        # REVISIT(rkukura) The super(Ml2Plugin, self).delete_network()
        # function is not used because it auto-deletes ports and
        # subnets from the DB without invoking the derived class's
        # delete_port() or delete_subnet(), preventing mechanism
        # drivers from being called. This approach should be revisited
        # when the API layer is reworked during icehouse.

        LOG.debug(_("Deleting network %s called"), id)
        session = context.session
        while True:
            try:
                with session.begin(subtransactions=True):
                    # Get ports to auto-delete.
                    ports = (session.query(models_v2.Port).
                             enable_eagerloads(False).
                             filter_by(network_id=id).
                             with_lockmode('update').all())
                    LOG.debug(_("Ports to auto-delete: %s"), ports)
                    only_auto_del = all(p.device_owner
                                        in db_base_plugin_v2.
                                        AUTO_DELETE_PORT_OWNERS
                                        for p in ports)
                    if not only_auto_del:
                        LOG.debug(_("Tenant-owned ports exist"))
                        raise exc.NetworkInUse(net_id=id)

                    # Get subnets to auto-delete.
                    subnets = (session.query(models_v2.Subnet).
                               enable_eagerloads(False).
                               filter_by(network_id=id).
                               with_lockmode('update').all())
                    LOG.debug(_("Subnets to auto-delete: %s"), subnets)

                    if not (ports or subnets):
                        network = self.get_network(context, id)
                        mech_context = driver_context.NetworkContext(self,
                                                                     context,
                                                                     network)
                        self.mechanism_manager.delete_network_precommit(
                            mech_context)

                        record = self._get_network(context, id)
                        LOG.debug(_("Deleting network record %s"), record)
                        session.delete(record)

                        for segment in mech_context.network_segments:
                            self.type_manager.release_segment(session, segment)

                        # The segment records are deleted via cascade from the
                        # network record, so explicit removal is not necessary.
                        LOG.debug(_("Committing transaction"))
                        break
            except os_db.exception.DBError as e:
                if isinstance(e.inner_exception, sql_exc.IntegrityError):
                    msg = _("A concurrent port creation has occurred")
                    LOG.warning(msg)
                    continue
                else:
                    raise

            for port in ports:
                try:
                    self.delete_port(context, port.id)
                except Exception:
                    LOG.exception(_("Exception auto-deleting port %s"),
                                  port.id)
                    raise

            for subnet in subnets:
                try:
                    self.delete_subnet(context, subnet.id)
                except Exception:
                    LOG.exception(_("Exception auto-deleting subnet %s"),
                                  subnet.id)
                    raise

        try:
            self.mechanism_manager.delete_network_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            # TODO(apech) - One or more mechanism driver failed to
            # delete the network.  Ideally we'd notify the caller of
            # the fact that an error occurred.
            LOG.error(_("mechanism_manager.delete_network_postcommit failed"))
        self.notifier.network_delete(context, id)

    def create_subnet(self, context, subnet):
        LOG.info(_("create_subnet called"))
        session = context.session
        with session.begin(subtransactions=True):
            result = super(Ml2Plugin, self).create_subnet(context, subnet)
            mech_context = driver_context.SubnetContext(self, context, result)
            self.mechanism_manager.create_subnet_precommit(mech_context)

        try:
            self.mechanism_manager.create_subnet_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager.create_subnet_postcommit "
                            "failed, deleting subnet '%s'"), result['id'])
                self.delete_subnet(context, result['id'])
        return result

    def update_subnet(self, context, id, subnet):
        LOG.info(_("update_subnet called"))
        session = context.session
        with session.begin(subtransactions=True):
            original_subnet = super(Ml2Plugin, self).get_subnet(context, id)
            updated_subnet = super(Ml2Plugin, self).update_subnet(
                context, id, subnet)
            mech_context = driver_context.SubnetContext(
                self, context, updated_subnet, original_subnet=original_subnet)
            self.mechanism_manager.update_subnet_precommit(mech_context)

        # TODO(apech) - handle errors raised by update_subnet, potentially
        # by re-calling update_subnet with the previous attributes. For
        # now the error is propogated to the caller, which is expected to
        # either undo/retry the operation or delete the resource.
        self.mechanism_manager.update_subnet_postcommit(mech_context)
        return updated_subnet

    def delete_subnet(self, context, id):
        # REVISIT(rkukura) The super(Ml2Plugin, self).delete_subnet()
        # function is not used because it auto-deletes ports from the
        # DB without invoking the derived class's delete_port(),
        # preventing mechanism drivers from being called. This
        # approach should be revisited when the API layer is reworked
        # during icehouse.

        LOG.debug(_("Deleting subnet %s called"), id)
        session = context.session
        while True:
            with session.begin(subtransactions=True):
                subnet = self.get_subnet(context, id)
                # Get ports to auto-delete.
                allocated = (session.query(models_v2.IPAllocation).
                             filter_by(subnet_id=id).
                             join(models_v2.Port).
                             filter_by(network_id=subnet['network_id']).
                             with_lockmode('update').all())
                LOG.debug(_("Ports to auto-delete: %s"), allocated)
                only_auto_del = all(not a.port_id or
                                    a.ports.device_owner in db_base_plugin_v2.
                                    AUTO_DELETE_PORT_OWNERS
                                    for a in allocated)
                if not only_auto_del:
                    LOG.debug(_("Tenant-owned ports exist"))
                    raise exc.SubnetInUse(subnet_id=id)

                if not allocated:
                    mech_context = driver_context.SubnetContext(self, context,
                                                                subnet)
                    self.mechanism_manager.delete_subnet_precommit(
                        mech_context)

                    LOG.debug(_("Deleting subnet record"))
                    record = self._get_subnet(context, id)
                    session.delete(record)

                    LOG.debug(_("Committing transaction"))
                    break

            for a in allocated:
                try:
                    self.delete_port(context, a.port_id)
                except Exception:
                    LOG.exception(_("Exception auto-deleting port %s"),
                                  a.port_id)
                    raise

        try:
            self.mechanism_manager.delete_subnet_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            # TODO(apech) - One or more mechanism driver failed to
            # delete the subnet.  Ideally we'd notify the caller of
            # the fact that an error occurred.
            LOG.error(_("mechanism_manager.delete_subnet_postcommit failed"))

    def create_port(self, context, port):
        LOG.debug(_(" create_port called with context: %s"),context)
        LOG.debug(_(" create_port called with context roles: %s"),context.roles)
        LOG.debug(_(" create_port called with context session: %s"),context.session)
        LOG.debug(_(" create_port called with context is_admin: %s"),context.is_admin)
        LOG.debug(_(" create_port called with context project_id: %s"),context.project_id)
        LOG.debug(_(" create_port called with context tenant_id: %s"),context.tenant_id)
        LOG.debug(_(" create_port called with context: %s"),context.user_id)
        LOG.debug(_(" create_port called with port: %s"),port)

        attrs = port['port']
        attrs['status'] = const.PORT_STATUS_DOWN

        session = context.session
        with session.begin(subtransactions=True):
            self._ensure_default_security_group_on_port(context, port)
            sgids = self._get_security_groups_on_port(context, port)
            dhcp_opts = port['port'].get(edo_ext.EXTRADHCPOPTS, [])
            result = super(Ml2Plugin, self).create_port(context, port)
            LOG.debug(_(" create_port called result: %s"),result)
            self._process_port_create_security_group(context, result, sgids)
            network = self.get_network(context, result['network_id'])
            LOG.debug(_(" create_port called network: %s"),network)
            mech_context = driver_context.PortContext(self, context, result,
                                                      network)



            LOG.debug(_(" create_port called mech_context: %s"),mech_context)
            LOG.debug(_(" create_port called mech_context.network.current: %s"),mech_context.network.current)
            LOG.debug(_(" create_port called mech_context.network.original: %s"),mech_context.network.original)
            LOG.debug(_(" create_port called mech_context.network_segments: %s"),mech_context.network.network_segments)
            LOG.debug(_(" create_port called mech_context.current: %s"),mech_context.current)
            LOG.debug(_(" create_port called mech_context.bound_segment: %s"),mech_context.bound_segment)


            self._process_port_binding(mech_context, attrs)
            result[addr_pair.ADDRESS_PAIRS] = (
                self._process_create_allowed_address_pairs(
                    context, result,
                    attrs.get(addr_pair.ADDRESS_PAIRS)))
            self._process_port_create_extra_dhcp_opts(context, result,
                                                      dhcp_opts)
	    LOG.debug(_(" mechanism_manager called for create_port_precommit"))
            self.mechanism_manager.create_port_precommit(mech_context)


        LOG.debug(_(" mechanism_manager called for create_port_postcommit"))
        try:
            self.mechanism_manager.create_port_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager.create_port_postcommit "
                            "failed, deleting port '%s'"), result['id'])
                self.delete_port(context, result['id'])
        self.notify_security_groups_member_updated(context, result)
        
        LOG.debug(_(" TEST1 called"))
        LOG.debug(_(" context.current: %s"),mech_context.current)
        LOG.debug(_(" context.original: %s"),mech_context.original)
        # LATER IDENTIFY THIS ONLY FOR THE ROUTER-INTERFACES PORTS
        #self.mechanism_manager.update_port_precommit(mech_context)
	#self.mechanism_manager.update_port_postcommit(mech_context)
        LOG.debug(_(" TEST1 called over"))

        LOG.debug(_(" create_port called over"))
	
	
	'''
	if result['device_owner'] == "network:router_interface":
		port_id=result['id']
        	mac_address=result['mac_address']
                network_id=result['network_id']
        	self.internal_network_added_modified(network_id, port_id, mac_address)

        	self.update_port(context, result['id'], {'port': {"binding:host_id": "rhel65-rack1"}})
	'''
	'''
	if mech_driver._binding.vif_type == "unbound":
		port={'port': {'binding:host_id': u'rhel65-rack1'}}
		id= mech_context.current['id']
		self.update_port(mech_context, id, port)
	
	'''
	#port_id=mech_context.current['id']
	#self.update_port_status(context,port_id,"ACTIVE")
	return result

    def update_port(self, context, id, port):
        LOG.debug(_(" update_port called with port: %s"),port)
        LOG.debug(_(" update_port called with id: %s"),id)
        LOG.debug(_(" update_port called with context: %s"),context)
        attrs = port['port']
        need_port_update_notify = False

        session = context.session
        changed_fixed_ips = 'fixed_ips' in port['port']
        with session.begin(subtransactions=True):
            original_port = super(Ml2Plugin, self).get_port(context, id)
            updated_port = super(Ml2Plugin, self).update_port(context, id,
                                                              port)
            if addr_pair.ADDRESS_PAIRS in port['port']:
                self._delete_allowed_address_pairs(context, id)
                self._process_create_allowed_address_pairs(
                    context, updated_port,
                    port['port'][addr_pair.ADDRESS_PAIRS])
                need_port_update_notify = True
            elif changed_fixed_ips:
                self._check_fixed_ips_and_address_pairs_no_overlap(
                    context, updated_port)
            need_port_update_notify |= self.update_security_group_on_port(
                context, id, port, original_port, updated_port)
            network = self.get_network(context, original_port['network_id'])
            need_port_update_notify |= self._update_extra_dhcp_opts_on_port(
                context, id, port, updated_port)
            mech_context = driver_context.PortContext(
                self, context, updated_port, network,
                original_port=original_port)
            need_port_update_notify |= self._process_port_binding(
                mech_context, attrs)
            self.mechanism_manager.update_port_precommit(mech_context)

        # TODO(apech) - handle errors raised by update_port, potentially
        # by re-calling update_port with the previous attributes. For
        # now the error is propogated to the caller, which is expected to
        # either undo/retry the operation or delete the resource.
        self.mechanism_manager.update_port_postcommit(mech_context)

        need_port_update_notify |= self.is_security_group_member_updated(
            context, original_port, updated_port)

        if original_port['admin_state_up'] != updated_port['admin_state_up']:
            need_port_update_notify = True

        if need_port_update_notify:
            self._notify_port_updated(mech_context)
	    ''' 
	    Important call.. notify_port_updated -> /neutron/plugins/ml2/rpc.py
	    The above function calls port_update function from plugin -> agent
	    On OVS Agent port_update received. In agent, in port_update() it calls update_device_up() from agent -> plugin
	    device_update_up() in rpc.py calls plugin.port_bound_to_host and update_port_status
	    '''

        return updated_port

    def delete_port(self, context, id, l3_port_check=True):
        LOG.debug(_("Deleting port called %s"), id)
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if l3plugin and l3_port_check:
            l3plugin.prevent_l3_port_deletion(context, id)

        session = context.session
        with session.begin(subtransactions=True):
            if l3plugin:
                l3plugin.disassociate_floatingips(context, id)
            port = self.get_port(context, id)
            network = self.get_network(context, port['network_id'])
            mech_context = driver_context.PortContext(self, context, port,
                                                      network)
            self.mechanism_manager.delete_port_precommit(mech_context)
            self._delete_port_binding(mech_context)
            self._delete_port_security_group_bindings(context, id)
            LOG.debug(_("Calling base delete_port"))
            super(Ml2Plugin, self).delete_port(context, id)

        try:
            self.mechanism_manager.delete_port_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            # TODO(apech) - One or more mechanism driver failed to
            # delete the port.  Ideally we'd notify the caller of the
            # fact that an error occurred.
            LOG.error(_("mechanism_manager.delete_port_postcommit failed"))
        self.notify_security_groups_member_updated(context, port)

    def update_port_status(self, context, port_id, status):
        LOG.info(_("update_port_status called"))
        updated = False
        
        '''
	if mech_driver._binding.vif_type == "unbound":
                port={'port': {'binding:host_id': u'rhel65-rack1'}}
                id= mech_context.current['id']
                self.update_port(mech_context, id, port)
	'''
        session = context.session
        with session.begin(subtransactions=True):
            port = db.get_port(session, port_id)
	    LOG.debug(_("update_port_status called port: %s"),port)
            LOG.debug(_("update_port_status called status: %s"),status)
            if not port:
                LOG.warning(_("Port %(port)s updated up by agent not found"),
                            {'port': port_id})
                return False
            if port.status != status:
                original_port = self._make_port_dict(port)
                port.status = status
                LOG.debug(_("update_port_status called original_port: %s"),original_port)
                updated_port = self._make_port_dict(port)
                LOG.debug(_("update_port_status called updated_port: %s"),updated_port)
                network = self.get_network(context,
                                           original_port['network_id'])
                LOG.debug(_("update_port_status called network: %s"),network)
                # Update MechContext detail- Creates an object of PortContext having the needed details
		mech_context = driver_context.PortContext(
                    self, context, updated_port, network,
                    original_port=original_port)
        	LOG.debug(_(" update_port_status called with context original: %s"),mech_context.original)
	        LOG.debug(_(" update_port_status called with context curent: %s"),mech_context.current)
        	LOG.debug(_(" update_port_status called with context network: %s"),mech_context.network)
        	LOG.debug(_(" update_port_status called with context binding: %s"),mech_context._binding)
                self.mechanism_manager.update_port_precommit(mech_context)
                updated = True

        if updated:
            self.mechanism_manager.update_port_postcommit(mech_context)

        LOG.info(_("update_port_status called over"))

        return True

    def port_bound_to_host(self, port_id, host):
        LOG.info(_("port_bound_to_host called"))
        port_host = db.get_port_binding_host(port_id)
        LOG.info(_("port_bound_to_host called over"))
        return (port_host == host)


    def internal_network_added_modified(self, network_id, port_id, mac_address):
        LOG.debug(_(" L3 internal network added called"))
        
	'''
	try:
		self.driver = importutils.import_object("neutron.agent.linux.interface.OVSInterfaceDriver", self.conf)
	except Exception:
            msg = _("Error importing interface driver "
                    "'%s'") % self.conf.interface_driver
            LOG.error(msg)
            raise SystemExit(msg)

        '''
	interface_name = self.get_internal_device_name(port_id)
	if not ip_lib.device_exists(interface_name, root_helper=self.root_helper):
            self.plug(network_id, port_id, interface_name, mac_address)			# issue of root_helper


    def get_internal_device_name(self, port_id):
        return (INTERNAL_DEV_PREFIX + port_id)[:self.DEV_NAME_LEN]

    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:self.DEV_NAME_LEN]


    def update_router_interface(self, context, router_id):
    	LOG.debug(_("update_router_interface called context: %s"), context)
        LOG.debug(_("update_router_interface called router_id: %s"), router_id)

	#router = super(L3RouterPlugin, self).sync_routers(context,"rhel65-rack1",router_id)
     	self.l3_rpc_base_obj = l3_rpc_base.L3RpcCallbackMixin()
	router = self.l3_rpc_base_obj.sync_routers(context, host='rhel65-30', router_ids=[router_id] )
	LOG.debug(_("router FLAG1: %s"), router)
	self._process_router(context, router)

 
    def process_routers(self, ri):
	LOG.debug(_("process_router called ri: %s"), ri)
	ex_gw_port = self._get_ex_gw_port(ri)
        internal_ports = ri.router.get('_interfaces')                                                   # get 'interfaces' / all ports from ri.router
        existing_port_ids = set([p['id'] for p in ri.internal_ports])                                                   # already existing ports
        if internal_ports:
		current_port_ids = set([p['id'] for p in internal_ports
					if p['admin_state_up']]) 
	else:
		current_port_ids= set()
        if internal_ports:
        	new_ports = [p for p in internal_ports if
                	     p['id'] in current_port_ids and
                     	     p['id'] not in existing_port_ids]
	else:
		new_ports = []

        if ri.internal_ports:
		old_ports = [p for p in ri.internal_ports if
                	    p['id'] not in current_port_ids]
	else:
		old_ports = []
        
	for p in new_ports:
                self._set_subnet_info(p)
                ri.internal_ports.append(p)
                self.internal_network_added(ri, p['network_id'], p['id'], p['ip_cidr'], p['mac_address'])
	

	internal_cidrs = [p['ip_cidr'] for p in ri.internal_ports]
        ex_gw_port_id = (ex_gw_port and ex_gw_port['id'] or ri.ex_gw_port and ri.ex_gw_port['id'])
        interface_name = None
        if ex_gw_port_id:
            interface_name = self.get_external_device_name(ex_gw_port_id)
        if ex_gw_port and not ri.ex_gw_port:
            self._set_subnet_info(ex_gw_port)
            self.external_gateway_added(ri, ex_gw_port, interface_name, internal_cidrs)

        if ex_gw_port:
            self.process_router_floating_ips(ri, ex_gw_port)

    
    def process_router_floating_ips(self, ri, ex_gw_port):
        """Configure the router's floating IPs
        Configures floating ips in iptables and on the router's gateway device.

        Cleans up floating ips that should not longer be configured.
        """
	LOG.debug(_("process_router_floating_ips called ri: %s"), ri)
	LOG.debug(_("process_router_floating_ips called ex_gw_port: %s"), ex_gw_port)
        interface_name = self.get_external_device_name(ex_gw_port['id'])
        device = ip_lib.IPDevice(interface_name, self.root_helper)

        existing_cidrs = set([addr['cidr'] for addr in device.addr.list()])
        new_cidrs = set()

        # Loop once to ensure that floating ips are configured.
        for fip in ri.router.get(const.FLOATINGIP_KEY, []):
            fip_ip = fip['floating_ip_address']
            ip_cidr = str(fip_ip) + FLOATING_IP_CIDR_SUFFIX

            new_cidrs.add(ip_cidr)

            if ip_cidr not in existing_cidrs:
                net = netaddr.IPNetwork(ip_cidr)
                device.addr.add(net.version, ip_cidr, str(net.broadcast))

    def _process_router(self, context, router ):
	if not ip_lib.device_exists("br-ex"):
        	LOG.error(_("The external network bridge '%s' does not exist"), "br-ex")
                return

        router=router[0]
        LOG.debug(_("router in _process_router called: %s"), router)
	#target_ex_net_id = self._fetch_external_net_id(context)
        if not router['admin_state_up']:
        	return

        #ex_net_id = (router['external_gateway_info'] or {}).get('network_id')
        '''
	All networks handled by common agent
	if ex_net_id and ex_net_id != target_ex_net_id:					# This agent does not manage this external network!
        	return
        '''
	if router['id'] not in self.router_info:
        	ri = RouterInfo(router['id'], self.root_helper, router)
		self.router_info[router['id']] = ri
		#self._router_added(router['id'], router)
        ri = self.router_info[router['id']]
        ri.router = router
	self.process_routers(ri)


    def _fetch_external_net_id(self, context):
        LOG.debug(_(" L3 fetch external id called"))
        """Find UUID of single external network for this agent."""              # Remeber 1 external network per L3 Agent
        try:
        	return self.get_external_network_id(context)               # else ask plugin for the external_netwokr_id
        except rpc_common.RemoteError as e:
        	if e.exc_type == 'TooManyExternalNetworks':
                	msg = _("The 'gateway_external_network_id' option must be configured for this agent as Neutron has more than one external network.")
                raise Exception(msg)

    def _get_ex_gw_port(self, ri):
        return ri.router.get('gw_port')

    def _set_subnet_info(self, port):
    	LOG.debug(_(" L3 set_subnet_info called"))
        ips = port['fixed_ips']
        if not ips:
        	raise Exception(_("Router port %s has no IP address") % port['id'])
        if len(ips) > 1:
        	LOG.error(_("Ignoring multiple IPs on router port %s"), port['id'])
        prefixlen = netaddr.IPNetwork(port['subnet']['cidr']).prefixlen
        port['ip_cidr'] = "%s/%s" % (ips[0]['ip_address'], prefixlen)
        # 'ip_cidr': u'10.10.1.1/24 NOTE ip_cidr NOT subnet_cidr

    def internal_network_added(self, ri, network_id, port_id, internal_cidr, mac_address):
    	LOG.debug(_(" L3 internal network added called"))
	interface_name = self.get_internal_device_name(port_id)
	'''
	try:
                self.driver = importutils.import_object("neutron.agent.linux.interface.OVSInterfaceDriver", self.conf)
        except Exception:
            msg = _("Error importing interface driver")
            LOG.error(msg)
            raise SystemExit(msg)
	'''
        if not ip_lib.device_exists(interface_name, root_helper=self.root_helper):
	        LOG.debug(_(" driver.plug called"))
        	self.plug( network_id, port_id, interface_name, mac_address, prefix=INTERNAL_DEV_PREFIX)

        self.init_l3(interface_name, [internal_cidr] )


    def external_gateway_added(self, ri, ex_gw_port, interface_name, internal_cidrs):
        LOG.debug(_(" external_gateway_added called"))
        if not ip_lib.device_exists(interface_name, root_helper=self.root_helper):
            self.plug( ex_gw_port['network_id'], ex_gw_port['id'], interface_name, ex_gw_port['mac_address'], bridge="br-ex", prefix=EXTERNAL_DEV_PREFIX)
        self.init_l3(interface_name, [ex_gw_port['ip_cidr']])


    def _update_fip_assoc(self, context, fixed_ip, floating_ip, fixed_mac, fixed_network_id, floating_network_id, router_id, floatingip_id, floatingip_mac):
	self.notifier.fip_port_update(context, fixed_ip, floating_ip, fixed_mac, fixed_network_id, floating_network_id, router_id, floatingip_id, floatingip_mac)

	
class RouterInfo(object):

    def __init__(self, router_id, root_helper, router):
        LOG.debug(_("RouterInfo class init called"))
	self.router_id = router_id
        self.ex_gw_port = None
        self.internal_ports = []
        self.root_helper = root_helper
        self._router = router

        self.routes = []

    @property
    def router(self):
        return self._router

    @router.setter
    def router(self, value):
        self._router = value
        if not self._router:
            return
        # enable_snat by default if it wasn't specified by plugin
        self._snat_enabled = self._router.get('enable_snat', True)
        # Set a SNAT action for the router
        if self._router.get('gw_port'):
            self._snat_action = ('add_rules' if self._snat_enabled
                                 else 'remove_rules')
        elif self.ex_gw_port:
            # Gateway port was removed, remove rules
            self._snat_action = 'remove_rules'

