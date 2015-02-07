# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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

import abc

import netaddr

from neutron.agent.linux import ip_lib
from neutron.agent.linux import ovs_lib
from neutron.agent.linux import utils
from neutron.common import exceptions
from neutron.extensions.flavor import (FLAVOR_NETWORK)
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class LinuxInterfaceDriver(object):
    __metaclass__ = abc.ABCMeta

    # from linux IF_NAMESIZE
    DEV_NAME_LEN = 14
    DEV_NAME_PREFIX = 'tap'

    def __init__(self, conf):
        self.conf = conf
        self.root_helper = config.get_root_helper(conf)

    def init_l3(self, device_name, ip_cidrs, namespace=None):
        """Set the L3 settings for the interface using data from the port.
        ip_cidrs: list of 'X.X.X.X/YY' strings
        """
        LOG.debug(_("init_l3 called device_name: %s"), device_name)
        LOG.debug(_("init_l3 called ip_cidrs"), ip_cidrs)
        device = ip_lib.IPDevice(device_name, self.root_helper, namespace=namespace)

        LOG.debug(_("init_l3 called device: %s"), device)
        previous = {}
        for address in device.addr.list(scope='global', filters=['permanent']):
            previous[address['cidr']] = address['ip_version']

        LOG.debug(_("init_l3 called previous: %s"), previous)
        # add new addresses
        for ip_cidr in ip_cidrs:

            net = netaddr.IPNetwork(ip_cidr)
            if ip_cidr in previous:
                del previous[ip_cidr]
                continue

            LOG.debug(_("init_l3 called ip_cidr: %s"), ip_cidr)
            device.addr.add(net.version, ip_cidr, str(net.broadcast))

        # clean up any old addresses
        for ip_cidr, ip_version in previous.items():
            device.addr.delete(ip_version, ip_cidr)

    def check_bridge_exists(self, bridge):
        if not ip_lib.device_exists(bridge):
            raise exceptions.BridgeDoesNotExist(bridge=bridge)

    def get_device_name(self, port):
        return (self.DEV_NAME_PREFIX + port.id)[:self.DEV_NAME_LEN]

    @abc.abstractmethod
    def plug(self, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None, prefix=None):
        """Plug in the interface."""



class OVSInterfaceDriver(LinuxInterfaceDriver):
    """Driver for creating an internal interface on an OVS bridge."""

    DEV_NAME_PREFIX = 'tap'

    def __init__(self, conf):
        super(OVSInterfaceDriver, self).__init__(conf)

    def _get_tap_name(self, dev_name, prefix=None):
        return dev_name

    def _ovs_add_port(self, bridge, device_name, port_id, mac_address, internal=True):
        cmd = ['ovs-vsctl', '--', '--if-exists', 'del-port', device_name, '--', 'add-port', bridge, device_name]
        if internal:
            cmd += ['--', 'set', 'Interface', device_name, 'type=internal']
        cmd += ['--', 'set', 'Interface', device_name,
                'external-ids:iface-id=%s' % port_id,
                '--', 'set', 'Interface', device_name,
                'external-ids:iface-status=active',
                '--', 'set', 'Interface', device_name,
                'external-ids:attached-mac=%s' % mac_address]
        utils.execute(cmd, self.root_helper)

    def plug(self, network_id, port_id, device_name, mac_address, bridge=None,  prefix=None):
        """Plug in the interface."""
        if not bridge:
		bridge = "br-int"
	self.check_bridge_exists(bridge)
        if not ip_lib.device_exists(device_name, self.root_helper):

            ip = ip_lib.IPWrapper(self.root_helper)
            tap_name = self._get_tap_name(device_name, prefix)
            ns_dev = ip.device(device_name)
            self._ovs_add_port(bridge, tap_name, port_id, mac_address, internal=True)
            ns_dev.link.set_address(mac_address)
            ns_dev.link.set_up()
        else:
            LOG.warn(_("Device %s already exists"), device_name)

