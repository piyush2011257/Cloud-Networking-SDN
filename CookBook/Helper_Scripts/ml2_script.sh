yum -y install openstack-neutron-ml2
[ -h /etc/neutron/plugin.ini ] && unlink /etc/neutron/plugin.ini 
ln -s /etc/neutron/plugins/ml2/ml2_conf.ini /etc/neutron/plugin.ini 
crudini --set /etc/neutron/neutron.conf DEFAULT core_plugin neutron.plugins.ml2.plugin.Ml2Plugin 
crudini --set /etc/neutron/neutron.conf DEFAULT service_plugins neutron.services.l3_router.l3_router_plugin.L3RouterPlugin 
crudini --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2 mechanism_drivers openvswitch,l2population 
crudini --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2 tenant_network_types vxlan 
crudini --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2 type_drivers vxlan 
crudini --set /etc/neutron/plugins/ml2/ml2_conf.ini database sql_connection mysql://neutron:password@9.121.62.30/neutron_ml2 
crudini --set /etc/neutron/plugins/ml2/ml2_conf.ini securitygroup firewall_driver dummy_value_to_enable_security_groups_in_server 
crudini --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2_type_vxlan vni_ranges 5000:8000 
mysql -e "drop database if exists neutron_ml2;" 
mysql -e "create database neutron_ml2 character set utf8;" 
mysql -e "grant all on neutron_ml2.* to 'neutron'@'%';" 
neutron-db-manage --config-file /usr/share/neutron/neutron-dist.conf --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugin.ini upgrade head
