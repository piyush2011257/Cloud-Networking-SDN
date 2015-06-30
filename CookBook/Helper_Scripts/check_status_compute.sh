openstack-service status neutron
cat /var/log/neutron/openvswitch-agent.log | grep ERROR
cat /var/log/neutron/openvswitch-agent.log | grep CRITICAL
#cat /var/log/neutron/openvswitch-agent.log | grep WARNING

