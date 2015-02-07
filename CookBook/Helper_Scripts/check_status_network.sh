openstack-service status neutron
cat /var/log/neutron/openvswitch-agent.log | grep ERROR
cat /var/log/neutron/openvswitch-agent.log | grep CRITICAL
#cat /var/log/neutron/openvswitch-agent.log | grep WARNING
cat /var/log/neutron/server.log | grep ERROR
cat /var/log/neutron/server.log | grep CRITICAL
#cat /var/log/neutron/server.log | grep WARNING
cat /var/log/neutron/l3-agent.log | grep ERROR
cat /var/log/neutron/l3-agent.log | grep CRITICAL
#cat /var/log/neutron/l3-agent.log | grep WARNING

