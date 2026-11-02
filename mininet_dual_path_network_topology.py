#!/usr/bin/env python
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def create_topology():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch)

    info('*** Adding SDN Controller (OS-Ken)\n')
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info('*** Adding Hosts (Client & Backup Servers)\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24') # Client
    srv_a = net.addHost('srv_a', ip='10.0.0.2/24') # Backup Server A
    srv_b = net.addHost('srv_b', ip='10.0.0.3/24') # Backup Server B

    info('*** Adding OpenFlow Switches\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13') # Path A Switch
    s3 = net.addSwitch('s3', protocols='OpenFlow13') # Path B Switch
    s4 = net.addSwitch('s4', protocols='OpenFlow13')

    info('*** Creating Network Links (Path A and Path B)\n')
    # Client to S1
    net.addLink(h1, s1)
    
    # Dual Network Paths between S1 and S4
    net.addLink(s1, s2) # Path A
    net.addLink(s2, s4)
    
    net.addLink(s1, s3) # Path B (Alternative)
    net.addLink(s3, s4)
    
    # S4 to Servers
    net.addLink(s4, srv_a)
    net.addLink(s4, srv_b)

    info('*** Starting Network Topology\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])

    info('*** Network Running. Opening CLI...\n')
    CLI(net)

    info('*** Stopping Network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()