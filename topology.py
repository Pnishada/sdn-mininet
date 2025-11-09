#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, Host
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def militaryAlertNet():
    net = Mininet(controller=Controller, switch=OVSSwitch, link=TCLink)

    # Controller
    c0 = net.addController('c0', port=6633)

    # Alert Terminal + Switch
    s1 = net.addSwitch('s1', dpid='0000000000000001')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    net.addLink(h1, s1)

    # 4 Beacons
    for b in range(1, 5):
        bh = net.addHost(f'b{b}', mac=f'00:00:00:00:0{b}:00')
        bs = net.addSwitch(f's{b+1}', dpid=f'000000000000000{b+1}')
        net.addLink(bh, bs)
        net.addLink(s1, bs)

        for t in range(1, 5):
            term = net.addHost(f'b{b}t{t}', mac=f'00:00:00:00:0{b}:0{t}')
            net.addLink(term, bs)

    net.start()
    c0.start()

    # Fake default gateway + ARP
    h1.cmd('ip route add default via 10.0.0.254 dev h1-eth0')
    s1_mac = s1.intf('s1-eth1').mac
    h1.cmd(f'arp -s 10.0.0.254 {s1_mac}')

    print("*** Network ready. Type 'exit' to stop.")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    militaryAlertNet()