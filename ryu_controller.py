#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp

IP_TO_BEACON = {
    '192.168.1.1': 1, '172.16.1.1': 2, '8.8.8.8': 3, '1.1.1.1': 4, '77.77.77.77': 'all'
}
PORT_TO_TERM = {
    20: 1, 22: 2, 3389: 3, 443: 4, 7777: 'all'
}

class AlertController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.beacon_ports = {}  # dpid -> {term: port}

    def log(self, msg):
        print(f"[CONTROLLER] {msg}")

    @ofp_event.EventOFPSwitchFeatures(CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Default: send all to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

        self.datapaths[dp.id] = dp
        self.log(f"Switch s{dp.id} connected")

        # Auto-detect terminal ports on beacon switches
        if dp.id != 1:
            self.beacon_ports[dp.id] = {}
            for port in range(1, 6):
                if port != 1:  # skip beacon host
                    term_num = port - 1
                    self.beacon_ports[dp.id][term_num] = port

    @ofp_event.EventOFPPacketIn(MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)

        if not ip or not udp_pkt:
            self.drop(dp, in_port)
            return

        beacon = IP_TO_BEACON.get(ip.dst)
        term = PORT_TO_TERM.get(udp_pkt.dst_port)
        if not beacon or not term:
            self.drop(dp, in_port)
            return

        payload = udp_pkt.data.decode(errors='ignore').strip()
        self.log(f"ALERT: '{payload}' -> B{beacon} T{term}")

        beacons = [1,2,3,4] if beacon == 'all' else [beacon]
        terms = [1,2,3,4] if term == 'all' else [term]

        for b in beacons:
            b_dp = self.datapaths.get(b + 1)
            if not b_dp: continue

            # Install flow on Alert Switch (s1)
            if dp.id == 1:
                out_port = b  # s1-eth1 → s2, eth2 → s3, etc.
                match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=17,
                                        ipv4_dst=ip.dst, udp_dst=udp_pkt.dst_port)
                actions = [
                    parser.OFPActionSetField(ipv4_src='254.254.254.254'),
                    parser.OFPActionSetField(ipv4_dst='253.253.253.253'),
                    parser.OFPActionSetField(udp_dst=1),
                    parser.OFPActionOutput(out_port)
                ]
                self.add_flow(dp, 100, match, actions, msg.buffer_id)

            # Install flow on Beacon Switch
            for t in terms:
                out_port = self.beacon_ports[b_dp.id].get(t)
                if out_port:
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_dst='253.253.253.253', udp_dst=1)
                    actions = [parser.OFPActionOutput(out_port)]
                    self.add_flow(b_dp, 100, match, actions)

    def add_flow(self, dp, prio, match, actions, buffer_id=None):
        inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = dp.ofproto_parser.OFPFlowMod(datapath=dp, priority=prio, match=match,
                                           instructions=inst, buffer_id=buffer_id or dp.ofproto.OFP_NO_BUFFER)
        dp.send_msg(mod)

    def drop(self, dp, in_port):
        self.add_flow(dp, 1, dp.ofproto_parser.OFPMatch(in_port=in_port), [])