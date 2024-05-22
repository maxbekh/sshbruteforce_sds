from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, arp, dhcp, ipv4, ether_types
import logging

HOSTS = {}
PORT_COUNT = {}
ARP_FLOOD_THRESHOLD = 20
IDLE_TIMEOUT = 60
HARD_TIMEOUT = 60
ARP_PRIORITY = 2
PACKET_IN_PRIORITY = 1
DROP_PRIORITY = 20

class ARPFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] 
    
    def __init__(self, *args, **kwargs):
        super(ARPFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        self.add_flow(datapath, 0, parser.OFPMatch(), [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)])

        # Install ARP packet match entry
        self.add_flow(datapath, ARP_PRIORITY, parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP), [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)])

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst) if buffer_id else \
              parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def drop_packets_from_port(self, datapath, in_port):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port)
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_CLEAR_ACTIONS, [])]
        mod = parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=IDLE_TIMEOUT, hard_timeout=HARD_TIMEOUT, priority=DROP_PRIORITY, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info(f"Dropping all packets from port {in_port}")

    def handle_arp(self, pkt_arp, msg):
        arp_src_ip = pkt_arp.src_ip
        arp_dst_ip = pkt_arp.dst_ip
        arp_src_mac = pkt_arp.src_mac
        arp_dst_mac = pkt_arp.dst_mac
        in_port = msg.match['in_port']

        if in_port not in PORT_COUNT:
            PORT_COUNT[in_port] = 1
        else:
            if PORT_COUNT[in_port] > ARP_FLOOD_THRESHOLD:
                self.logger.warning("ARP Flood Attack detected on port %s! \n %s is sending %s packets", in_port, arp_src_mac, PORT_COUNT[in_port])
                self.drop_packets_from_port(msg.datapath, in_port)
                return True
            if pkt_arp.opcode == arp.ARP_REQUEST:
                PORT_COUNT[in_port] += 1

        self.logger.debug(f"ARP Source IP: {arp_src_ip}, Destination IP: {arp_dst_ip}, Source MAC: {arp_src_mac}, Destination MAC: {arp_dst_mac}")

        if arp_src_ip in HOSTS and HOSTS[arp_src_ip] != arp_src_mac:
            self.logger.warning("ARP spoofing detected: IP %s has conflicting MACs (%s and %s)", arp_src_ip, HOSTS[arp_src_ip], arp_src_mac)
            self.drop_packets_from_port(msg.datapath, in_port)
            return True

        return False

    def handle_dhcp(self, pkt_dhcp):
        if pkt_dhcp.op == dhcp.DHCP_ACK:
            self.logger.info(f"DHCP ACK: IP {pkt_dhcp.yiaddr}, MAC {pkt_dhcp.chaddr}")
            HOSTS[pkt_dhcp.yiaddr] = pkt_dhcp.chaddr
            self.logger.debug(f"Updated host list: {HOSTS}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)

        if pkt_arp:
            if self.handle_arp(pkt_arp, msg):
                return

        if pkt_dhcp:
            self.handle_dhcp(pkt_dhcp)

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, PACKET_IN_PRIORITY, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, PACKET_IN_PRIORITY, match, actions)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
