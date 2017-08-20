from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet, ethernet, ipv4, vlan
from logging import getLogger, DEBUG, Formatter
from logging.handlers import RotatingFileHandler as RFH
from datetime import datetime


class NAVT(app_manager.RyuApp):
    """
    Translate IP address by VLAN id
    [internal] vid, ip <==> [external] ip(10.(vid // 100).ip[2].ip[3])

    - IP
    - ARP

    Example:
    Team 1
    [internal] VLAN 100, IP 192.168.0.1 <==> [external] IP 10.1.0.1
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    INTERNAL_PORT = 1
    INTERNAL_IP_SEG = ["192", "168"]
    EXTERNAL_PORT = 2
    EXTERNAL_IP_SEG = ["10"]
    VLAN_SEG = 100
    VLAN_SUFFIX = 0
    TEAMS_RANGE = range(1, 16)

    def __init__(self, *args, **kwargs):
        super(NAVT, self).__init__(*args, **kwargs)
        # self.logger = getLogger(__name__)
        # times = str(datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
        # file_handler = RFH('./log/' + times + 'ictsc7navit.log', 'a+', 100000, 100)
        # log_fmt = '%(asctime)s- %(name)s - %(levelname)s - %(message)s'
        # file_handler.setFormatter(Formatter(log_fmt))
        # file_handler.level = DEBUG
        # self.logger.addHandler(file_handler)
        # self.logger.setLevel(DEBUG)
        # self.logger.debug('Init')


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        self.logger.info('Controller entry initialzing')
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # when no matched entries, packet in
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, 0)

        # ARP proxy
        for team_id in self.TEAMS_RANGE:
            vid = self.get_vid(team_id)

            # internal to external
            match = parser.OFPMatch(vlan_vid=(0x1000 | vid),
                                    eth_type=ether.ETH_TYPE_ARP,
                                    in_port=self.INTERNAL_PORT)
            actions = [parser.OFPActionPopVlan(),
                       parser.OFPActionOutput(self.EXTERNAL_PORT)]
            self.add_flow(datapath, 20000, match, actions, 60)

            # external to internal
            match = parser.OFPMatch(in_port=self.EXTERNAL_PORT,
                                    eth_type=ether.ETH_TYPE_ARP)
            actions = [parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
                       parser.OFPActionSetField(vlan_vid=vid | ofproto_v1_3.OFPVID_PRESENT),
                       parser.OFPActionOutput(self.INTERNAL_PORT)]
            self.add_flow(datapath, 20000, match, actions, 60)

        self.logger.info('  Switch ID: %d' % datapath.id)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return
        eth_type = pkt_ethernet.ethertype
        if eth_type == ether.ether.ETH_TYPE_8021Q:
            pkt_vlan = pkt.get_protocol(vlan.vlan)
            eth_type = pkt_vlan.ethertype

        if eth_type == ether.ETH_TYPE_IP:
            if in_port == self.INTERNAL_PORT:
                self._in2ex_ip(datapath, pkt)
            elif in_port == self.EXTERNAL_PORT:
                self._ex2in_ip(datapath, pkt)
            else:
                self.logger.warn("Get packets from invalid port: %d", in_port)
        # elif eth_type == ether.ETH_TYPE_ARP:
        #     if in_port == self.INTERNAL_PORT:
        #         self._in2ex_ip(datapath, pkt)
        #     elif in_port == self.EXTERNAL_PORT:
        #         self._ex2in_ip(datapath, pkt)
        #     else:
        #         self.logger.warn("Get packets from invalid port: %d", in_port)
        return


    def get_vid(self, team_id):
        return int(team_id) * self.VLAN_SEG + self.VLAN_SUFFIX


    def translate_ip(self, ip_addr, vid=None):
        """
        @param ip_addr str
        @param vid int
        @return (external_ip, internal_ip, vid) but when input invalid params, return None
        """
        ip_seg = ip_addr.split('.')
        if vid:
            if ip_seg[0] == self.INTERNAL_IP_SEG[0] and ip_seg[1] == self.INTERNAL_IP_SEG[1]:
                team_id = vid // self.VLAN_SEG
                internal_ip = ip_addr
                external_ip = "%s.%s.%s.%s" % (self.EXTERNAL_IP_SEG[0], str(team_id), ip_seg[2], ip_seg[3])
            else:
                return
        else:
            if ip_seg[0] == self.EXTERNAL_IP_SEG[0]:
            # if ip_seg[0] == self.EXTERNAL_IP_SEG[0] and int(ip_seg[1]) in self.TEAMS_RANGE:
                team_id = ip_seg[3]
                vid = self.get_vid(team_id)
                internal_ip = "%s.%s.%s.%s" % (self.INTERNAL_IP_SEG[0], self.INTERNAL_IP_SEG[1], ip_seg[2], ip_seg[3])
                external_ip = ip_addr
            else:
                return
        return (external_ip, internal_ip, vid)


    def add_flow(self, datapath, priority, match, actions, idle_timeout):
        """
        フローエントリ追加
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)


    def _in2ex_ip(self, datapath, pkt):
        self.logger.info("Internal network to External network")
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_vlan = pkt.get_protocol(vlan.vlan)
        if pkt_vlan:
            src_vlan = pkt_vlan.vid
        else:
            self.logger.warn("  No vid packets from internal")            
            return
        self.logger.info("  Input IP %s, VLAN %s" % (pkt_ipv4, src_vlan))

        try:
            (ex_ip, in_ip, vid) = self.translate_ip(pkt_ipv4.dst)
        except TypeError:
            self.logger.warn("  Invalid translating IP")
            return

        self.logger.info("  Translated ex_ip %s, in_ip %s, vid %s" % (ex_ip, in_ip, vid))
        parser = datapath.ofproto_parser

        # internal to external
        match = parser.OFPMatch(vlan_vid=(0x1000 | vid),
                                eth_type=ether.ETH_TYPE_IP,
                                in_port=self.INTERNAL_PORT,
                                ipv4_src=in_ip)
        actions = [parser.OFPActionPopVlan(),
                   parser.OFPActionSetField(ipv4_src=ex_ip),
                   parser.OFPActionOutput(self.EXTERNAL_PORT)]
        self.add_flow(datapath, 30000, match, actions, 60)

        # external to internal
        match = parser.OFPMatch(in_port=self.EXTERNAL_PORT,
                                eth_type=ether.ETH_TYPE_IP,
                                ipv4_dst=in_ip)
        actions = [parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
                   parser.OFPActionSetField(vlan_vid=vid | ofproto_v1_3.OFPVID_PRESENT),
                   parser.OFPActionSetField(ipv4_dst=in_ip),
                   parser.OFPActionOutput(self.INTERNAL_PORT)]
        self.add_flow(datapath, 30000, match, actions, 60)


    def _ex2in_ip(self, datapath, pkt):
        self.logger.info("External network to Internal network")
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        self.logger.info("  Input IP %s, VLAN %s" % (pkt_ipv4))

        try:
            (ex_ip, in_ip, vid) = self.translate_ip(pkt_ipv4.dst)
        except TypeError:
            self.logger.warn("  Invalid translating IP")
            return

        self.logger.info("  Translated ex_ip %s, in_ip %s, vid %s" % (ex_ip, in_ip, vid))
        parser = datapath.ofproto_parser

        # external to internal
        match = parser.OFPMatch(in_port=self.EXTERNAL_PORT,
                                eth_type=ether.ETH_TYPE_IP,
                                ipv4_dst=ex_ip)
        actions = [parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
                   parser.OFPActionSetField(vlan_vid=vid | ofproto_v1_3.OFPVID_PRESENT),
                   parser.OFPActionSetField(ipv4_dst=in_ip),
                   parser.OFPActionOutput(self.INTERNAL_PORT)]
        self.add_flow(datapath, 30000, match, actions, 60)

        # internal to external
        match = parser.OFPMatch(in_port=self.INTERNAL_PORT,
                                eth_type=ether.ETH_TYPE_IP,
                                vlan_vid=(0x1000 | vid),
                                ipv4_src=in_ip)
        actions = [parser.OFPActionPopVlan(),
                   parser.OFPActionSetField(ipv4_src=ex_ip),
                   parser.OFPActionOutput(self.EXTERNAL_PORT)]
        self.add_flow(datapath, 30000, match, actions, 60)
