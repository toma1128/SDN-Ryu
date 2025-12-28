from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp, udp, arp

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        print("【SYSTEM】コントローラー起動完了。接続を待っています...")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        print(f"【EVENT】スイッチ接続確認！ DPID: {datapath.id}")

        # 初期化
        self.remove_table_flows(datapath, 0, parser.OFPMatch(), [])
        print("【ACTION】古いルールを全削除しました。")

        # デフォルトルール追加
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        print("【ACTION】デフォルトルール(Packet-In)を設定しました。")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod_args = dict(datapath=datapath, priority=priority, match=match, instructions=inst)
        if buffer_id:
            mod_args['buffer_id'] = buffer_id
        else:
            mod_args['buffer_id'] = ofproto.OFP_NO_BUFFER
            
        mod = parser.OFPFlowMod(**mod_args)
        datapath.send_msg(mod)

    def remove_table_flows(self, datapath, table_id, match, instructions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                match=match, instructions=instructions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # MAC学習
        self.mac_to_port[dpid][src] = in_port

        # 転送先判断
        out_port = ofproto.OFPP_FLOOD
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        
        actions = [parser.OFPActionOutput(out_port)]

        #　詳細解析＆ログ出力
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            src_ip = pkt_ipv4.src
            dst_ip = pkt_ipv4.dst
            
            if not (src_ip.startswith('192.168.') and dst_ip.startswith('192.168.')):
                # プロトコル特定
                proto_name = "IP"
                info = ""
                
                pkt_tcp = pkt.get_protocol(tcp.tcp)
                pkt_udp = pkt.get_protocol(udp.udp)
                
                if pkt_tcp:
                    proto_name = "TCP"
                    info = f"Port {pkt_tcp.dst_port}"
                    if pkt_tcp.bits & tcp.TCP_SYN:
                        info += " [SYN]"
                elif pkt_udp:
                    proto_name = "UDP"
                    info = f"Port {pkt_udp.dst_port}"
                    if pkt_udp.dst_port == 53:
                        proto_name = "DNS"
                
                print(f"📡 {proto_name}: {src_ip} -> {dst_ip} | {info} | OutPort: {out_port}")

        # フロー追加（学習）
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # タイムアウトなしで登録
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)