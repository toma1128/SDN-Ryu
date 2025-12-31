import time
import logging
import threading
import queue
import socket
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.dhcp import DHCP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class SimpleMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        
        # データ管理
        self.mac_to_name = {}
        self.ip_to_domain = {}
        self.log_cache = {}
        self.query_log = {}
        
        # 非同期検索設定
        self.resolve_queue = queue.Queue()
        self.pending_ips = set()
        
        self.worker_thread = threading.Thread(target=self._resolver_loop, daemon=True)
        self.worker_thread.start()

        print("SYSTEM: Active Monitor Mode Started (All Traffic)")

    # 別スレッドでのIP逆引き
    def _resolver_loop(self):
        while True:
            try:
                ip_addr = self.resolve_queue.get()
                try:
                    hostname, _, _ = socket.gethostbyaddr(ip_addr)
                    self.ip_to_domain[ip_addr] = hostname
                except socket.herror:
                    self.ip_to_domain[ip_addr] = ip_addr 
                except Exception:
                    pass
                
                if ip_addr in self.pending_ips:
                    self.pending_ips.remove(ip_addr)
                self.resolve_queue.task_done()
                time.sleep(0.1) 
            except Exception:
                pass

    # 表示名取得
    def get_display_name(self, mac, ip):
        if mac in self.mac_to_name:
            return f"[{self.mac_to_name[mac]}]"
        if ip in self.ip_to_domain:
             return f"({self.ip_to_domain[ip]})"
        if ip not in self.pending_ips:
            if not ip.startswith("192.168."):
                self.pending_ips.add(ip)
                self.resolve_queue.put(ip)
        return f"({ip})"

    # mDNS質問パケット送信 (職務質問)
    def send_mdns_query(self, datapath, target_ip):
        # 30秒に1回制限
        now = time.time()
        if target_ip in self.query_log and now - self.query_log[target_ip] < 30:
            return
        self.query_log[target_ip] = now

        # 逆引き用アドレス作成
        rev_ip = ".".join(reversed(target_ip.split("."))) + ".in-addr.arpa"
        
        # srcはOVSのIPを指定して信頼させる
        pkt = Ether(src="02:00:00:00:00:01", dst="01:00:5e:00:00:fb") / \
              IP(src="192.168.0.254", dst="224.0.0.251") / \
              UDP(sport=5353, dport=5353) / \
              DNS(rd=1, qd=DNSQR(qname=rev_ip, qtype='PTR'))
        
        data = pkt.build()
        actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        try:
            scapy_pkt = Ether(msg.data)
            src_mac = scapy_pkt.src
            
            # DHCP監視
            if scapy_pkt.haslayer(DHCP):
                for opt in scapy_pkt[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == 'hostname':
                        name = opt[1].decode('utf-8', 'ignore')
                        self.mac_to_name[src_mac] = name
                        break

            # mDNS監視
            if scapy_pkt.haslayer(UDP) and scapy_pkt[UDP].dport == 5353:
                if scapy_pkt.haslayer(DNS):
                    dns = scapy_pkt[DNS]
                    found_name = None
                    if dns.ancount > 0:
                        for i in range(dns.ancount):
                            rr = dns.an[i]
                            # A/AAAAレコード
                            if rr.type in [1, 28]: 
                                if hasattr(rr, 'rrname'):
                                    rname = rr.rrname.decode('utf-8', 'ignore')
                                    if rname.endswith('.local.') and not rname.startswith('_'):
                                        found_name = rname.rstrip('.')
                            # PTRレコード
                            elif rr.type == 12: 
                                if hasattr(rr, 'rdata'):
                                    rdata = rr.rdata.decode('utf-8', 'ignore')
                                    if rdata.endswith('.local.') and not rdata.startswith('_'):
                                        found_name = rdata.rstrip('.')
                            if found_name: break
                    
                    if found_name and src_mac not in self.mac_to_name:
                        self.mac_to_name[src_mac] = found_name

            # パケット処理
            if scapy_pkt.haslayer(IP):
                src_ip = scapy_pkt[IP].src
                dst_ip = scapy_pkt[IP].dst
                dst_mac = scapy_pkt.dst

                # ノイズ除去
                if dst_ip.endswith(".255") or dst_ip.startswith("224.") or dst_ip.startswith("239.") or dst_ip == "255.255.255.255":
                    return

                # 名前未学習端末には名前質問を投げる
                if src_ip.startswith("192.168.") and src_mac not in self.mac_to_name:
                    self.send_mdns_query(datapath, src_ip)

                protocol = ""
                if scapy_pkt.haslayer(TCP): protocol = "TCP"
                elif scapy_pkt.haslayer(UDP): protocol = "UDP"

                if protocol:
                    is_dns_traffic = (scapy_pkt.haslayer(UDP) and 
                                     (scapy_pkt[UDP].sport == 53 or scapy_pkt[UDP].dport == 53 or 
                                      scapy_pkt[UDP].sport == 5353 or scapy_pkt[UDP].dport == 5353))
                    
                    if not is_dns_traffic:
                        current_time = time.time()
                        cache_key = (src_mac, dst_ip, protocol) 
                        
                        if current_time - self.log_cache.get(cache_key, 0) > 2.0:
                            src_show = self.get_display_name(src_mac, src_ip)
                            dst_show = self.get_display_name(dst_mac, dst_ip)
                            
                            print(f"{src_show} -> {dst_show} | {protocol}")
                            self.log_cache[cache_key] = current_time

        except Exception:
            pass