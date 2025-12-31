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
        
        # データ管理: IPアドレス → 名前
        self.ip_to_name = {}
        self.log_cache = {}
        self.query_log = {}
        
        # 自分(OVS)のIP
        self.MY_IP = "192.168.0.254"
        
        # 非同期検索設定
        self.resolve_queue = queue.Queue()
        self.pending_ips = set()
        
        self.worker_thread = threading.Thread(target=self._resolver_loop, daemon=True)
        self.worker_thread.start()

        print("SYSTEM: IP-Only Monitor Started (Simple Mode)")

    # IP逆引き
    def _resolver_loop(self):
        while True:
            try:
                ip_addr = self.resolve_queue.get()
                # 既にmDNSできれいな名前がわかっているならDNS検索しない
                if ip_addr in self.ip_to_name and not self.ip_to_name[ip_addr].startswith(ip_addr):
                    pass 
                else:
                    try:
                        hostname, _, _ = socket.gethostbyaddr(ip_addr)
                        self.ip_to_name[ip_addr] = hostname
                    except socket.herror:
                        pass # 名前がなければ何もしない
                    except Exception:
                        pass
                
                if ip_addr in self.pending_ips:
                    self.pending_ips.remove(ip_addr)
                self.resolve_queue.task_done()
                time.sleep(0.1) 
            except Exception:
                pass

    # 表示名取得
    def get_display_name(self, ip):
        # 知っている名前があればそれを返す
        if ip in self.ip_to_name:
            name = self.ip_to_name[ip]
            if "192.168." in ip:
                return f"[{name}]"
            return f"({name})"
        
        # 知らなければ検索キューに入れてIPを返す
        if ip not in self.pending_ips:
            # 外部IPはDNS検索
            if not ip.startswith("192.168."):
                self.pending_ips.add(ip)
                self.resolve_queue.put(ip)
        return f"({ip})"

    # mDNS質問パケット送信
    def send_mdns_query(self, datapath, target_ip):
        now = time.time()
        if target_ip in self.query_log and now - self.query_log[target_ip] < 10:
            return
        self.query_log[target_ip] = now

        rev_ip = ".".join(reversed(target_ip.split("."))) + ".in-addr.arpa"
        
        # OVSのIPを指定
        pkt = Ether(src="02:00:00:00:00:01", dst="01:00:5e:00:00:fb") / \
              IP(src=self.MY_IP, dst="224.0.0.251") / \
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
            
            # DHCP監視
            if scapy_pkt.haslayer(DHCP):
                if scapy_pkt.haslayer(IP):
                    src_ip = scapy_pkt[IP].src
                    # Requestパケットなどで0.0.0.0の場合は無視
                    if src_ip != "0.0.0.0":
                        for opt in scapy_pkt[DHCP].options:
                            if isinstance(opt, tuple) and opt[0] == 'hostname':
                                name = opt[1].decode('utf-8', 'ignore')
                                self.ip_to_name[src_ip] = name
                                break

            # mDNS監視
            if scapy_pkt.haslayer(UDP) and scapy_pkt[UDP].sport == 5353:
                if scapy_pkt.haslayer(IP) and scapy_pkt.haslayer(DNS):
                    src_ip = scapy_pkt[IP].src
                    dns = scapy_pkt[DNS]                
                    found_name = None
                    if dns.ancount > 0:
                        for i in range(dns.ancount):
                            rr = dns.an[i]
                            candidate = None
                            
                            # 名前候補の抽出
                            if hasattr(rr, 'rdata') and isinstance(rr.rdata, bytes):
                                try:
                                    candidate = rr.rdata.decode('utf-8', 'ignore')
                                except: pass
                            elif hasattr(rr, 'rrname'):
                                try:
                                    candidate = rr.rrname.decode('utf-8', 'ignore')
                                except: pass
                            
                            # フィルタリング
                            if candidate:
                                if ('._tcp' in candidate or 
                                    '._udp' in candidate or 
                                    '_sub' in candidate or
                                    '@' in candidate):
                                    continue
                                
                                # .local で終わる名前を採用
                                if candidate.endswith('.local.'):
                                    found_name = candidate.rstrip('.')
                                    break
                    
                    if found_name:
                        self.ip_to_name[src_ip] = found_name

            # パケットログ出力
            if scapy_pkt.haslayer(IP):
                src_ip = scapy_pkt[IP].src
                dst_ip = scapy_pkt[IP].dst
                
                # 自分自身の通信は無視
                if src_ip == self.MY_IP or dst_ip == self.MY_IP:
                    return

                # ノイズ除去
                if dst_ip.endswith(".255") or dst_ip.startswith("224.") or dst_ip.startswith("239."):
                    return

                # 名前を知らない端末があったらホスト名を聞く
                if src_ip.startswith("192.168.") and src_ip not in self.ip_to_name:
                    self.send_mdns_query(datapath, src_ip)

                protocol = ""
                if scapy_pkt.haslayer(TCP): protocol = "TCP"
                elif scapy_pkt.haslayer(UDP): protocol = "UDP"

                if protocol:
                    # DNS通信除外
                    is_dns_traffic = (scapy_pkt.haslayer(UDP) and 
                                     (scapy_pkt[UDP].sport == 53 or scapy_pkt[UDP].dport == 53 or 
                                      scapy_pkt[UDP].sport == 5353 or scapy_pkt[UDP].dport == 5353))
                    
                    if not is_dns_traffic:
                        current_time = time.time()
                        cache_key = (src_ip, dst_ip, protocol) 
                        
                        if current_time - self.log_cache.get(cache_key, 0) > 2.0:
                            src_show = self.get_display_name(src_ip)
                            dst_show = self.get_display_name(dst_ip)
                            
                            print(f"{src_show} -> {dst_show} | {protocol}")
                            self.log_cache[cache_key] = current_time

        except Exception:
            pass