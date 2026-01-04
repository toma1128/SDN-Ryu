import time
import logging
import threading
import queue
import socket
import json
import urllib.request
import re
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
        
        self.ip_to_name = {}
        self.log_cache = {}
        self.query_log = {}
        self.MY_IP = "192.168.0.254"
        
        # APIリクエスト制限対策
        self.api_checked_ips = set()
        
        self.resolve_queue = queue.Queue()
        self.pending_ips = set()
        
        self.worker_thread = threading.Thread(target=self._resolver_loop, daemon=True)
        self.worker_thread.start()

        print("SYSTEM: Monitor Started (External API Mode)")

    # UUIDフィルタ
    def is_uuid(self, name):
        pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        return re.search(pattern, name) is not None

    # APIを使って組織名を取得
    def fetch_org_from_api(self, ip_addr):
        if ip_addr.startswith("192.168.") or ip_addr.startswith("10."):
            return None
        
        url = f"http://ip-api.com/json/{ip_addr}?fields=status,org,isp"
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                data = json.loads(response.read().decode())
                if data.get('status') == 'success':
                    org = data.get('org', '')
                    if not org:
                        org = data.get('isp', '')
                    return org
        except Exception:
            return None
        return None

    # バックグラウンド処理
    def _resolver_loop(self):
        while True:
            try:
                ip_addr = self.resolve_queue.get()
                
                if ip_addr not in self.ip_to_name and ip_addr not in self.api_checked_ips:
                    # 外部IPならAPI
                    if not ip_addr.startswith("192.168."):
                        org_name = self.fetch_org_from_api(ip_addr)
                        if org_name:
                            self.ip_to_name[ip_addr] = org_name
                        else:
                            try:
                                hostname, _, _ = socket.gethostbyaddr(ip_addr)
                                self.ip_to_name[ip_addr] = hostname
                            except:
                                pass
                        self.api_checked_ips.add(ip_addr)
                    # 内部IPならDNS逆引き
                    else:
                        try:
                            hostname, _, _ = socket.gethostbyaddr(ip_addr)
                            self.ip_to_name[ip_addr] = hostname
                        except:
                            pass

                if ip_addr in self.pending_ips:
                    self.pending_ips.remove(ip_addr)
                self.resolve_queue.task_done()
                time.sleep(1.5) 
            except Exception:
                pass

    def get_display_name(self, ip):
        if ip in self.ip_to_name:
            name = self.ip_to_name[ip]
            if "192.168." in ip:
                return f"[{name}]"
            return f"({name})"
        
        if ip not in self.pending_ips:
            if not ip.startswith("192.168.") and ip not in self.api_checked_ips:
                self.pending_ips.add(ip)
                self.resolve_queue.put(ip)
        
        return f"({ip})"

    def send_mdns_query(self, datapath, target_ip):
        now = time.time()
        if target_ip in self.query_log and now - self.query_log[target_ip] < 10:
            return
        self.query_log[target_ip] = now

        rev_ip = ".".join(reversed(target_ip.split("."))) + ".in-addr.arpa"
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
            if scapy_pkt.haslayer(DHCP) and scapy_pkt.haslayer(IP):
                src_ip = scapy_pkt[IP].src
                if src_ip != "0.0.0.0":
                    for opt in scapy_pkt[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == 'hostname':
                            name = opt[1].decode('utf-8', 'ignore')
                            self.ip_to_name[src_ip] = name
                            break

            # DNS/mDNS解析
            if scapy_pkt.haslayer(UDP) and scapy_pkt.haslayer(DNS):
                dns = scapy_pkt[DNS]
                sport = scapy_pkt[UDP].sport
                dport = scapy_pkt[UDP].dport
                
                # DNS Snooping
                if sport == 53 or dport == 53:
                    if dns.ancount > 0:
                        for i in range(dns.ancount):
                            rr = dns.an[i]
                            if rr.type == 1: 
                                if hasattr(rr, 'rrname') and hasattr(rr, 'rdata'):
                                    domain = rr.rrname.decode('utf-8', 'ignore').rstrip('.')
                                    ip_addr = rr.rdata
                                    if ip_addr not in self.ip_to_name:
                                        self.ip_to_name[ip_addr] = domain

                # mDNS解析
                elif sport == 5353:
                    if scapy_pkt.haslayer(IP):
                        src_ip = scapy_pkt[IP].src
                        found_name = None
                        if dns.ancount > 0:
                            for i in range(dns.ancount):
                                rr = dns.an[i]
                                candidate = None
                                if hasattr(rr, 'rdata') and isinstance(rr.rdata, bytes):
                                    try: candidate = rr.rdata.decode('utf-8', 'ignore')
                                    except: pass
                                elif hasattr(rr, 'rrname'):
                                    try: candidate = rr.rrname.decode('utf-8', 'ignore')
                                    except: pass
                                
                                if candidate:
                                    if ('._tcp' in candidate or '._udp' in candidate or '_sub' in candidate or '@' in candidate):
                                        continue
                                    if self.is_uuid(candidate):
                                        continue
                                    if candidate.endswith('.local.'):
                                        found_name = candidate.rstrip('.')
                                        break
                        if found_name:
                            self.ip_to_name[src_ip] = found_name

            # ログ出力
            if scapy_pkt.haslayer(IP):
                src_ip = scapy_pkt[IP].src
                dst_ip = scapy_pkt[IP].dst
                
                if src_ip == self.MY_IP or dst_ip == self.MY_IP:
                    return
                if dst_ip.endswith(".255") or dst_ip.startswith("224.") or dst_ip.startswith("239."):
                    return

                # 未学習ローカル端末には質問
                if src_ip.startswith("192.168.") and src_ip not in self.ip_to_name:
                    self.send_mdns_query(datapath, src_ip)

                # 未学習グローバルIPはAPIキューへ
                if not src_ip.startswith("192.168.") and src_ip not in self.api_checked_ips:
                    if src_ip not in self.pending_ips:
                        self.pending_ips.add(src_ip)
                        self.resolve_queue.put(src_ip)
                
                if not dst_ip.startswith("192.168.") and dst_ip not in self.api_checked_ips:
                    if dst_ip not in self.pending_ips:
                        self.pending_ips.add(dst_ip)
                        self.resolve_queue.put(dst_ip)

                protocol = ""
                if scapy_pkt.haslayer(TCP): protocol = "TCP"
                elif scapy_pkt.haslayer(UDP): protocol = "UDP"

                if protocol:
                    is_dns_traffic = (scapy_pkt.haslayer(UDP) and (sport == 53 or dport == 53 or sport == 5353 or dport == 5353))
                    
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