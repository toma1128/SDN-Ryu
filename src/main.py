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

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class SimpleMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        
        # データ管理
        self.ip_to_name = {}      # IP -> ドメイン名のキャッシュ
        self.log_cache = {}       # ログ重複防止用
        
        # 非同期検索設定
        self.resolve_queue = queue.Queue()
        self.pending_ips = set()
        
        self.worker_thread = threading.Thread(target=self._resolver_loop, daemon=True)
        self.worker_thread.start()

        print("SYSTEM: Simple IP Monitor Mode Started")

    # IP逆引き
    def _resolver_loop(self):
        while True:
            try:
                ip_addr = self.resolve_queue.get()
                
                try:
                    hostname, _, _ = socket.gethostbyaddr(ip_addr)
                    self.ip_to_name[ip_addr] = hostname
                except socket.herror:
                    self.ip_to_name[ip_addr] = ip_addr # 名前がなければIP
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
        # キャッシュにあれば名前を返す
        if ip in self.ip_to_name:
            return f"({self.ip_to_name[ip]})"
        
        # なければ検索し、一旦IPを返す
        if ip not in self.pending_ips:
            self.pending_ips.add(ip)
            self.resolve_queue.put(ip)
        
        return f"({ip})"

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        try:
            scapy_pkt = Ether(msg.data)
            
            # IPパケットのみ処理
            if scapy_pkt.haslayer(IP):
                src_ip = scapy_pkt[IP].src
                dst_ip = scapy_pkt[IP].dst

                # ノイズ除去 (ブロードキャスト・マルチキャスト)
                if dst_ip.endswith(".255") or dst_ip.startswith("224.") or dst_ip.startswith("239.") or dst_ip == "255.255.255.255":
                    return

                protocol = ""
                if scapy_pkt.haslayer(TCP): protocol = "TCP"
                elif scapy_pkt.haslayer(UDP): protocol = "UDP"

                if protocol:
                    # DNS通信(53)とmDNS(5353)はログに出さない
                    is_dns_traffic = (scapy_pkt.haslayer(UDP) and 
                                     (scapy_pkt[UDP].sport == 53 or scapy_pkt[UDP].dport == 53 or 
                                      scapy_pkt[UDP].sport == 5353 or scapy_pkt[UDP].dport == 5353))
                    
                    if not is_dns_traffic:
                        current_time = time.time()
                        # IPペア+プロトコル キャッシュ制御
                        cache_key = (src_ip, dst_ip, protocol) 
                        
                        if current_time - self.log_cache.get(cache_key, 0) > 2.0:
                            src_show = self.get_display_name(src_ip)
                            dst_show = self.get_display_name(dst_ip)
                            
                            print(f"{src_show} -> {dst_show} | {protocol}")
                            self.log_cache[cache_key] = current_time

        except Exception:
            pass