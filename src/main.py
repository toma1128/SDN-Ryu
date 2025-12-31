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
from scapy.layers.dhcp import DHCP
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class SimpleMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        
        # データ管理
        self.mac_to_name = {}     # スマホの端末名
        self.ip_to_domain = {}    # IP→ドメイン名
        self.log_cache = {}       # ログ重複防止用
        
        # ドメイン検索用の設定
        self.resolve_queue = queue.Queue()  # 検索するリスト
        self.pending_ips = set()            # 現在検索中のIPリスト
        
        # 裏で検索するスレッドを起動
        self.worker_thread = threading.Thread(target=self._resolver_loop, daemon=True)
        self.worker_thread.start()

        self.TARGET_IP = "192.168.0.9" # 監視対象IP(一旦)
        print(f"SYSTEM: Async Monitor Mode Started for {self.TARGET_IP}")

    # 検索処理
    def _resolver_loop(self):
        while True:
            try:
                # リストからIPを取り出す
                ip_addr = self.resolve_queue.get()
                
                try:
                    hostname, _, _ = socket.gethostbyaddr(ip_addr)
                    self.ip_to_domain[ip_addr] = hostname # 結果をメモ
                except socket.herror:
                    self.ip_to_domain[ip_addr] = ip_addr 
                except Exception:
                    pass
                
                # リストから消す
                if ip_addr in self.pending_ips:
                    self.pending_ips.remove(ip_addr)
                
                self.resolve_queue.task_done()
                
                # 連続アクセス防止
                time.sleep(0.1) 
                
            except Exception as e:
                print(f"Resolver Error: {e}")

    # 表示名の取得
    def get_display_name(self, mac, ip):
        # 端末名が分かれば優先
        if mac in self.mac_to_name:
            return f"[{self.mac_to_name[mac]}]"
        
        # すでに検索済みのドメインがあれば返す
        if ip in self.ip_to_domain:
             return f"({self.ip_to_domain[ip]})"
        
        # とりあえずIPを返す
        if ip not in self.pending_ips:
            # プライベートIPは検索不要
            if not ip.startswith("192.168."):
                self.pending_ips.add(ip)
                self.resolve_queue.put(ip)
        
        return f"({ip})"

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        try:
            scapy_pkt = Ether(msg.data)
            
            # DHCPから端末名学習
            if scapy_pkt.haslayer(DHCP):
                src_mac = scapy_pkt.src
                for opt in scapy_pkt[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == 'hostname':
                        name = opt[1].decode('utf-8', 'ignore')
                        self.mac_to_name[src_mac] = name
                        print(f"[LEARNED] DHCP: {src_mac} -> {name}")
                        break

            if scapy_pkt.haslayer(IP):
                src_ip = scapy_pkt[IP].src
                dst_ip = scapy_pkt[IP].dst
                src_mac = scapy_pkt.src
                dst_mac = scapy_pkt.dst

                # ノイズ除去
                if dst_ip.startswith("224.") or dst_ip.startswith("239.") or dst_ip == "255.255.255.255":
                    return
                if src_ip != self.TARGET_IP and dst_ip != self.TARGET_IP:
                    return

                # プロトコル判定
                protocol = ""
                if scapy_pkt.haslayer(TCP): protocol = "TCP"
                elif scapy_pkt.haslayer(UDP): protocol = "UDP"

                if protocol:
                    # DNS通信(53)自体は表示しない
                    is_dns = (scapy_pkt.haslayer(UDP) and (scapy_pkt[UDP].sport == 53 or scapy_pkt[UDP].dport == 53))
                    
                    if not is_dns:
                        # ログキャッシュ（重複表示の防止）
                        current_time = time.time()
                        cache_key = (src_mac, dst_ip, protocol) 
                        
                        if current_time - self.log_cache.get(cache_key, 0) > 2.0:
                            src_show = self.get_display_name(src_mac, src_ip)
                            dst_show = self.get_display_name(dst_mac, dst_ip)
                            
                            arrow = ">>>" if src_ip == self.TARGET_IP else "<<<"
                            print(f"{arrow} {src_show} -> {dst_show} | {protocol}")
                            self.log_cache[cache_key] = current_time

        except Exception:
            pass