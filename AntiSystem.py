import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import random
from datetime import datetime
import os
from collections import deque, defaultdict
import time
import threading

def generate_dummy_packet_data(counter):
    src_ip = f"192.168.0.{random.randint(2, 254)}"
    dst_ip = f"52.85.{random.randint(10, 200)}.{random.randint(10, 200)}"
    length = random.randint(64, 6000)
    port = random.choice([80, 443, 22, 21, 3389, 8080, random.randint(1024, 65535)])
    protocol = random.choice(["TCP", "UDP", "ICMP"])

    title = "정상 패킷"
    if length > 1500:
        title = f"비정상적으로 큰 패킷 감지 ({length} bytes)"

    return {
        "No": counter,
        "Time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "제목": title,
        "Source IP": src_ip,
        "Country": "South Korea",
        "Destination IP": dst_ip,
        "Port": port,
        "Protocol": protocol,
        "Length": length,
        "상세 정보": ""
    }

class PacketAnalyzerApp:
    # 상수 정의
    LARGE_PACKET_THRESHOLD = 2000
    DDOS_TIME_WINDOW = 2.0  # 초
    DDOS_PACKET_THRESHOLD = 15  # 2초 내 15개 이상 패킷
    FLOODING_IP_THRESHOLD = 10  # 같은 IP에서 10개 이상
    FLOODING_TIME_WINDOW = 3.0  # 초
    ABNORMAL_PORT_THRESHOLD = 0.3  # 비정상 포트 비율 30%
    CIWS_QUARANTINE_THRESHOLD = 4000

    def __init__(self, root):
        self.root = root
        self.root.title("Sia CIWS Anti System v1.1.0")
        self.root.geometry("1200x850")
        self.capturing = False
        self.packet_counter = 0
        self.packet_details = {}
        self.quarantine_packets = {}
        self.ciws_enabled = False
        self.current_filter = "all"

        # 지능형 CIWS 데이터 추적
        self.packet_timestamps = deque(maxlen=100)
        self.ip_packet_count = defaultdict(lambda: deque(maxlen=50))
        self.port_statistics = {"normal": 0, "abnormal": 0}
        self.attack_logs = []

        # 카운터 스트라이크 관련
        self.counter_strike_active = {}  # {packet_no: thread}

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", rowheight=25, fieldbackground="#F0F0F0")
        style.configure("Treeview.Heading", font=('Malgun Gothic', 10, 'bold'))

        self.control_frame = tk.Frame(self.root)
        self.control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        self.create_control_widgets(self.control_frame)

        # 메인 레이아웃
        self.main_container = tk.Frame(self.root)
        self.main_container.pack(expand=True, fill='both')

        # 왼쪽: 패킷 리스트
        self.left_pane = ttk.PanedWindow(self.main_container, orient=tk.VERTICAL)
        self.left_pane.pack(side=tk.LEFT, expand=True, fill='both')

        self.list_frame = ttk.Frame(self.left_pane, padding="5")
        self.left_pane.add(self.list_frame, weight=2)

        self.quarantine_frame = ttk.Frame(self.left_pane, padding="5")
        self.left_pane.add(self.quarantine_frame, weight=1)

        self.detail_frame = ttk.Frame(self.left_pane, padding="5")
        self.left_pane.add(self.detail_frame, weight=1)

        # 오른쪽: 공격 로그 및 통계
        self.right_frame = tk.Frame(self.main_container, width=300)
        self.right_frame.pack(side=tk.RIGHT, fill='both', padx=5)
        self.right_frame.pack_propagate(False)

        self.create_packet_list_widgets(self.list_frame)
        self.create_quarantine_list_widgets(self.quarantine_frame)
        self.create_detail_view_widgets(self.detail_frame)
        self.create_attack_log_widgets(self.right_frame)

        self.tree.tag_configure("low", background="#FFFACD")
        self.tree.tag_configure("medium", background="#FFE4B5")
        self.tree.tag_configure("high", background="#FFB6B6")
        self.tree.tag_configure("critical", background="#FF6961")

        self.quarantine_tree.tag_configure("low", background="#FFFACD")
        self.quarantine_tree.tag_configure("medium", background="#FFE4B5")
        self.quarantine_tree.tag_configure("high", background="#FFB6B6")
        self.quarantine_tree.tag_configure("critical", background="#FF6961")

        if os.path.exists("capture_log.txt"):
            os.remove("capture_log.txt")

    def create_control_widgets(self, parent):
        self.control_left_frame = tk.Frame(parent)
        self.control_left_frame.pack(side=tk.LEFT)

        ttk.Button(self.control_left_frame, text="캡처 시작", command=self.start_capture).pack(side=tk.LEFT, padx=2)
        ttk.Button(self.control_left_frame, text="캡처 중지", command=self.stop_capture).pack(side=tk.LEFT, padx=2)
        ttk.Button(self.control_left_frame, text="목록 지우기", command=self.clear_list).pack(side=tk.LEFT, padx=2)
        self.ciws_button = ttk.Button(self.control_left_frame, text="CIWS 활성화", command=self.toggle_ciws)
        self.ciws_button.pack(side=tk.LEFT, padx=(8, 2))
        ttk.Button(self.control_left_frame, text="위험도 필터", command=self.open_filter_dialog).pack(side=tk.LEFT, padx=2)

        self.control_right_frame = tk.Frame(parent)
        self.control_right_frame.pack(side=tk.RIGHT)

        ttk.Button(self.control_right_frame, text="캡처 다운로드", command=self.download_capture).pack(side=tk.RIGHT, padx=2)

    def toggle_ciws(self):
        self.ciws_enabled = not self.ciws_enabled
        if self.ciws_enabled:
            self.ciws_button.config(text="CIWS 비활성화")
            messagebox.showinfo("CIWS", "지금부터 위험 패킷을 격리 카테고리에 모읍니다.")
        else:
            self.ciws_button.config(text="CIWS 활성화")
            messagebox.showinfo("CIWS", "CIWS가 비활성화되었습니다.")

    def open_filter_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("위험도 필터")
        dialog.geometry("250x200")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="표시할 최소 위험도 선택:", font=('Malgun Gothic', 10, 'bold')).pack(pady=10)
        filter_var = tk.StringVar(value=self.current_filter)
        options = [("모두 보기", "all"), ("노란색 이상", "low"), ("주황색 이상", "medium"),
                   ("빨간색 이상", "high"), ("심각(붉은 빨강)", "critical")]
        for text, val in options:
            ttk.Radiobutton(dialog, text=text, variable=filter_var, value=val).pack(anchor="w", padx=20)

        def apply_filter():
            self.current_filter = filter_var.get()
            self.refresh_packet_list()
            self.refresh_quarantine_list()
            dialog.destroy()

        ttk.Button(dialog, text="적용", command=apply_filter).pack(pady=10)

    def create_packet_list_widgets(self, parent):
        ttk.Label(parent, text="일반 패킷", font=('Malgun Gothic', 10, 'bold')).pack(anchor="w")
        columns = ("No", "Time", "제목", "Source IP", "Destination IP", "Port", "Protocol", "Length")
        self.tree = ttk.Treeview(parent, columns=columns, show='headings')

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=80, anchor='center')

        self.tree.column("제목", width=200)
        self.tree.column("Source IP", width=110)
        self.tree.column("Destination IP", width=110)
        self.tree.column("Time", width=80)
        self.tree.column("No", width=50, anchor='e')
        self.tree.column("Port", width=60)
        self.tree.column("Protocol", width=70)

        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(expand=True, fill='both')
        self.tree.bind('<<TreeviewSelect>>', self.on_item_select)

    def create_quarantine_list_widgets(self, parent):
        header_frame = tk.Frame(parent)
        header_frame.pack(anchor="w", fill=tk.X)
        ttk.Label(header_frame, text="격리 패킷", font=('Malgun Gothic', 10, 'bold')).pack(side=tk.LEFT)

        # 카운터 스트라이크 버튼
        self.counter_strike_btn = ttk.Button(header_frame, text="⚡ Counter Strike",
                                              command=self.counter_strike_selected, state="disabled")
        self.counter_strike_btn.pack(side=tk.RIGHT, padx=5)

        columns = ("No", "Time", "제목", "Source IP", "Destination IP", "Port", "Protocol", "Length", "Status")
        self.quarantine_tree = ttk.Treeview(parent, columns=columns, show='headings')

        for col in columns:
            self.quarantine_tree.heading(col, text=col)
            self.quarantine_tree.column(col, width=80, anchor='center')

        self.quarantine_tree.column("제목", width=180)
        self.quarantine_tree.column("Source IP", width=110)
        self.quarantine_tree.column("Destination IP", width=110)
        self.quarantine_tree.column("Time", width=80)
        self.quarantine_tree.column("No", width=50, anchor='e')
        self.quarantine_tree.column("Port", width=60)
        self.quarantine_tree.column("Protocol", width=70)
        self.quarantine_tree.column("Status", width=100)

        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.quarantine_tree.yview)
        self.quarantine_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.quarantine_tree.pack(expand=True, fill='both')
        self.quarantine_tree.bind('<<TreeviewSelect>>', self.on_quarantine_select)

    def create_detail_view_widgets(self, parent):
        ttk.Label(parent, text="선택된 패킷의 상세 정보:", font=('Malgun Gothic', 10, 'bold')).pack(anchor='w')
        text_frame = tk.Frame(parent)
        text_frame.pack(expand=True, fill='both')
        self.detail_text = tk.Text(text_frame, wrap="word", state="disabled", font=("Consolas", 10), relief="sunken", borderwidth=1)
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.detail_text.pack(expand=True, fill='both')

    def create_attack_log_widgets(self, parent):
        self.log_parent = parent
        ttk.Label(parent, text="🛡️ 위협 탐지 로그", font=('Malgun Gothic', 11, 'bold')).pack(anchor='w', pady=(5, 5))

        # 통계 프레임
        self.stats_frame = tk.LabelFrame(parent, text="통계", font=('Malgun Gothic', 9, 'bold'))
        self.stats_frame.pack(fill=tk.X, padx=5, pady=5)

        self.stats_label = tk.Label(self.stats_frame, text="대기 중...", justify=tk.LEFT, font=('Consolas', 9))
        self.stats_label.pack(anchor='w', padx=5, pady=5)

        # 공격 로그
        self.attack_log_frame = tk.LabelFrame(parent, text="실시간 공격 탐지", font=('Malgun Gothic', 9, 'bold'))
        self.attack_log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.attack_log_text = tk.Text(self.attack_log_frame, wrap="word", font=("Consolas", 8),
                                        height=20, relief="sunken", borderwidth=1, bg="#ffffff", fg="#000000")
        log_scrollbar = ttk.Scrollbar(self.attack_log_frame, orient=tk.VERTICAL, command=self.attack_log_text.yview)
        self.attack_log_text.configure(yscrollcommand=log_scrollbar.set)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.attack_log_text.pack(expand=True, fill='both')

        # 카운터 스트라이크 로그
        self.cs_log_frame = tk.LabelFrame(parent, text="⚡ Counter Strike 로그", font=('Malgun Gothic', 9, 'bold'))
        self.cs_log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.counter_strike_log_text = tk.Text(self.cs_log_frame, wrap="word", font=("Consolas", 8),
                                                height=10, relief="sunken", borderwidth=1, bg="#ffffff", fg="#000000")
        cs_scrollbar = ttk.Scrollbar(self.cs_log_frame, orient=tk.VERTICAL, command=self.counter_strike_log_text.yview)
        self.counter_strike_log_text.configure(yscrollcommand=cs_scrollbar.set)
        cs_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.counter_strike_log_text.pack(expand=True, fill='both')

    def capture_loop(self):
        if not self.capturing:
            return
        self.packet_counter += 1
        packet = generate_dummy_packet_data(self.packet_counter)

        current_time = time.time()
        should_quarantine = False
        quarantine_reason = ""

        # 지능형 CIWS 분석
        if self.ciws_enabled:
            # 1. 대용량 패킷 차단
            if packet["Length"] >= self.LARGE_PACKET_THRESHOLD:
                should_quarantine = True
                quarantine_reason = f"대용량 패킷 ({packet['Length']} bytes)"
                packet["제목"] = f"[차단됨] {packet['제목']}"

            # 2. DDoS 공격 의심 탐지
            self.packet_timestamps.append(current_time)
            recent_packets = [t for t in self.packet_timestamps if current_time - t <= self.DDOS_TIME_WINDOW]
            if len(recent_packets) >= self.DDOS_PACKET_THRESHOLD:
                self.log_attack(f"⚠️ DDoS 공격 의심: {self.DDOS_TIME_WINDOW}초 내 {len(recent_packets)}개 패킷 감지")
                if not should_quarantine and packet["Length"] >= 1500:
                    should_quarantine = True
                    quarantine_reason = f"DDoS 패턴 감지 (고빈도 공격)"
                    packet["제목"] = f"[차단됨] DDoS 패턴 감지"

            # 3. 플러딩 공격 탐지 (특정 IP)
            src_ip = packet["Source IP"]
            self.ip_packet_count[src_ip].append(current_time)
            recent_from_ip = [t for t in self.ip_packet_count[src_ip]
                            if current_time - t <= self.FLOODING_TIME_WINDOW]

            if len(recent_from_ip) >= self.FLOODING_IP_THRESHOLD:
                self.log_attack(f"🚨 플러딩 공격 탐지: IP {src_ip}에서 {self.FLOODING_TIME_WINDOW}초 내 {len(recent_from_ip)}개 패킷")
                should_quarantine = True
                quarantine_reason = f"플러딩 공격 ({src_ip})"
                packet["제목"] = f"[차단됨] 플러딩 공격 from {src_ip}"

            # 4. 비정상 포트 스캔 탐지
            normal_ports = [80, 443, 22, 8080]
            if packet["Port"] in normal_ports:
                self.port_statistics["normal"] += 1
            else:
                self.port_statistics["abnormal"] += 1

            total_port_checks = self.port_statistics["normal"] + self.port_statistics["abnormal"]
            if total_port_checks >= 50:
                abnormal_ratio = self.port_statistics["abnormal"] / total_port_checks
                if abnormal_ratio >= self.ABNORMAL_PORT_THRESHOLD:
                    self.log_attack(f"⚠️ 비정상 포트 스캔 경고: 비정상 포트 접근 비율 {abnormal_ratio*100:.1f}%")
                    if packet["Port"] not in normal_ports and not should_quarantine:
                        should_quarantine = True
                        quarantine_reason = f"비정상 포트 스캔 (Port {packet['Port']})"
                        packet["제목"] = f"[차단됨] 포트 스캔 감지"

        # 패킷 처리
        if should_quarantine:
            packet["Status"] = quarantine_reason
            self.quarantine_packets[str(packet["No"])] = packet
            self.add_packet_to_quarantine(packet)
        else:
            packet["Status"] = "정상"
            self.packet_details[str(packet["No"])] = packet
            self.add_packet_to_list(packet)

        # 통계 업데이트
        self.update_statistics()

        self.root.after(random.randint(500, 2500), self.capture_loop)

    def log_attack(self, message):
        """공격 로그 추가"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        self.attack_logs.append(log_message)
        self.attack_log_text.insert(tk.END, log_message)
        self.attack_log_text.see(tk.END)

    def update_statistics(self):
        """통계 업데이트"""
        total_packets = len(self.packet_details) + len(self.quarantine_packets)
        quarantined = len(self.quarantine_packets)
        normal = len(self.packet_details)

        abnormal_ratio = 0
        total_port = self.port_statistics["normal"] + self.port_statistics["abnormal"]
        if total_port > 0:
            abnormal_ratio = (self.port_statistics["abnormal"] / total_port) * 100

        stats_text = f"""총 패킷: {total_packets}
정상: {normal}
격리: {quarantined}
비정상 포트 비율: {abnormal_ratio:.1f}%
활성 IP 추적: {len(self.ip_packet_count)}"""

        self.stats_label.config(text=stats_text)

    def get_risk_tag(self, length):
        if length >= 5000:
            return "critical"
        elif length >= 4000:
            return "high"
        elif length >= 3000:
            return "medium"
        elif length >= 2000:
            return "low"
        return ""

    def add_packet_to_list(self, packet):
        iid = str(packet["No"])
        risk_tag = self.get_risk_tag(packet["Length"])
        if self.should_display_packet(risk_tag):
            values = [packet["No"], packet["Time"], packet["제목"], packet["Source IP"],
                     packet["Destination IP"], packet["Port"], packet["Protocol"], packet["Length"]]
            self.tree.insert('', tk.END, values=values, iid=iid, tags=(risk_tag,))
            self.tree.see(iid)
        self.save_packet_log(packet)

    def add_packet_to_quarantine(self, packet):
        iid = str(packet["No"])
        risk_tag = self.get_risk_tag(packet["Length"])
        if self.should_display_packet(risk_tag):
            values = [packet["No"], packet["Time"], packet["제목"], packet["Source IP"],
                     packet["Destination IP"], packet["Port"], packet["Protocol"],
                     packet["Length"], packet.get("Status", "격리됨")]
            self.quarantine_tree.insert('', tk.END, values=values, iid=iid, tags=(risk_tag,))
            self.quarantine_tree.see(iid)
        self.save_packet_log(packet, quarantine=True)

    def should_display_packet(self, tag):
        levels = {"all": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        current_level = levels.get(self.current_filter, 0)
        packet_level = levels.get(tag, 0)
        return packet_level >= current_level

    def refresh_packet_list(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for packet in self.packet_details.values():
            tag = self.get_risk_tag(packet["Length"])
            if self.should_display_packet(tag):
                values = [packet["No"], packet["Time"], packet["제목"], packet["Source IP"],
                         packet["Destination IP"], packet["Port"], packet["Protocol"], packet["Length"]]
                self.tree.insert('', tk.END, values=values, iid=str(packet["No"]), tags=(tag,))

    def refresh_quarantine_list(self):
        for i in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(i)
        for packet in self.quarantine_packets.values():
            tag = self.get_risk_tag(packet["Length"])
            if self.should_display_packet(tag):
                values = [packet["No"], packet["Time"], packet["제목"], packet["Source IP"],
                         packet["Destination IP"], packet["Port"], packet["Protocol"],
                         packet["Length"], packet.get("Status", "격리됨")]
                self.quarantine_tree.insert('', tk.END, values=values, iid=str(packet["No"]), tags=(tag,))

    def clear_list(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for i in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(i)
        self.detail_text.config(state="normal")
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.config(state="disabled")
        self.packet_counter = 0
        self.packet_details.clear()
        self.quarantine_packets.clear()

        # 지능형 CIWS 데이터 초기화
        self.packet_timestamps.clear()
        self.ip_packet_count.clear()
        self.port_statistics = {"normal": 0, "abnormal": 0}
        self.attack_logs.clear()
        self.attack_log_text.delete('1.0', tk.END)
        self.counter_strike_log_text.delete('1.0', tk.END)
        self.counter_strike_active.clear()
        self.update_statistics()

        if os.path.exists("capture_log.txt"):
            os.remove("capture_log.txt")

    def on_item_select(self, event):
        selected_items = self.tree.selection()
        if not selected_items:
            return
        selected_iid = selected_items[0]
        packet_data = self.packet_details.get(selected_iid)
        if not packet_data:
            return
        self.show_packet_detail(packet_data)

    def on_quarantine_select(self, event):
        selected_items = self.quarantine_tree.selection()
        if not selected_items:
            self.counter_strike_btn.config(state="disabled")
            return
        selected_iid = selected_items[0]
        packet_data = self.quarantine_packets.get(selected_iid)
        if not packet_data:
            self.counter_strike_btn.config(state="disabled")
            return
        self.show_packet_detail(packet_data)

        # high 또는 critical 위험도인 경우 카운터 스트라이크 버튼 활성화
        risk_tag = self.get_risk_tag(packet_data["Length"])
        if risk_tag in ["high", "critical"]:
            self.counter_strike_btn.config(state="normal")
        else:
            self.counter_strike_btn.config(state="disabled")

    def show_packet_detail(self, packet_data):
        detail_content = packet_data["상세 정보"] if packet_data["상세 정보"] else f"""--- 감지된 이상 패킷 정보 ---
감지 이유: {packet_data['제목']}
시간: {datetime.now().strftime('%Y-%m-%d')} {packet_data['Time']}

출발지 IP: {packet_data['Source IP']}
출발지 국가: {packet_data.get('Country', 'Unknown')}
목적지 IP: {packet_data['Destination IP']}
포트: {packet_data['Port']}
프로토콜: {packet_data['Protocol']}
패킷 길이: {packet_data['Length']}
상태: {packet_data.get('Status', '정상')}

--- 패킷 레이어 상세 정보 (자동 생성) ---
###[ IP ]###
  version = 4, ihl = 5, len = {packet_data['Length']}
  src = {packet_data['Source IP']}
  dst = {packet_data['Destination IP']}
###[ {packet_data['Protocol']} ]###
  sport = {packet_data['Port']}
..."""
        self.detail_text.config(state="normal")
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.insert('1.0', detail_content)
        self.detail_text.config(state="disabled")

    def counter_strike_selected(self):
        """선택된 격리 패킷에 대해 카운터 스트라이크 실행"""
        selected_items = self.quarantine_tree.selection()
        if not selected_items:
            return

        selected_iid = selected_items[0]
        packet_data = self.quarantine_packets.get(selected_iid)
        if not packet_data:
            return

        # 사용자 확인
        target_ip = packet_data['Source IP']
        confirm = messagebox.askyesno(
            "Counter Strike 확인",
            f"⚠️ 경고: 능동적 방어 작전 승인 요청\n\n"
            f"대상 IP: {target_ip}\n"
            f"위협 수준: {self.get_risk_tag(packet_data['Length']).upper()}\n"
            f"패킷 크기: {packet_data['Length']} bytes\n\n"
            f"이 공격 소스로 역공격 시뮬레이션을 시작하시겠습니까?\n\n"
            f"주의: 이것은 교육 목적의 시뮬레이션입니다."
        )

        if confirm:
            # 카운터 스트라이크 시작
            thread = threading.Thread(target=self.execute_counter_strike,
                                     args=(packet_data,), daemon=True)
            thread.start()
            self.counter_strike_active[selected_iid] = thread

    def execute_counter_strike(self, packet_data):
        """카운터 스트라이크 시뮬레이션 실행"""
        target_ip = packet_data['Source IP']
        packet_no = packet_data['No']

        # 시작 로그
        self.log_counter_strike(f"🎯 [시작] Counter Strike 작전 개시")
        self.log_counter_strike(f"   대상: {target_ip}")
        self.log_counter_strike(f"   패킷 #{packet_no} 역추적 시작\n")

        # 시뮬레이션 단계
        stages = [
            ("역추적 중...", 1.5),
            (f"대상 {target_ip} 위치 확인 완료", 1.0),
            ("대응 패킷 생성 중...", 1.5),
            ("방어 패킷 전송 시뮬레이션 (Wave 1/3)", 2.0),
            ("방어 패킷 전송 시뮬레이션 (Wave 2/3)", 2.0),
            ("방어 패킷 전송 시뮬레이션 (Wave 3/3)", 2.0),
            (f"✅ Counter Strike 완료 - {target_ip} 무력화 시뮬레이션 성공", 0.5),
        ]

        for message, delay in stages:
            time.sleep(delay)
            self.log_counter_strike(f"   {message}")

        self.log_counter_strike(f"\n📊 작전 결과:")
        self.log_counter_strike(f"   - 전송된 대응 패킷: {random.randint(50, 150)}개")
        self.log_counter_strike(f"   - 소요 시간: {sum(s[1] for s in stages):.1f}초")
        self.log_counter_strike(f"   - 상태: 시뮬레이션 성공\n")
        self.log_counter_strike("="*50 + "\n")

    def log_counter_strike(self, message):
        """카운터 스트라이크 로그 추가"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        self.counter_strike_log_text.insert(tk.END, log_message)
        self.counter_strike_log_text.see(tk.END)

    def start_capture(self):
        if self.capturing:
            return
        self.capturing = True
        self.capture_loop()

    def stop_capture(self):
        self.capturing = False

    def save_packet_log(self, packet, quarantine=False):
        with open("capture_log.txt", "a", encoding="utf-8") as f:
            f.write(f"[{'Q' if quarantine else 'N'}-{packet['No']}] {packet['Time']} | {packet['제목']} | "
                    f"{packet['Source IP']} -> {packet['Destination IP']} | {packet['Length']} bytes | "
                    f"{packet['상세 정보'] if packet['상세 정보'] else '자동 생성 상세 정보'}\n")

    def download_capture(self):
        if not self.packet_details and not self.quarantine_packets:
            messagebox.showinfo("다운로드", "저장할 패킷이 없습니다.")
            return
        save_path = "captured_packets.txt"
        with open(save_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("Sia CIWS Anti System - 패킷 캡처 리포트\n")
            f.write(f"생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")

            # 통계 정보
            f.write("📊 통계 정보\n")
            f.write(f"총 패킷: {len(self.packet_details) + len(self.quarantine_packets)}\n")
            f.write(f"정상 패킷: {len(self.packet_details)}\n")
            f.write(f"격리 패킷: {len(self.quarantine_packets)}\n")
            f.write(f"추적된 고유 IP: {len(self.ip_packet_count)}\n")
            f.write("\n" + "=" * 80 + "\n\n")

            # 공격 로그
            if self.attack_logs:
                f.write("🚨 공격 탐지 로그\n")
                f.write("-" * 80 + "\n")
                for log in self.attack_logs:
                    f.write(log)
                f.write("\n" + "=" * 80 + "\n\n")

            # 정상 패킷
            f.write("✅ 정상 패킷 목록\n")
            f.write("-" * 80 + "\n")
            for packet in self.packet_details.values():
                f.write(f"No: {packet['No']}\n")
                f.write(f"Time: {packet['Time']}\n")
                f.write(f"제목: {packet['제목']}\n")
                f.write(f"Source IP: {packet['Source IP']}\n")
                f.write(f"Destination IP: {packet['Destination IP']}\n")
                f.write(f"Port: {packet['Port']}\n")
                f.write(f"Protocol: {packet['Protocol']}\n")
                f.write(f"Length: {packet['Length']} bytes\n")
                f.write(f"Status: {packet.get('Status', '정상')}\n")
                f.write("-" * 80 + "\n")

            # 격리 패킷
            if self.quarantine_packets:
                f.write("\n⚠️ 격리된 위협 패킷\n")
                f.write("-" * 80 + "\n")
                for packet in self.quarantine_packets.values():
                    f.write(f"No: {packet['No']} (격리됨)\n")
                    f.write(f"Time: {packet['Time']}\n")
                    f.write(f"제목: {packet['제목']}\n")
                    f.write(f"Source IP: {packet['Source IP']}\n")
                    f.write(f"Destination IP: {packet['Destination IP']}\n")
                    f.write(f"Port: {packet['Port']}\n")
                    f.write(f"Protocol: {packet['Protocol']}\n")
                    f.write(f"Length: {packet['Length']} bytes\n")
                    f.write(f"격리 사유: {packet.get('Status', '알 수 없음')}\n")
                    f.write(f"위험도: {self.get_risk_tag(packet['Length']).upper()}\n")
                    f.write("-" * 80 + "\n")

        messagebox.showinfo("다운로드", f"패킷 리포트가 {save_path}로 저장되었습니다.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerApp(root)
    root.mainloop()
