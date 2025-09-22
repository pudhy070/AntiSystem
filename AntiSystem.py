import tkinter as tk
from tkinter import ttk, messagebox
import random
from datetime import datetime
import os

def generate_dummy_packet_data(counter):
    src_ip = f"192.168.0.{random.randint(2, 254)}"
    dst_ip = f"52.85.{random.randint(10, 200)}.{random.randint(10, 200)}"
    length = random.randint(64, 6000)
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
        "Length": length,
        "상세 정보": ""
    }

class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sia CIWS Anti System")
        self.root.geometry("950x750")
        self.capturing = False
        self.packet_counter = 0
        self.packet_details = {}
        self.quarantine_packets = {}
        self.ciws_enabled = False
        self.current_filter = "all"

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", rowheight=25, fieldbackground="#F0F0F0")
        style.configure("Treeview.Heading", font=('Malgun Gothic', 10, 'bold'))

        control_frame = tk.Frame(self.root)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        self.create_control_widgets(control_frame)

        main_pane = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_pane.pack(expand=True, fill='both')

        list_frame = ttk.Frame(main_pane, padding="5")
        main_pane.add(list_frame, weight=2)

        quarantine_frame = ttk.Frame(main_pane, padding="5")
        main_pane.add(quarantine_frame, weight=1)

        detail_frame = ttk.Frame(main_pane, padding="5")
        main_pane.add(detail_frame, weight=1)

        self.create_packet_list_widgets(list_frame)
        self.create_quarantine_list_widgets(quarantine_frame)
        self.create_detail_view_widgets(detail_frame)

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
        left_frame = tk.Frame(parent)
        left_frame.pack(side=tk.LEFT)

        ttk.Button(left_frame, text="캡처 시작", command=self.start_capture).pack(side=tk.LEFT, padx=2)
        ttk.Button(left_frame, text="캡처 중지", command=self.stop_capture).pack(side=tk.LEFT, padx=2)
        ttk.Button(left_frame, text="목록 지우기", command=self.clear_list).pack(side=tk.LEFT, padx=2)
        self.ciws_button = ttk.Button(left_frame, text="CIWS 활성화", command=self.toggle_ciws)
        self.ciws_button.pack(side=tk.LEFT, padx=(8, 2))
        ttk.Button(left_frame, text="위험도 필터", command=self.open_filter_dialog).pack(side=tk.LEFT, padx=2)

        right_frame = tk.Frame(parent)
        right_frame.pack(side=tk.RIGHT)
        ttk.Button(right_frame, text="캡처 다운로드", command=self.download_capture).pack(side=tk.RIGHT, padx=2)

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
        columns = ("No", "Time", "제목", "Source IP", "Country", "Destination IP", "Length")
        self.tree = ttk.Treeview(parent, columns=columns, show='headings')

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100, anchor='center')

        self.tree.column("제목", width=250)
        self.tree.column("Source IP", width=120)
        self.tree.column("Destination IP", width=120)
        self.tree.column("Time", width=80)
        self.tree.column("No", width=50, anchor='e')

        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(expand=True, fill='both')
        self.tree.bind('<<TreeviewSelect>>', self.on_item_select)

    def create_quarantine_list_widgets(self, parent):
        ttk.Label(parent, text="격리 패킷", font=('Malgun Gothic', 10, 'bold')).pack(anchor="w")
        columns = ("No", "Time", "제목", "Source IP", "Country", "Destination IP", "Length")
        self.quarantine_tree = ttk.Treeview(parent, columns=columns, show='headings')

        for col in columns:
            self.quarantine_tree.heading(col, text=col)
            self.quarantine_tree.column(col, width=100, anchor='center')

        self.quarantine_tree.column("제목", width=250)
        self.quarantine_tree.column("Source IP", width=120)
        self.quarantine_tree.column("Destination IP", width=120)
        self.quarantine_tree.column("Time", width=80)
        self.quarantine_tree.column("No", width=50, anchor='e')

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

    def capture_loop(self):
        if not self.capturing:
            return
        self.packet_counter += 1
        packet = generate_dummy_packet_data(self.packet_counter)

        if self.ciws_enabled and packet["Length"] >= 2000:
            self.quarantine_packets[str(packet["No"])] = packet
            self.add_packet_to_quarantine(packet)
        else:
            self.packet_details[str(packet["No"])] = packet
            self.add_packet_to_list(packet)

        self.root.after(random.randint(500, 2500), self.capture_loop)

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
            self.tree.insert('', tk.END, values=[v for k, v in packet.items() if k != "상세 정보"], iid=iid, tags=(risk_tag,))
            self.tree.see(iid)
        self.save_packet_log(packet)

    def add_packet_to_quarantine(self, packet):
        iid = str(packet["No"])
        risk_tag = self.get_risk_tag(packet["Length"])
        if self.should_display_packet(risk_tag):
            self.quarantine_tree.insert('', tk.END, values=[v for k, v in packet.items() if k != "상세 정보"], iid=iid, tags=(risk_tag,))
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
                self.tree.insert('', tk.END, values=[v for k, v in packet.items() if k != "상세 정보"], iid=str(packet["No"]), tags=(tag,))

    def refresh_quarantine_list(self):
        for i in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(i)
        for packet in self.quarantine_packets.values():
            tag = self.get_risk_tag(packet["Length"])
            if self.should_display_packet(tag):
                self.quarantine_tree.insert('', tk.END, values=[v for k, v in packet.items() if k != "상세 정보"], iid=str(packet["No"]), tags=(tag,))

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
            return
        selected_iid = selected_items[0]
        packet_data = self.quarantine_packets.get(selected_iid)
        if not packet_data:
            return
        self.show_packet_detail(packet_data)

    def show_packet_detail(self, packet_data):
        detail_content = packet_data["상세 정보"] if packet_data["상세 정보"] else f"""--- 감지된 이상 패킷 정보 ---
감지 이유: {packet_data['제목']}
시간: {datetime.now().strftime('%Y-%m-%d')} {packet_data['Time']}

출발지 IP: {packet_data['Source IP']}
출발지 국가: {packet_data['Country']}
목적지 IP: {packet_data['Destination IP']}
패킷 길이: {packet_data['Length']}

--- 패킷 레이어 상세 정보 (자동 생성) ---
###[ IP ]###
  version = 4, ihl = 5, len = {packet_data['Length']}
  src = {packet_data['Source IP']}
  dst = {packet_data['Destination IP']}
..."""
        self.detail_text.config(state="normal")
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.insert('1.0', detail_content)
        self.detail_text.config(state="disabled")

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
            for packet in self.packet_details.values():
                f.write(f"No: {packet['No']}\nTime: {packet['Time']}\n제목: {packet['제목']}\n"
                        f"Source IP: {packet['Source IP']}\nCountry: {packet['Country']}\n"
                        f"Destination IP: {packet['Destination IP']}\nLength: {packet['Length']}\n"
                        f"상세 정보:\n{packet['상세 정보'] if packet['상세 정보'] else '(자동 생성 상세 정보)'}\n")
                f.write("-" * 50 + "\n")
            for packet in self.quarantine_packets.values():
                f.write(f"No: {packet['No']} (격리)\nTime: {packet['Time']}\n제목: {packet['제목']}\n"
                        f"Source IP: {packet['Source IP']}\nCountry: {packet['Country']}\n"
                        f"Destination IP: {packet['Destination IP']}\nLength: {packet['Length']}\n"
                        f"상세 정보:\n{packet['상세 정보'] if packet['상세 정보'] else '(자동 생성 상세 정보)'}\n")
                f.write("-" * 50 + "\n")
        messagebox.showinfo("다운로드", f"패킷이 {save_path}로 저장되었습니다.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerApp(root)
    root.mainloop()
