import tkinter as tk
from tkinter import ttk, font, messagebox
import random
from datetime import datetime

# --- 가상 패킷 데이터 생성기 ---
def generate_dummy_packet_data(counter):
    """시뮬레이션을 위한 가상의 패킷 데이터를 생성합니다."""
    src_ip = f"192.168.0.{random.randint(2, 254)}"
    dst_ip = f"52.85.{random.randint(10, 200)}.{random.randint(10, 200)}"
    length = random.randint(64, 4000)
    
    title = "정상 패킷"
    if length > 1500:
        title = f"비정상적으로 큰 패킷 감지 ({length} bytes)"

    packet_info = {
        "No": counter,
        "Time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "제목": title,
        "Source IP": src_ip,
        "Country": "South Korea",
        "Destination IP": dst_ip,
        "Length": length,
        "상세 정보": ""
    }
    return packet_info

class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sia CIWS Anti System")
        self.root.geometry("850x650")
        
        self.capturing = False
        self.packet_counter = 0
        self.packet_details = {}

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
        main_pane.add(list_frame, weight=1)

        detail_frame = ttk.Frame(main_pane, padding="5")
        main_pane.add(detail_frame, weight=1)

        self.create_packet_list_widgets(list_frame)
        self.create_detail_view_widgets(detail_frame)

    def create_control_widgets(self, parent):
        left_frame = tk.Frame(parent)
        left_frame.pack(side=tk.LEFT)
        
        ttk.Button(left_frame, text="캡처 시작", command=self.start_capture).pack(side=tk.LEFT, padx=2)
        ttk.Button(left_frame, text="캡처 중지", command=self.stop_capture).pack(side=tk.LEFT, padx=2)
        ttk.Button(left_frame, text="목록 지우기", command=self.clear_list).pack(side=tk.LEFT, padx=2)
        # ttk.Button(left_frame, text="데이터 추가", command=self.open_add_data_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(left_frame, text="CIWS 활성화").pack(side=tk.LEFT, padx=(8, 2))

        right_frame = tk.Frame(parent)
        right_frame.pack(side=tk.RIGHT)
        # ... (이하 필터 부분은 동일)

    def open_add_data_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("데이터 수동 추가")
        dialog.geometry("450x450") # 팝업창 세로 크기 약간 증가
        dialog.resizable(False, False)

        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding="15")
        frame.pack(expand=True, fill="both")

        # --- [수정] 입력 필드 재구성 및 시간 필드 추가 ---
        # --- [새로운 기능] 시간 입력 필드 ---
        ttk.Label(frame, text="Time:").grid(row=0, column=0, sticky="w", pady=3)
        time_entry = ttk.Entry(frame, width=40)
        time_entry.grid(row=0, column=1, pady=3)
        # 현재 시간으로 미리 채워넣기
        time_entry.insert(0, datetime.now().strftime("%H:%M:%S.%f")[:-3])

        ttk.Label(frame, text="Source IP:").grid(row=1, column=0, sticky="w", pady=3)
        src_ip_entry = ttk.Entry(frame, width=40)
        src_ip_entry.grid(row=1, column=1, pady=3)

        ttk.Label(frame, text="Destination IP:").grid(row=2, column=0, sticky="w", pady=3)
        dst_ip_entry = ttk.Entry(frame, width=40)
        dst_ip_entry.grid(row=2, column=1, pady=3)

        ttk.Label(frame, text="Length (bytes):").grid(row=3, column=0, sticky="w", pady=3)
        length_entry = ttk.Entry(frame, width=40)
        length_entry.grid(row=3, column=1, pady=3)
        
        ttk.Label(frame, text="제목:").grid(row=4, column=0, sticky="w", pady=3)
        title_entry = ttk.Entry(frame, width=40)
        title_entry.grid(row=4, column=1, pady=3)

        ttk.Label(frame, text="상세 정보:").grid(row=5, column=0, sticky="nw", pady=3)
        detail_text = tk.Text(frame, width=40, height=8, font=("Malgun Gothic", 9))
        detail_text.grid(row=5, column=1, pady=3)

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=15)
        
        # --- [수정] 람다 함수에 time_entry 추가 ---
        ttk.Button(button_frame, text="추가", command=lambda: self.submit_manual_data(
            dialog, time_entry, src_ip_entry, dst_ip_entry, length_entry, title_entry, detail_text
        )).pack(side="left", padx=5)
        ttk.Button(button_frame, text="취소", command=dialog.destroy).pack(side="left", padx=5)

    def submit_manual_data(self, dialog, time_entry, src_ip_entry, dst_ip_entry, length_entry, title_entry, detail_text):
        # --- [수정] 시간 값 가져오기 ---
        time_str = time_entry.get()
        src_ip = src_ip_entry.get()
        dst_ip = dst_ip_entry.get()
        length_str = length_entry.get()
        title = title_entry.get()
        detail_info = detail_text.get("1.0", tk.END).strip()

        # --- [수정] 필수 항목에 시간 추가 ---
        if not (time_str and src_ip and dst_ip and length_str and title):
            messagebox.showerror("입력 오류", "Time, IP, Length, 제목은 필수 항목입니다.", parent=dialog)
            return
        
        try:
            length = int(length_str)
        except ValueError:
            messagebox.showerror("입력 오류", "Length는 숫자여야 합니다.", parent=dialog)
            return

        self.packet_counter += 1
        packet = {
            "No": self.packet_counter,
            "Time": time_str, # --- [수정] 자동 생성 대신 입력된 값 사용 ---
            "제목": title,
            "Source IP": src_ip,
            "Country": "Manual Input",
            "Destination IP": dst_ip,
            "Length": length,
            "상세 정보": detail_info
        }

        self.add_packet_to_list(packet)
        dialog.destroy()

    def create_packet_list_widgets(self, parent):
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
        if not self.capturing: return
        self.packet_counter += 1
        packet = generate_dummy_packet_data(self.packet_counter)
        self.add_packet_to_list(packet)
        self.root.after(random.randint(500, 2500), self.capture_loop)
        
    def add_packet_to_list(self, packet):
        iid = str(packet["No"])
        self.packet_details[iid] = packet
        
        display_values = [v for k, v in packet.items() if k != "상세 정보"]
        
        self.tree.insert('', tk.END, values=display_values, iid=iid)
        self.tree.see(iid)

    def clear_list(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        self.detail_text.config(state="normal"); self.detail_text.delete('1.0', tk.END); self.detail_text.config(state="disabled")
        self.packet_counter = 0
        self.packet_details.clear()

    def on_item_select(self, event):
        selected_items = self.tree.selection()
        if not selected_items: return
            
        selected_iid = selected_items[0]
        packet_data = self.packet_details.get(selected_iid)
        if not packet_data: return

        detail_content = ""
        if packet_data.get("상세 정보"):
            detail_content = packet_data["상세 정보"]
        else:
            detail_content = f"""--- 감지된 이상 패킷 정보 ---
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
...
"""
        self.detail_text.config(state="normal")
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.insert('1.0', detail_content)
        self.detail_text.config(state="disabled")

    def start_capture(self):
        if self.capturing: return
        self.capturing = True
        self.capture_loop()

    def stop_capture(self):
        self.capturing = False


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerApp(root)
    root.mainloop()