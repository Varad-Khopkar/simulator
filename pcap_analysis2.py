# pcap_analysis2.py
# Futuristic PCAP Firewall Flow Visualizer for H-SAFE

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False

from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from schema import new_packet


# =========================
# VISUAL CONSTANTS
# =========================

BG = "#0b0f14"
PANEL = "#111827"
ACCENT = "#00e5ff"

ACTION_COLORS = {
    "ALLOW": "#00e676",
    "DENY": "#ff1744",
    "ALERT": "#00e5ff"
}

PROTOCOL_LANES = {
    22: 120,    # SSH
    80: 160,    # HTTP
    443: 200,   # HTTPS
    "default": 240
}


# =========================
# PCAP PARSER
# =========================

def parse_pcap_gui(file_path):
    packets = []
    scapy_packets = rdpcap(file_path)

    for pkt in scapy_packets:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        protocol = None
        src_port = None
        dst_port = None

        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        packets.append(
            new_packet(
                src_ip=ip.src,
                dst_ip=ip.dst,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                payload_size=len(bytes(pkt))
            )
        )

    return packets


# =========================
# GUI APPLICATION
# =========================

class FirewallFlowUI(TkinterDnD.Tk if DND_AVAILABLE else tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("H-SAFE | Firewall Packet Flow Simulator")
        self.geometry("1200x720")
        self.configure(bg=BG)

        self.packets = []
        self.current_index = 0
        self.playing = False
        self.speed = 15

        self._build_ui()

        if DND_AVAILABLE:
            self.drop_target_register(DND_FILES)
            self.dnd_bind("<<Drop>>", self._on_drop)

    # ---------------- UI ----------------

    def _build_ui(self):
        self._top_bar()
        self._canvas()
        self._controls()
        self._log_panel()
        self._status_bar()

    def _top_bar(self):
        bar = tk.Frame(self, bg=PANEL, height=40)
        bar.pack(fill="x")

        tk.Button(
            bar, text="IMPORT PCAP", bg=ACCENT, fg="black",
            relief="flat", command=self._open_file
        ).pack(side="left", padx=10, pady=5)

        self.file_label = tk.Label(bar, text="NO PCAP LOADED", bg=PANEL, fg=ACCENT)
        self.file_label.pack(side="left", padx=10)

    def _canvas(self):
        self.canvas = tk.Canvas(self, bg=BG, height=340, highlightthickness=0)
        self.canvas.pack(fill="x", padx=10, pady=10)
        self._draw_nodes()

    def _controls(self):
        controls = tk.Frame(self, bg=PANEL)
        controls.pack(fill="x", padx=10)

        tk.Label(controls, text="Speed", bg=PANEL, fg=ACCENT).pack(side="left")
        tk.Scale(
            controls, from_=5, to=50, orient="horizontal",
            bg=PANEL, fg=ACCENT, troughcolor=BG,
            command=lambda v: setattr(self, "speed", int(v))
        ).pack(side="left", padx=10)

        self.timeline = tk.Scale(
            controls, from_=0, to=0, orient="horizontal",
            bg=PANEL, fg=ACCENT, troughcolor=BG,
            command=self._scrub
        )
        self.timeline.pack(side="left", fill="x", expand=True, padx=20)

    def _log_panel(self):
        self.log = tk.Text(self, bg="#020617", fg=ACCENT, height=10, borderwidth=0)
        self.log.pack(fill="both", expand=True, padx=10)

    def _status_bar(self):
        self.status = tk.Label(self, text="STATUS: IDLE", bg=PANEL, fg=ACCENT, anchor="w")
        self.status.pack(fill="x")

    # ---------------- Nodes ----------------

    def _draw_nodes(self):
        self.canvas.delete("all")
        y = 200

        self.src_x = 120
        self.fw_x = 600
        self.dst_x = 1080

        def node(x, label, color):
            self.canvas.create_oval(x-45, y-45, x+45, y+45, outline=color, width=3)
            self.canvas.create_text(x, y+60, text=label, fill=color)

        node(self.src_x, "SOURCE", ACCENT)
        self.fw_node = node(self.fw_x, "H-SAFE FW", "#ff1744")
        node(self.dst_x, "DESTINATION", "#00e676")

        self.canvas.create_line(self.src_x+45, y, self.fw_x-45, y, fill="#1f2937", width=2)
        self.canvas.create_line(self.fw_x+45, y, self.dst_x-45, y, fill="#1f2937", width=2)

    # ---------------- File Handling ----------------

    def _open_file(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if path:
            self._load_pcap(path)

    def _on_drop(self, event):
        path = event.data.strip("{}")
        if path.endswith(".pcap"):
            self._load_pcap(path)
        else:
            messagebox.showerror("Invalid", "Only .pcap files allowed")

    def _load_pcap(self, path):
        self.file_label.config(text=os.path.basename(path))
        self.log.delete("1.0", tk.END)
        self.status.config(text="STATUS: PARSING PCAP")
        self._draw_nodes()

        threading.Thread(target=self._process_pcap, args=(path,), daemon=True).start()

    # ---------------- Simulation ----------------

    def _process_pcap(self, path):
        self.packets = parse_pcap_gui(path)
        self.timeline.config(to=len(self.packets)-1)
        self.current_index = 0
        self.playing = True

        self.status.config(text="STATUS: SIMULATING TRAFFIC")

        while self.playing and self.current_index < len(self.packets):
            self._simulate_packet(self.packets[self.current_index])
            self.timeline.set(self.current_index)
            self.current_index += 1

        self._final_report()

    def _simulate_packet(self, pkt):
        action = self._mock_firewall_decision(pkt)
        color = ACTION_COLORS[action]

        y = PROTOCOL_LANES.get(pkt["dst_port"], PROTOCOL_LANES["default"])
        dot = self.canvas.create_oval(self.src_x-5, y-5, self.src_x+5, y+5, fill=color)

        steps = 40
        dx = (self.dst_x - self.src_x) / steps

        for _ in range(steps):
            self.canvas.move(dot, dx, 0)
            self.canvas.update()
            self.after(self.speed)

        self.canvas.delete(dot)
        self._firewall_glow(color)

        self._log(
            f"{action} | {pkt['protocol']} "
            f"{pkt['src_ip']}:{pkt['src_port']} -> "
            f"{pkt['dst_ip']}:{pkt['dst_port']} "
            f"({pkt['payload_size']}B)\n"
        )

    # ---------------- Effects ----------------

    def _firewall_glow(self, color):
        glow = self.canvas.create_oval(
            self.fw_x-55, 145, self.fw_x+55, 255,
            outline=color, width=4
        )
        self.canvas.update()
        self.after(120)
        self.canvas.delete(glow)

    def _mock_firewall_decision(self, pkt):
        if pkt["dst_port"] in {22, 3389}:
            return "DENY"
        if pkt["dst_port"] in {80, 443}:
            return "ALLOW"
        return "ALERT"

    # ---------------- Timeline ----------------

    def _scrub(self, value):
        self.current_index = int(value)

    # ---------------- Logging ----------------

    def _log(self, text):
        self.log.insert(tk.END, text)
        self.log.see(tk.END)

    # ---------------- Final Report ----------------

    def _final_report(self):
        self._log("\n=== FINAL PCAP FIREWALL ANALYSIS ===\n")
        self._log(f"Total packets processed: {len(self.packets)}\n")
        self._log("Simulation completed successfully.\n")
        self.status.config(text="STATUS: COMPLETE")


# =========================
# ENTRY POINT
# =========================

if __name__ == "__main__":
    FirewallFlowUI().mainloop()
