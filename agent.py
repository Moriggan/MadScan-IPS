# agent.py
"""
Optional system-tray agent that can run separately.
It provides Start/Stop/Capture Now via a tray menu and writes pcap files under captures/.
Requires: pip install pystray pillow scapy
Run separately: python agent.py
"""
import time, threading, sys, os, binascii
from datetime import datetime
from pathlib import Path

try:
    from scapy.all import AsyncSniffer, wrpcap
except Exception:
    AsyncSniffer = None
    wrpcap = None

try:
    from PIL import Image, ImageDraw
    import pystray
except Exception:
    Image = None
    pystray = None

CAP_DIR = Path(__file__).resolve().parent / "captures"
CAP_DIR.mkdir(exist_ok=True)

class Agent:
    def __init__(self):
        self.sniffer = None
        self.running = False
        self.thread = None
        self.lock = threading.Lock()

    def start(self):
        if AsyncSniffer is None:
            print("Scapy not installed. Cannot start agent.")
            return
        with self.lock:
            if self.running:
                return
            self.running = True
            self.thread = threading.Thread(target=self._run_loop, daemon=True)
            self.thread.start()
            print("Agent started.")

    def stop(self):
        with self.lock:
            if not self.running:
                return
            self.running = False
            if self.sniffer:
                try:
                    self.sniffer.stop()
                except Exception:
                    pass
                self.sniffer = None
            print("Agent stopped.")

    def capture_now(self, duration=10):
        if AsyncSniffer is None:
            print("Scapy not installed.")
            return
        print(f"Capturing now for {duration}s ...")
        s = AsyncSniffer(store=True)
        s.start()
        time.sleep(duration)
        pkts = s.stop()
        fname = datetime.utcnow().strftime("%Y%m%d_%H%M%S") + "_agent.pcap"
        p = CAP_DIR / fname
        try:
            wrpcap(str(p), pkts)
            print("Wrote", p)
        except Exception as e:
            print("Write failed:", e)

    def _run_loop(self):
        # simple loop: capture short rolling pcaps to avoid memory growth
        while self.running:
            try:
                s = AsyncSniffer(store=True)
                self.sniffer = s
                s.start()
                time.sleep(30)
                pkts = s.stop()
                self.sniffer = None
                if pkts and len(pkts) > 0:
                    fname = datetime.utcnow().strftime("%Y%m%d_%H%M%S") + "_agent.pcap"
                    p = CAP_DIR / fname
                    try:
                        wrpcap(str(p), pkts)
                        print("Agent wrote", p)
                    except Exception as e:
                        print("Agent write failed", e)
            except Exception as e:
                print("Agent loop exception", e)
                time.sleep(5)

def make_image():
    # small 64x64 icon
    img = Image.new('RGBA', (64,64), (0,0,0,0))
    d = ImageDraw.Draw(img)
    d.ellipse((8,8,56,56), fill=(77,171,247), outline=(255,255,255))
    return img

def run_tray():
    agent = Agent()
    if pystray is None or Image is None:
        print("pystray or pillow not installed. Running in console-only mode.")
        agent.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            agent.stop()
            sys.exit(0)

    icon = pystray.Icon("pcatcher")
    icon.icon = make_image()
    icon.title = "PacketCatcher Agent"

    def on_start(icon, item):
        agent.start()
    def on_stop(icon, item):
        agent.stop()
    def on_capture(icon, item):
        agent.capture_now(10)
    def on_quit(icon, item):
        agent.stop()
        icon.stop()

    icon.menu = pystray.Menu(
        pystray.MenuItem("Start", on_start),
        pystray.MenuItem("Stop", on_stop),
        pystray.MenuItem("Capture Now (10s)", on_capture),
        pystray.MenuItem("Exit", on_quit),
    )
    icon.run()

if __name__ == "__main__":
    run_tray()
