import schedule
import time
from core.packet_scanner import scan_network
from core.packet_analyzer import analyze_packets

auto_scan_job = None

def auto_scan(interface, protocol, interval):
    def job():
        capture_file = scan_network(interface, protocol)
        malicious_packets = analyze_packets(capture_file)
        print(f"Auto-scan detected malicious packets: {malicious_packets}")

    schedule.every(interval).minutes.do(job)
    while True:
        schedule.run_pending()
        time.sleep(1)

def start_auto_scan(interface, protocol, interval):
    global auto_scan_job
    if auto_scan_job is None:
        auto_scan_job = schedule.every(interval).minutes.do(auto_scan, interface, protocol, interval)
        print(f"Auto-scan started with interval {interval} minutes.")
    else:
        print("Auto-scan is already running.")

def stop_auto_scan():
    global auto_scan_job
    if auto_scan_job is not None:
        schedule.clear()
        auto_scan_job = None
        print("Auto-scan stopped.")