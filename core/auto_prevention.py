import os

def prevent_dos_ddos():
    # Example iptables rule to prevent DOS attacks
    os.system('iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --set')
    os.system('iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP')

    # Additional measures for DDOS prevention
    print("Temporary measures for DDOS implemented.")