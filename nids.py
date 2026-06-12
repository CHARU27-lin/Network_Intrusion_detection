from scapy.all import sniff, IP, TCP
from colorama import Fore, Style, init
from datetime import datetime
import csv
import sys

# =========================================
# UTF-8 SUPPORT
# =========================================

sys.stdout.reconfigure(encoding='utf-8')

# =========================================
# INITIALIZE COLORAMA
# =========================================

init(autoreset=True)

# =========================================
# DATA STORAGE
# =========================================

# COUNT REQUESTS FROM IPS

ip_count = {}

# STORE PORTS FOR PORT SCAN DETECTION

port_scan = {}

# TOTAL PACKETS

total_packets = 0

# TOTAL ALERTS

total_alerts = 0

# UNIQUE IPS

unique_ips = set()

# =========================================
# SETTINGS
# =========================================

# ALERT THRESHOLD

THRESHOLD = 10

# TXT LOG FILE

log_file = "intrusion_logs.txt"

# CSV LOG FILE

csv_file = "intrusion_logs.csv"

# =========================================
# CREATE CSV HEADER
# =========================================

with open(

    csv_file,

    "w",

    newline="",

    encoding="utf-8"

) as file:

    writer = csv.writer(file)

    writer.writerow(

        [

            "Time",
            "IP Address",
            "Event"

        ]

    )

# =========================================
# SAVE TXT LOG
# =========================================

def save_log(message):

    with open(

        log_file,

        "a",

        encoding="utf-8"

    ) as file:

        file.write(message + "\n")

# =========================================
# SAVE CSV LOG
# =========================================

def save_csv(time, ip, event):

    with open(

        csv_file,

        "a",

        newline="",

        encoding="utf-8"

    ) as file:

        writer = csv.writer(file)

        writer.writerow(

            [

                time,
                ip,
                event

            ]

        )

# =========================================
# MAIN DETECTION FUNCTION
# =========================================

def detect_intrusion(packet):

    global total_packets
    global total_alerts

    # ONLY IP PACKETS

    if packet.haslayer(IP):

        total_packets += 1

        # SOURCE IP

        src_ip = packet[IP].src

        # ADD UNIQUE IP

        unique_ips.add(src_ip)

        # CURRENT TIME

        timestamp = datetime.now().strftime(
            "%H:%M:%S"
        )

        # =================================
        # COUNT REQUESTS
        # =================================

        if src_ip not in ip_count:

            ip_count[src_ip] = 1

        else:

            ip_count[src_ip] += 1

        # =================================
        # NORMAL PACKET MESSAGE
        # =================================

        normal_msg = (

            f"[{timestamp}] "

            f"[INFO] "

            f"Packet from {src_ip}"

        )

        print(

            Fore.GREEN +

            normal_msg

        )

        save_log(normal_msg)

        save_csv(

            timestamp,

            src_ip,

            "Normal Packet"

        )

        # =================================
        # SUSPICIOUS TRAFFIC DETECTION
        # =================================

        if ip_count[src_ip] > THRESHOLD:

            total_alerts += 1

            alert_msg = (

                f"[{timestamp}] "

                f"[ALERT] "

                f"Suspicious activity detected "

                f"from {src_ip}"

            )

            print(

                Fore.RED +

                Style.BRIGHT +

                alert_msg

            )

            save_log(alert_msg)

            save_csv(

                timestamp,

                src_ip,

                "Suspicious Activity"

            )

        # =================================
        # PORT SCAN DETECTION
        # =================================

        if packet.haslayer(TCP):

            dst_port = packet[TCP].dport

            # CREATE PORT SET

            if src_ip not in port_scan:

                port_scan[src_ip] = set()

            # STORE PORT

            port_scan[src_ip].add(dst_port)

            # DETECT PORT SCAN

            if len(port_scan[src_ip]) > 10:

                total_alerts += 1

                port_alert = (

                    f"[{timestamp}] "

                    f"[CRITICAL] "

                    f"PORT SCAN DETECTED "

                    f"from {src_ip}"

                )

                print(

                    Fore.MAGENTA +

                    Style.BRIGHT +

                    port_alert

                )

                save_log(port_alert)

                save_csv(

                    timestamp,

                    src_ip,

                    "Port Scan Detected"

                )

        # =================================
        # LIVE STATISTICS
        # =================================

        stats = (

            f"\n"

            f"[STATS] TOTAL PACKETS : {total_packets}\n"

            f"[STATS] TOTAL ALERTS : {total_alerts}\n"

            f"[STATS] UNIQUE IPS   : {len(unique_ips)}\n"

        )

        print(

            Fore.CYAN +

            stats

        )

# =========================================
# START MESSAGE
# =========================================

start_msg = (

    "\n"

    "=====================================\n"

    "NETWORK INTRUSION DETECTION SYSTEM\n"

    "=====================================\n"

    "[INFO] Monitoring Started...\n"

)

print(

    Fore.CYAN +

    Style.BRIGHT +

    start_msg

)

save_log(start_msg)

# =========================================
# START PACKET SNIFFING
# =========================================

sniff(

    prn=detect_intrusion,

    store=False

)
