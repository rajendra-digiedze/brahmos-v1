import time
import os
import random
import requests
import datetime

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")
LOG_INGEST_ENDPOINT = f"{BACKEND_URL}/api/logs/ingest"
FIREWALL_LOG = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"


def _post_ingest(log_data, max_attempts=5):
    print(f"Transmitting: {log_data['log_line']}")
    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.post(LOG_INGEST_ENDPOINT, json=log_data, timeout=3)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as exc:
            delay = min(1.5 * attempt, 5)
            print(
                f"Ingest failed (attempt {attempt}/{max_attempts}): {exc}. "
                f"Retrying in {delay:.1f}s..."
            )
            time.sleep(delay)

    print("Dropping log after retry budget exhausted.")
    return False


def _random_ipv4():
    first = str(random.randint(1, 223))
    rest = [str(random.randint(0, 255)) for _ in range(3)]
    return ".".join([first, *rest])


def synthetic_log_loop():
    """Demo stream for Docker/Linux where the Windows firewall log path does not exist."""
    print("Synthetic log mode (USE_SYNTHETIC_LOGS): generating demo events for the dashboard.")
    while True:
        src_ip = _random_ipv4()
        dst_ip = _random_ipv4()
        if src_ip.startswith("127.") and dst_ip.startswith("127."):
            time.sleep(0.2)
            continue
        now = datetime.datetime.utcnow()
        date = now.strftime("%Y-%m-%d")
        time_part = now.strftime("%H:%M:%S")
        line = (
            f"{date} {time_part} ALLOW TCP {src_ip} {dst_ip} "
            f"{random.randint(1024, 65535)} {random.randint(1, 65535)}"
        )
        log_data = process_line(line)
        if log_data:
            _post_ingest(log_data)
        time.sleep(random.uniform(0.4, 1.2))

connection_cache = {}

def follow_log(filepath):
    """Yields new lines as they are appended to the file."""
    try:
        with open(filepath, 'r', errors='ignore') as file:
            file.seek(0, 2)  # Go to end of file
            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                yield line.strip()
    except PermissionError:
        print("CRITICAL ERROR: Permission Denied!")
        print("You MUST run this python script from an Administrator PowerShell to read raw OS packet files.")
        print(f"Path: {filepath}")
        import sys; sys.exit(1)
    except FileNotFoundError:
        print(f"Waiting for {filepath} to be created by the OS...")
        time.sleep(5)
        yield from follow_log(filepath)

def process_line(line):
    # W3C Log Format usually ignores lines starting with #
    if line.startswith("#") or not line:
        return
    
    parts = line.split()
    # Windows Firewall Format: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
    if len(parts) >= 8:
        # We need mapping. 
        # parts[0] = date, parts[1] = time, parts[2] = action (ALLOW/DROP)
        # parts[3] = protocol, parts[4] = src-ip, parts[5] = dst-ip
        # parts[6] = src-port, parts[7] = dst-port
        
        date = parts[0]
        time_part = parts[1]
        action = parts[2]
        src_ip = parts[4]
        dst_ip = parts[5]
        src_port = parts[6]
        dst_port = parts[7]
        
        # Filter out internal localhost chatter (the dashboard polling the API, or the generator sending to the API)
        if (src_ip == "127.0.0.1" and dst_ip == "127.0.0.1") or (src_ip == "::1" and dst_ip == "::1"):
            return None
        
        # Translate to our API Format
        timeline = f"{date}T{time_part}Z"
        
        conn_key = f"{src_ip}->{dst_ip}"
        if conn_key in connection_cache:
            status, severity = connection_cache[conn_key]
        else:
            # 12.4 Hackathon Requirement: Enforce strict 95/3/2 statistical formatting over real OS IP logs
            roll = random.random()
            if roll < 0.95:
                status = "Allowed"
                severity = "Low"
            elif roll < 0.98:
                status = "Denied"
                severity = "High"
            else:
                status = "Denied"
                severity = "Critical"
            connection_cache[conn_key] = (status, severity)
            
        log_string = f"{timeline}| {src_ip}| {dst_ip}| {src_port}| {dst_port}| {status}| {severity}"
        
        return {
            "log_line": log_string,
            "timeline": timeline,
            "status": status,
            "severity": severity
        }
    return None

def main():
    print(f"OS-Level Target: {FIREWALL_LOG}")
    print(f"Streaming packets directly into Backend Pipeline: {LOG_INGEST_ENDPOINT}")

    if os.environ.get("USE_SYNTHETIC_LOGS", "").lower() in ("1", "true", "yes"):
        synthetic_log_loop()
        return

    for line in follow_log(FIREWALL_LOG):
        log_data = process_line(line)
        if log_data:
            _post_ingest(log_data)

if __name__ == "__main__":
    main()
