"""
LogGuardian AI Sample Log Generator.
Programmatically builds highly realistic security logs mimicking various attack patterns
(SQLi, XSS, Path Traversal, SSH Brute Force, Sudo abuse, Port scans, DoS).
"""

import os
from datetime import datetime, timedelta

def generate_sample_logs(output_dir: str = "sample_logs") -> None:
    """Generates mock log files for platform ingestion and validation."""
    os.makedirs(output_dir, exist_ok=True)
    
    now = datetime.now()

    # 1. Apache Access Log (SQLi, XSS, Directory Traversal, path scans)
    apache_path = os.path.join(output_dir, "apache.log")
    apache_lines = [
        # Normal accesses
        f'192.168.1.5 - - [{now - timedelta(minutes=60):%d/%b/%Y:%H:%M:%S +0000}] "GET /index.html HTTP/1.1" 200 12043 "http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
        f'192.168.1.5 - - [{now - timedelta(minutes=59):%d/%b/%Y:%H:%M:%S +0000}] "GET /static/style.css HTTP/1.1" 200 4502 "http://example.com/index.html" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
        f'192.168.1.12 - - [{now - timedelta(minutes=55):%d/%b/%Y:%H:%M:%S +0000}] "GET /about.html HTTP/1.1" 200 3409 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
        
        # SQL Injection attempt
        f'198.51.100.42 - - [{now - timedelta(minutes=45):%d/%b/%Y:%H:%M:%S +0000}] "GET /products.php?id=1%20OR%201=1 HTTP/1.1" 200 40593 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
        f'198.51.100.42 - - [{now - timedelta(minutes=44):%d/%b/%Y:%H:%M:%S +0000}] "GET /products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 500 230 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
        
        # Directory Traversal attempt
        f'203.0.113.80 - - [{now - timedelta(minutes=30):%d/%b/%Y:%H:%M:%S +0000}] "GET /downloads.php?file=../../../../etc/passwd HTTP/1.1" 200 1482 "-" "Mozilla/5.0 (Linux; Android 10)"',
        f'203.0.113.80 - - [{now - timedelta(minutes=29):%d/%b/%Y:%H:%M:%S +0000}] "GET /downloads.php?file=..%2f..%2f..%2fwin.ini HTTP/1.1" 404 153 "-" "Mozilla/5.0 (Linux; Android 10)"',
        
        # XSS attempt
        f'198.51.100.77 - - [{now - timedelta(minutes=20):%d/%b/%Y:%H:%M:%S +0000}] "GET /search.php?query=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1" 200 2940 "http://example.com/search.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
        
        # Scanning directories
        f'185.220.101.5 - - [{now - timedelta(minutes=15):%d/%b/%Y:%H:%M:%S +0000}] "GET /wp-admin/ HTTP/1.1" 404 153 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"',
        f'185.220.101.5 - - [{now - timedelta(minutes=14):%d/%b/%Y:%H:%M:%S +0000}] "GET /.env HTTP/1.1" 200 843 "-" "Mozilla/5.0 (compatible; Nikto)"',
        f'185.220.101.5 - - [{now - timedelta(minutes=13):%d/%b/%Y:%H:%M:%S +0000}] "GET /.git/config HTTP/1.1" 404 153 "-" "Mozilla/5.0 (compatible; Nikto)"'
    ]
    with open(apache_path, "w", encoding="utf-8") as f:
        f.write("\n".join(apache_lines) + "\n")

    # 2. Nginx Access Log (Suspicious agents, DoS volumetric attack)
    nginx_path = os.path.join(output_dir, "nginx.log")
    nginx_lines = [
        # Normal traffic
        f'192.168.1.20 - - [{now - timedelta(minutes=10):%d/%b/%Y:%H:%M:%S +0000}] "GET /home HTTP/1.1" 200 8420 "-" "Mozilla/5.0 (Windows NT 10.0)"',
        
        # Malicious user agents (sqlmap)
        f'198.51.100.120 - - [{now - timedelta(minutes=5):%d/%b/%Y:%H:%M:%S +0000}] "GET /index.php?id=1 HTTP/1.1" 200 2034 "-" "sqlmap/1.4.12#stable (http://sqlmap.org)"',
        
        # Missing User Agent
        f'198.51.100.121 - - [{now - timedelta(minutes=4):%d/%b/%Y:%H:%M:%S +0000}] "GET /api/v1/health HTTP/1.1" 200 45 "-" ""'
    ]
    
    # DoS volume flood: 120 hits in 30 seconds from same IP
    dos_ip = "203.0.113.250"
    for i in range(120):
        offset_sec = i * 0.2  # spacing of 200ms
        log_time = now - timedelta(minutes=2) + timedelta(seconds=offset_sec)
        nginx_lines.append(
            f'{dos_ip} - - [{log_time:%d/%b/%Y:%H:%M:%S +0000}] "GET /index.php HTTP/1.1" 200 4510 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        )
    with open(nginx_path, "w", encoding="utf-8") as f:
        f.write("\n".join(nginx_lines) + "\n")

    # 3. SSH log (brute force failure loop, then successful compromise login)
    ssh_path = os.path.join(output_dir, "ssh.log")
    ssh_lines = []
    bf_ip = "182.21.34.80"
    
    # Generate 8 failures targeting root and admin
    for i in range(8):
        log_time = now - timedelta(minutes=15) + timedelta(seconds=i * 20)
        target_user = "admin" if i % 2 == 0 else "root"
        ssh_lines.append(
            f'{log_time:%b %d %H:%M:%S} ubuntu sshd[28491]: Failed password for {target_user} from {bf_ip} port {45000 + i} ssh2'
        )
    
    # Successful login from same IP shortly after
    success_time = now - timedelta(minutes=15) + timedelta(seconds=180)
    ssh_lines.append(
        f'{success_time:%b %d %H:%M:%S} ubuntu sshd[28510]: Accepted password for root from {bf_ip} port 45109 ssh2'
    )
    ssh_lines.append(
        f'{success_time:%b %d %H:%M:%S} ubuntu sshd[28510]: pam_unix(sshd:session): session opened for user root by (uid=0)'
    )
    with open(ssh_path, "w", encoding="utf-8") as f:
        f.write("\n".join(ssh_lines) + "\n")

    # 4. Linux Auth Log (sudo commands, privilege elevation)
    auth_path = os.path.join(output_dir, "auth.log")
    auth_lines = [
        f'{now - timedelta(minutes=50):%b %d %H:%M:%S} host sudo:    aswin : TTY=pts/0 ; PWD=/home/aswin ; USER=root ; COMMAND=/bin/systemctl restart nginx',
        f'{now - timedelta(minutes=45):%b %d %H:%M:%S} host sshd[28912]: Invalid user guest from 192.168.1.105 port 51234',
        f'{now - timedelta(minutes=45):%b %d %H:%M:%S} host sshd[28912]: Failed password for invalid user guest from 192.168.1.105 port 51234 ssh2',
        
        # Suspicious admin elevation commands
        f'{now - timedelta(minutes=10):%b %d %H:%M:%S} host sudo:    meera : TTY=pts/1 ; PWD=/home/meera ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow',
        f'{now - timedelta(minutes=9):%b %d %H:%M:%S} host sudo:    meera : TTY=pts/1 ; PWD=/home/meera ; USER=root ; COMMAND=/bin/chmod 777 /etc/shadow'
    ]
    with open(auth_path, "w", encoding="utf-8") as f:
        f.write("\n".join(auth_lines) + "\n")

    # 5. Firewall log (port sweep scanning)
    firewall_path = os.path.join(output_dir, "firewall.log")
    firewall_lines = []
    scanner_ip = "198.51.100.99"
    local_target = "10.0.0.15"
    
    # Port sweep lines
    ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]
    for i, port in enumerate(ports):
        log_time = now - timedelta(minutes=25) + timedelta(seconds=i * 5)
        firewall_lines.append(
            f'{log_time:%b %d %H:%M:%S} firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 '
            f'SRC={scanner_ip} DST={local_target} LEN=40 TOS=0x00 TTL=64 PROTO=TCP SPT={50000 + i} DPT={port}'
        )
    with open(firewall_path, "w", encoding="utf-8") as f:
        f.write("\n".join(firewall_lines) + "\n")

    print("Mock log samples generated successfully.")

if __name__ == "__main__":
    generate_sample_logs()
