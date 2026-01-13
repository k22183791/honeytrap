HONEYPOT_NAME    = "HoneyTrap-DC01"
LOG_FILE         = "attack_log.json"
DASHBOARD_PORT   = 5000
REPEAT_THRESHOLD = 3

SERVICES = {22: "SSH", 21: "FTP", 8080: "HTTP"}

# real version strings — scanners validate these before continuing
BANNERS = {
    22:   b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    21:   b"220 (vsFTPd 3.0.5)\r\n",
    8080: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)\r\n\r\n",
}

EXPLOIT_SIGS = [
    "/../", "%2e%2e", "select ", "union ", "<script",
    "cmd.exe", "/bin/sh", "wget ", "curl ",
    "eval(", "base64", "passwd", "shadow",
]

KNOWN_CREDS = [
    "root", "admin", "administrator", "user",
    "guest", "test", "ubuntu", "pi", "postgres",
]