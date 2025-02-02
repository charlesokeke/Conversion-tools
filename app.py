from flask import Flask, render_template, request
from datetime import datetime
import base64
import ipaddress
import urllib.parse
import requests
import json
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Inject the visitor's IP address into every template context
@app.context_processor
def inject_visitor_ip():
    # If behind a proxy, X-Forwarded-For can contain a list of IPs.
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    return dict(visitor_ip=ip)

@app.route('/')
def index():
    return render_template('test.html')

@app.route('/test', methods=['POST', 'GET'])
def unix_time_convert():
    if request.method == 'POST':
        try:
            unix_timestamp = int(request.form.get('unix_time', ''))
            date_convert = datetime.fromtimestamp(unix_timestamp).strftime('%b %d, %Y %H:%M:%S')
            return render_template('test.html', date_covert=date_convert)
        except Exception as e:
            logging.exception("Error converting Unix timestamp")
            return render_template('test.html', unix_error="Invalid Unix timestamp")
    return render_template('test.html')

@app.route('/test2', methods=['POST', 'GET'])
def base64_convert():
    if request.method == 'POST':
        try:
            form_data = request.form
            input_str = form_data.get('base64_data', '')
            encode_counter = 0

            # Try to decode repeatedly until decoding fails.
            decoded_str = input_str
            while True:
                try:
                    temp = base64.b64decode(decoded_str).decode("utf-8")
                    if temp == decoded_str:
                        break
                    decoded_str = temp
                    encode_counter += 1
                except Exception:
                    break

            if encode_counter > 0:
                rounds_message = f"This object was encoded {encode_counter} time(s)"
                return render_template('test.html', base64_convert=decoded_str, encoded_rounds=rounds_message)
            else:
                # Otherwise, encode the input string once.
                encoded_str = base64.b64encode(input_str.encode('utf-8')).decode('utf-8')
                rounds_message = "Encoded 1 time(s)"
                return render_template('test.html', base64_convert=encoded_str, encoded_rounds=rounds_message)
        except Exception as e:
            logging.exception("Error in base64 conversion")
            return render_template('test.html', base64error='Invalid base64 entry')
    return render_template('test.html')

@app.route('/test3', methods=['POST', 'GET'])
def ip_convert():
    if request.method == 'POST':
        try:
            ip_input = request.form.get('ip_convert', '').replace(" ", "")
            ip_obj = ipaddress.ip_address(ip_input)
            binary_ip = ""
            if isinstance(ip_obj, ipaddress.IPv4Address):
                octets = ip_input.split(".")
                binary_ip = ".".join([bin(int(octet))[2:].zfill(8) for octet in octets])
                return render_template('test.html', binary_ip=binary_ip, ip_version="IPV4")
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                exploded = ip_obj.exploded
                hextets = exploded.split(":")
                binary_ip = ":".join([bin(int(hextet, 16))[2:].zfill(16) for hextet in hextets])
                return render_template('test.html', binary_ip=binary_ip, ip_version="IPV6")
        except Exception as e:
            logging.exception("Error converting IP address")
            return render_template('test.html', error="Invalid IP address")
    return render_template('test.html')

@app.route('/test4', methods=['POST', 'GET'])
def get_ip_subnet():
    if request.method == 'POST':
        try:
            subnet_mask = request.form.get('subnet_mask', '')
            ip_address = request.form.get('ip', '')
            ip_obj = ipaddress.ip_address(ip_address)
            network = ipaddress.ip_network(f"{ip_address}/{subnet_mask}", strict=False)
            return render_template('test.html', ip_subnet=str(network))
        except Exception as e:
            logging.exception("Error calculating subnet")
            return render_template('test.html', ip_subnet_error="Invalid entry")
    return render_template('test.html')

@app.route('/test5', methods=['POST', 'GET'])
def get_url():
    if request.method == 'POST':
        try:
            url = request.form.get('url_decode', '')
            if url:
                parsed = urllib.parse.urlparse(url)
                if not parsed.scheme:
                    url = "http://" + url
                decoded_url = urllib.parse.unquote_plus(url)
                return render_template('test.html', url_decoded=decoded_url)
            else:
                return render_template('test.html', url_error="Invalid URL")
        except Exception as e:
            logging.exception("Error decoding URL")
            return render_template('test.html', url_error="Invalid URL. Enter the URL in the format http://")
    return render_template('test.html')

@app.route('/test6', methods=['POST', 'GET'])
def get_url_redirects():
    if request.method == 'POST':
        try:
            url = request.form.get('url_redirector', '')
            if url:
                response = requests.get(url, allow_redirects=True, timeout=10)
                redirects = []
                for resp in response.history:
                    redirects.append({
                        "url": resp.url,
                        "response_code": resp.status_code
                    })
                redirects.append({
                    "url": response.url,
                    "response_code": response.status_code
                })
                return render_template('test.html', url_redirector=redirects)
            else:
                return render_template('test.html', url_redirect_error="Invalid URL")
        except Exception as e:
            logging.exception("Error tracing URL redirects")
            return render_template('test.html', url_redirect_error="Invalid URL")
    return render_template('test.html')

if __name__ == '__main__':
    app.run()
