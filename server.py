from flask import Flask, render_template, request
from datetime import datetime
import base64
import ipaddress

app = Flask(__name__)

@app.route('/')
def index():
    print("hello")
    return render_template('test.html')

@app.route('/test', methods=['POST'])
def unix_time_convert():
    print('reached')
    form_data = request.form
    date_covert = datetime.fromtimestamp(int(form_data['unix_time'])).strftime('%b %d, %Y %H:%M:%S')
    return render_template('test.html',date_covert=date_covert)
 
@app.route('/test2', methods=['POST'])
def base64_convert():
    try:
        # Attempt to decode the string with base64
        form_data = request.form
        base64_convert = base64.b64decode(form_data['base64_data'])
        return render_template('test.html',base64_convert=base64_convert)
    except (binascii.Error, TypeError):
        # If an exception is raised, it's not a valid base64 encoded string
        return render_template('test.html',base64_convert=base64_convert)
        


@app.route('/test3', methods=['POST'])
def ip_convert():
 
    ip_address = request.form['ip_convert']
    print(ip_address)

    try:
        # Convert the address to binary
        binary_ip = ""
        if isinstance(ipaddress.ip_address(ip_address),ipaddress.IPv4Address):
        # Convert each octet to binary
            octets = ip_address.split(".")
            for octet in octets:
                binary_octet = bin(int(octet))[2:].zfill(8)
                binary_ip += binary_octet + "."
        # Remove the last "."
            binary_ip = binary_ip[:-1]
            return render_template('test.html',binary_ip=binary_ip, ip_version="IPV4")
        elif isinstance(ipaddress.ip_address(ip_address),ipaddress.IPv6Address):
        # Convert each hextet to binary
            hextets = ip_address.split(":")
            for hextet in hextets:
                binary_hextet = bin(int(hextet, 16))[2:].zfill(16)
                binary_ip += binary_hextet + ":"
        # Remove the last ":"
            binary_ip = binary_ip[:-1]
            return render_template('test.html',binary_ip=binary_ip, ip_version="IPV6")    
    except ValueError:
        return render_template('test.html',error="Invalid IP address")        
    
    


@app.route('/test4', methods=['POST'])
def get_ip_subnet():
    subnet_mask = request.form['subnet_mask']
    ip_address= request.form['ip']
    ip = ipaddress.ip_address(ip_address)
    ip_subnet = str(ipaddress.ip_network(ip_address + '/' + subnet_mask, strict=False))
    return render_template('test.html',ip_subnet=ip_subnet)    

if __name__ == '__main__':
    app.run(debug=True)
