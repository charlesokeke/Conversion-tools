from flask import Flask, render_template, request
from datetime import datetime
import base64
import ipaddress
import re
import urllib
import requests
import json

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('test.html')

@app.route('/test', methods=['POST','GET'])
def unix_time_convert():
    print('reached')
    try:
        form_data = request.form
        date_covert = datetime.fromtimestamp(int(form_data['unix_time'])).strftime('%b %d, %Y %H:%M:%S')
        return render_template('test.html',date_covert=date_covert)
    except:
        return render_template('test.html',unix_error="invalid unix timestap")           
 
@app.route('/test2', methods=['POST','GET'])
def base64_convert():
    pattern = re.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$")
    enconde_counter = 0
  
    try:
        # Attempt to decode the string with base64
        form_data = request.form
        base64_convert = form_data['base64_data']
        if  pattern.match(base64_convert):       
            while pattern.match(base64_convert):
                base64_convert = base64.b64decode(base64_convert).decode("utf-8")    
                enconde_counter += 1
            encoded_rounds = 'This object was encoded {} time(s)'.format(enconde_counter)
            return render_template('test.html',base64_convert=base64_convert, encoded_rounds=encoded_rounds)
        elif isinstance(base64_convert, str):
            while not pattern.match(base64_convert):
                base64_convert = base64_convert.encode('utf-8')
                base64_convert =  base64.b64encode(base64_convert).decode('utf-8')
                enconde_counter += 1
            encoded_rounds = 'This object was encoded {} time(s)'.format(enconde_counter)    
            return render_template('test.html',base64_convert=base64_convert,encoded_rounds=encoded_rounds)         
        else:
            return render_template('test.html', base64error='Invalid base64 entry')       
        
    except:
        # If an exception is raised, it's not a valid base64 encoded string
         return render_template('test.html', base64error='Invalid base64 entry')
        


@app.route('/test3', methods=['POST','GET'])
def ip_convert():
 
    
    try:
        ip_address = request.form['ip_convert'].replace(" ", "")
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
    except:
        return render_template('test.html',error="Invalid IP address")        
    
    


@app.route('/test4', methods=['POST','GET'])
def get_ip_subnet():
    try:
        subnet_mask = request.form['subnet_mask']
        ip_address= request.form['ip']
        ip = ipaddress.ip_address(ip_address)
        ip_subnet = str(ipaddress.ip_network(ip_address + '/' + subnet_mask, strict=False))
        return render_template('test.html',ip_subnet=ip_subnet) 
    except:
         return render_template('test.html',ip_subnet_error="Invalid entry")   


@app.route('/test5', methods=['POST','GET'])
def get_url():
    
    try:
        url = request.form['url_decode']
        url_check = urllib.parse.urlparse(url)
        if url:
            url = urllib.parse.unquote(url)
            url = urllib.parse.unquote_plus(url)
        elif isinstance(url, unicode):
            url = urllib.parse.quote(url.encode('utf8'))
            url = urllib.parse.unquote(url)
            url = urllib.parse.unquote_plus(url)
        else:
            return render_template('test.html',url_error="invalid url") 
        return render_template('test.html',url_decoded=url)
    except:
         return render_template('test.html',url_error="Invalid url. Enter the url in the format http://")  


@app.route('/test6', methods=['POST','GET'])        
def get_url_redirects():
    url_redirects = []
    
    try:
        url = request.form['url_redirector']
        responses = requests.get(url)
        final_code_200 = responses.status_code
        final_url = responses.url
        
       
        if url:
            for response in responses.history:
                url_redirects.append({ "url":response.url, "response_code":response.status_code})
            #print(response.status_code) 
            url_redirects.append({"url":final_url,"response_code":final_code_200})            
            url_redirects = json.loads(json.dumps(url_redirects))
            return render_template('test.html',url_redirector=url_redirects)
        else:
            return render_template('test.html',url_redirect_error="Invalid url") 
        
    except:
         return render_template('test.html',url_redirect_error="Invalid url")
         

if __name__ == '__main__':
    app.run()
