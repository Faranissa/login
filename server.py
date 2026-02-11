#!/usr/bin/env python3
import hashlib
import struct
import binascii
import uuid
import random
import string
import requests
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

URL = "https://tnkbk.com/data/handleMsg.do?v="

class AutoLoginFlow:
    def __init__(self):
        self.login_size = 308
        self.second_size = 1024
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10)',
            'Accept': '*/*',
        })
    
    def rand_session(self):
        return hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()
    
    def rand_imei(self):
        return ''.join(str(random.randint(0, 9)) for _ in range(15))
    
    def rand_token(self):
        chars = string.ascii_uppercase + string.digits
        return ''.join(random.choice(chars) for _ in range(16))
    
    def rand_device_id(self):
        p1 = ''.join(str(random.randint(0, 9)) for _ in range(12))
        p2 = ''.join(str(random.randint(0, 9)) for _ in range(18))
        return f"{p1}-{p2}"
    
    def rand_uuid(self):
        return str(uuid.uuid4())
    
    def rand_token_string(self):
        chars = string.ascii_uppercase + string.digits
        return ''.join(random.choice(chars) for _ in range(17))
    
    def format_chip(self, chip):
        """Format chip ke K, M, B, T"""
        try:
            num = int(chip)
            
            if num >= 1_000_000_000_000:
                return f"{num / 1_000_000_000_000:.2f}T"
            elif num >= 1_000_000_000:
                return f"{num / 1_000_000_000:.2f}B"
            elif num >= 1_000_000:
                return f"{num / 1_000_000:.2f}M"
            elif num >= 1_000:
                return f"{num / 1_000:.2f}K"
            else:
                return str(num)
        except:
            return chip
    
    def create_login(self, user_id, password):
        payload = bytearray(self.login_size)
        
        session = self.rand_session().encode()
        imei = self.rand_imei().encode()
        token = self.rand_token().encode()
        pwd_md5 = hashlib.md5(password.encode()).hexdigest().encode()
        
        payload[0:32] = session[:32]
        struct.pack_into('<I', payload, 0x20, 0x94)
        struct.pack_into('<I', payload, 0x24, 0x58)
        payload[0x28:0x2C] = b'\x51\xCC\x80\x69'
        payload[0x2C:0x2C+15] = imei
        struct.pack_into('<I', payload, 0x50, 0)
        struct.pack_into('<I', payload, 0x54, 1)
        struct.pack_into('<I', payload, 0x58, 0x00990C16)
        payload[0x5C:0x60] = b'2.58'
        struct.pack_into('<I', payload, 0x64, 0x1FF)
        struct.pack_into('<I', payload, 0x68, 0)
        struct.pack_into('<I', payload, 0x6C, user_id)
        struct.pack_into('<I', payload, 0x90, 2)
        payload[0x94:0x94+32] = pwd_md5
        struct.pack_into('<I', payload, 0xD8, 1)
        payload[0xDC:0xDC+16] = token
        payload[0x104:0x114] = b'\x00' * 16
        
        sign = hashlib.md5(payload[0:0x114] + b"qwerpoiuasdflkjh").hexdigest().encode()
        payload[0x114:0x114+32] = sign
        
        return binascii.hexlify(payload).decode().upper()
    
    def parse_login_response(self, hex_resp):
        try:
            raw = binascii.unhexlify(hex_resp)
            status = struct.unpack_from('<I', raw, 0)[0]
            
            if status == 0:
                token_section = raw[4:36]
                token_hex = binascii.hexlify(token_section).decode()
                return {
                    'success': True,
                    'status': status,
                    'token': token_hex
                }
            else:
                message = raw[4:].decode('utf-8', errors='ignore').rstrip('\x00')
                return {
                    'success': False,
                    'status': status,
                    'token': None,
                    'message': message
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def create_second_request(self, user_id, login_token_hex):
        payload = bytearray(self.second_size)
        
        session = self.rand_session().encode()
        payload[0:32] = session[:32]
        
        struct.pack_into('<I', payload, 0x20, 0x94)
        struct.pack_into('<I', payload, 0x24, 0x99)
        payload[0x28:0x2C] = b'\xCC\x50\x8B\x69'
        
        imei = self.rand_imei().encode()
        payload[0x2C:0x2C+15] = imei
        
        struct.pack_into('<I', payload, 0x50, 0)
        struct.pack_into('<I', payload, 0x54, 1)
        struct.pack_into('<I', payload, 0x58, 0x00990C16)
        payload[0x5C:0x60] = b'2.58'
        struct.pack_into('<I', payload, 0x64, 0x1FF)
        struct.pack_into('<I', payload, 0x68, 0)
        struct.pack_into('<I', payload, 0x6C, user_id)
        
        struct.pack_into('<I', payload, 0x70, user_id)
        
        token_ascii = login_token_hex.rstrip('0')
        payload[0x74:0x74+len(token_ascii)] = token_ascii.encode()
        
        struct.pack_into('<I', payload, 0x90, 2)
        
        device_id = self.rand_device_id()
        payload[0x94:0x94+len(device_id)] = device_id.encode()
        
        uuid1 = self.rand_uuid()
        payload[0xD4:0xD4+36] = uuid1.encode()
        
        payload[0x114:0x124] = b'com.higgs.domino'
        
        hash1 = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:16]
        payload[0x154:0x154+16] = hash1.encode()
        
        payload[0x174:0x174+36] = uuid1.encode()
        
        hash2 = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()
        payload[0x198:0x198+32] = hash2.encode()
        
        struct.pack_into('<I', payload, 0x1B8, 0x0102)
        struct.pack_into('<I', payload, 0x1BC, 0x0272)
        
        payload[0x1C0:0x1DC] = b'Ye03foXThqjf7muGS9hbC/qlr4E='
        struct.pack_into('<I', payload, 0x1DC, 0x0A)
        
        token_str = self.rand_token_string()
        payload[0x1E0:0x1E0+len(token_str)] = token_str.encode()
        
        struct.pack_into('<I', payload, 0x1F4, 1)
        
        payload[0x1F8:0x3F8] = b'\x00' * 512
        
        sign = hashlib.md5(payload[0:0x3F8] + b"qwerpoiuasdflkjh").hexdigest().encode()
        payload[0x3F8:0x3F8+32] = sign
        
        return binascii.hexlify(payload).decode().upper()
    
    def send_request(self, url, max_retries=3):
        for attempt in range(max_retries):
            try:
                r = self.session.get(url, timeout=30)
                return {
                    'success': True,
                    'status_code': r.status_code,
                    'response': r.text.strip()
                }
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(2)
        
        return {'success': False, 'error': 'Max retries exceeded'}
    
    def parse_game_response(self, hex_resp):
        try:
            raw = binascii.unhexlify(hex_resp)
            
            status = struct.unpack_from('<I', raw, 0)[0]
            
            nickname = raw[4:100].decode('utf-8', errors='ignore').split('\x00')[0]
            
            chip_area = raw[240:260]
            chip_text = chip_area.decode('utf-8', errors='ignore').rstrip('\x00')
            chip_raw = ''.join(c for c in chip_text if c.isdigit())
            
            level_area = raw[260:275]
            level_text = level_area.decode('utf-8', errors='ignore').rstrip('\x00')
            level = ''.join(c for c in level_text if c.isdigit() or c == '.')
            
            if not chip_raw:
                chip_raw = "0"
            if not level or '.' not in level:
                level = "0"
            
            chip_formatted = self.format_chip(chip_raw)
            
            return {
                'status': status,
                'nickname': nickname,
                'chip': chip_formatted,
                'level': level
            }
        except Exception as e:
            return {
                'error': str(e),
                'raw': hex_resp[:200]
            }
    
    def execute_flow(self, user_id, password):
        login_payload = self.create_login(user_id, password)
        login_url = URL + login_payload
        
        login_result = self.send_request(login_url)
        
        if not login_result['success']:
            print(f"Login Error: {login_result.get('error')}")
            return
        
        parse_result = self.parse_login_response(login_result['response'])
        
        if parse_result['success']:
            second_payload = self.create_second_request(user_id, parse_result['token'])
            second_url = URL + second_payload
            
            second_result = self.send_request(second_url)
            
            if second_result['success']:
                game_data = self.parse_game_response(second_result['response'])
                
                if 'error' not in game_data:
                    print(f"Nickname : {game_data['nickname']}")
                    print(f"Chip     : {game_data['chip']}")
                    print(f"Level    : {game_data['level']}")
                else:
                    print(f"Parse Error: {game_data['error']}")
            else:
                print(f"Second Request Error: {second_result.get('error')}")
        else:
            print(f"Login Failed!")
            print(f"Status  : {parse_result.get('status')}")
            print(f"Message : {parse_result.get('message', 'N/A')}")

flow = AutoLoginFlow()

@app.route('/')
def home():
    return 'Auto Login Service'

@app.route('/login')
def login():
    user_id = request.args.get('userId')
    password = request.args.get('password')
    
    if not user_id or not password:
        return jsonify({'error': 'Missing userId or password'}), 400
    
    try:
        user_id_int = int(user_id)
    except ValueError:
        return jsonify({'error': 'userId must be a number'}), 400
    
    # Jalankan flow
    login_payload = flow.create_login(user_id_int, password)
    login_url = URL + login_payload
    
    login_result = flow.send_request(login_url)
    
    if not login_result['success']:
        return jsonify({'error': f"Login Error: {login_result.get('error')}"})
    
    parse_result = flow.parse_login_response(login_result['response'])
    
    if parse_result['success']:
        second_payload = flow.create_second_request(user_id_int, parse_result['token'])
        second_url = URL + second_payload
        
        second_result = flow.send_request(second_url)
        
        if second_result['success']:
            game_data = flow.parse_game_response(second_result['response'])
            
            if 'error' not in game_data:
                return jsonify({
                    'success': True,
                    'nickname': game_data['nickname'],
                    'chip': game_data['chip'],
                    'level': game_data['level']
                })
            else:
                return jsonify({'error': f"Parse Error: {game_data['error']}"})
        else:
            return jsonify({'error': f"Second Request Error: {second_result.get('error')}"})
    else:
        return jsonify({
            'error': f"Login Failed!",
            'status': parse_result.get('status'),
            'message': parse_result.get('message', 'N/A')
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
