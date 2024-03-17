from socket import *
import ast
import os
import rsa
import hmac
import hkdf
import pyDes
import hashlib
import random


class Client:
    def __init__(self):
        self.clientSocket = None
        self.clientRandom = None
        self.serverRandom = None
        self.serverPubkey = None
        self.sessionKey = None

    def Client_connect(self):
        print('\n================ Client Connect ================')
        self.clientSocket = socket(AF_INET, SOCK_STREAM)	# 创建套接字
        self.clientSocket.connect(('127.0.0.1', 6789))		# 初始化服务器连接
        print('Client connection established')

    def Client_hello(self):
        print('\n================ Client Hello ================')
        self.clientRandom = random.getrandbits(32).to_bytes(4, 'big')   # 客户端 32 位随机数
        print('(1) Generate client random')
        print('    clientRandom:', self.clientRandom)
        Msg_client_hello = {'TLS Version': 'myTLS',                     # TLS 版本号
                            'Cipher Suite': 'TLS_RSA_WITH_DES_SHA256',  # 密码套件
                            'Client Random': self.clientRandom}         # 客户端随机数
        self.clientSocket.send(str(Msg_client_hello).encode())
        print('(2) Send client hello message to server')
        for key, value in Msg_client_hello.items():
            print('    ' + key + ':', value)

    def Client_verify_crt(self):
        print('\n================ Client Verify Certificate ================')
        Msg_server_hello = ast.literal_eval(self.clientSocket.recv(1024).decode())      # 将字符串转化回字典
        self.serverRandom = Msg_server_hello['Server Random']                           # 服务器随机数
        print('(1) Receive server hello message from server')
        print('    serverRandom:', self.serverRandom)

        Msg_server_send_crt = ast.literal_eval(self.clientSocket.recv(1024).decode())   # 将字符串转化回字典
        self.serverPubkey = Msg_server_send_crt['serverPubkey']                         # 服务器公钥
        serverCrt = Msg_server_send_crt['serverCrt']
        print('(2) Receive server public key and certificate from server')
        print('    serverPubkey:', self.serverPubkey)

        print('(2) Verify certificate')
        with open('get_server.crt', 'wb') as f:                                         # 将证书字符串写入创建的文件
            f.write(serverCrt.encode())
        if os.system("openssl verify -CAfile ../ca/ca.crt ./get_server.crt") != 0:      # 运行 openssl 命令验证证书
            print('    Certificate verify fail')
            self.Client_close()
            exit(1)
        else:
            print('    Certificate verify pass')

    def Client_key_exchange(self):
        print('\n================ Client Key Exchange ================')
        premasterSecret = random.getrandbits(48).to_bytes(8, 'big')     # 生成 48 位预主密钥
        print('(1) Generate premaster secret')
        print('    premasterSecret:', premasterSecret)
        Msg_client_key_exchange = rsa.encrypt(premasterSecret, rsa.PublicKey.load_pkcs1(self.serverPubkey))
        print('(2) Encrypt premaster secret with server public key')    # 使用服务器的 rsa 公钥加密后发送给服务器
        self.clientSocket.send(Msg_client_key_exchange)
        print('(3) Send encrypted premaster secret to server')
        self.sessionKey = self.Client_generate_sessionkey(premasterSecret)

    def Client_send(self):  # 会话密钥协商好之后发送信息的函数
        print('\n================ Client Send ================')
        text = 'The long snake passes under a large elephant'
        ciphermsg, MAC = self.Encrypt(text)
        self.clientSocket.send(ciphermsg)
        print('(1) Client send cipher message to server')
        print('    text:', text)
        print('    MAC:', MAC)

    def Client_receive(self):
        print('\n================ Client Receive ================')
        ciphermsg = self.clientSocket.recv(1024)
        ciphertext, text, MAC = self.Decrypt(ciphermsg)
        print('(1) Client receive text from server')
        print('    MAC:', MAC)
        # 进行 SHA256 加密得到 verifyMAC，验证它和 MAC 是否相同
        verifyMAC = hashlib.sha256(ciphertext).digest()
        print('(2) Client verify MAC')
        print('    verifyMAC:', verifyMAC)
        if verifyMAC != MAC:
            print('    Verification fail\nClient closing...')
            self.Client_close()
        else:
            print('    Verification pass')
            print('    text:', text)

    def Client_close(self):
        print('\n================ Client Close ================')
        print('Client close')
        self.clientSocket.close()

    def Client_generate_sessionkey(self, premasterSecret):
        print('\n================ Client Generate Session Key ================')
        # 把 clientRandom 和 serverRandom 相加作为密钥，对预主密钥进行 MD5 哈希运算生成主密钥
        masterSecret = hmac.new(self.clientRandom + self.serverRandom, premasterSecret, 'MD5').digest()
        print('(1) Generate master secret')
        print('    masterSecret:', masterSecret)
        salt = 'yangyi'.encode()
        PRK = hkdf.hkdf_extract(salt, masterSecret)     # 加盐伪随机化
        sessionKey = hkdf.hkdf_expand(PRK, b'', 8)      # 扩展到 8 字节
        print('(2) Generate session key')
        print('    sessionKey:', sessionKey)
        return sessionKey

    def Encrypt(self, text):
        key = self.sessionKey
        des = pyDes.des(key, pyDes.ECB, key, padmode=pyDes.PAD_PKCS5)   # 初始化一个 des 对象并进行加密
        ciphertext = des.encrypt(text.encode())
        MAC = hashlib.sha256(ciphertext).digest()                       # 对加密后的密文进行 SHA256 加密得到 MAC
        ciphertext += MAC
        ciphermsg = des.encrypt(ciphertext)                             # 将密文和 MAC 拼接后再次进行 DES 加密得到最终的加密消息
        return ciphermsg, MAC

    def Decrypt(self, ciphermsg):
        key = self.sessionKey
        des = pyDes.des(key, pyDes.ECB, key, padmode=pyDes.PAD_PKCS5)   # 传递和客户端相同的参数初始化一个 des 对象
        plainmsg = des.decrypt(ciphermsg)
        ciphertext = plainmsg[0:-32]                                    # 截取后 256 位得到 MAC
        MAC = plainmsg[-32:len(plainmsg)]                               # 其余位数为 ciphertext
        text = des.decrypt(ciphertext).decode()                         # 再对 ciphertext 解密得到原来的消息
        return ciphertext, text, MAC


def main():
    client = Client()

    # 建立连接
    client.Client_connect()

    # TLS 握手
    client.Client_hello()
    client.Client_verify_crt()
    client.Client_key_exchange()

    # 加密通信
    client.Client_send()
    client.Client_receive()

    # 关闭连接
    client.Client_close()


if __name__ == '__main__':
    main()
