from socket import *
import ast
import rsa
import hmac
import hkdf
import pyDes
import hashlib
import random


class Server:
    def __init__(self):
        self.connectionSocket = None
        self.serverRandom = None
        self.clientRandom = None
        self.serverKeys = None
        self.serverCrt = None
        self.sessionKey = None

    def Server_connect(self):
        print('\n================ Server Connect ================')
        serverSocket = socket(AF_INET, SOCK_STREAM)             # 创建套接字
        serverSocket.bind(('', 6789))                           # 绑定地址和端口
        serverSocket.listen(1)                                  # 监听端口
        self.connectionSocket, addr = serverSocket.accept()     # 被动接受连接
        print('Server connect established')

    def Server_hello(self):
        print('\n================ Server Hello ================')
        Msg_client_hello = ast.literal_eval(self.connectionSocket.recv(1024).decode())
        self.clientRandom = Msg_client_hello['Client Random']
        print('(1) Receive client hello message from client')
        print('    clientRandom:', self.clientRandom)

        self.serverRandom = random.getrandbits(32).to_bytes(4, 'big')
        print('(2) Generate server random')

        Msg_server_hello = {'TLS Version': Msg_client_hello['TLS Version'],     # 确定的 TLS 版本
                            'Cipher Suite': Msg_client_hello['Cipher Suite'],   # 确定的密码套件
                            'Server Random': self.serverRandom}                 # 服务器随机数
        self.connectionSocket.send(str(Msg_server_hello).encode())
        print('(3) Send server hello message to client')
        for key, value in Msg_server_hello.items():
            print('    ' + key + ':', value)

    def Server_send_crt(self):
        print('\n================ Server Send Certificate ================')
        self.serverKeys = rsa.newkeys(256)								# 生成公钥和私钥
        serverPubkey = self.serverKeys[0].save_pkcs1()					# 转化为 pkcs1 格式便于传输
        serverCrt = open('server.crt').read()							# 读取服务器证书
        Msg_server_send_crt = {'serverPubkey': serverPubkey,
                               'serverCrt': serverCrt}
        self.connectionSocket.send(str(Msg_server_send_crt).encode())	# 将字典转化为字符串传输
        print('(1) Server send certificate and pubkey')
        print('    Server public key:', serverPubkey)
        print('    Server certificate:', 'server.crt')

    def Server_generate_sessionkey(self):
        print('\n================ Server Generate Session Key ================')
        Msg_client_key_exchange = self.connectionSocket.recv(1024)
        print('(1) Receive encrypted premaster secret from client')             # 接收客户端的加密信息
        serverPrivkey = self.serverKeys[1]
        premasterSecret = rsa.decrypt(Msg_client_key_exchange, serverPrivkey)   # 通过 RSA 私钥解密得到预主密钥
        print('(2) Decrypt premaster secret with server private key')
        print('    premasterSecret:', premasterSecret)
        # 把 clientRandom 和 serverRandom 相加作为密钥，对预主密钥进行 MD5 哈希运算生成主密钥
        masterSecret = hmac.new(self.clientRandom + self.serverRandom,
                                premasterSecret, 'MD5').digest()
        print('(3) Generate master secret', masterSecret)
        print('    masterSecret:', masterSecret)
        salt = 'yangyi'.encode()
        PRK = hkdf.hkdf_extract(salt, masterSecret)         # 加盐伪随机化
        self.sessionKey = hkdf.hkdf_expand(PRK, b'', 8)     # 扩展到 8 字节
        print('(4) Generate session key')
        print('    sessionKey:', self.sessionKey)

    def Server_send(self):  # 会话密钥协商好之后发送信息的函数
        print('\n================ Server Send ================')
        text = 'The quick brown fox jumps over a lazy dog'
        ciphermsg, MAC = self.Encrypt(text)
        self.connectionSocket.send(ciphermsg)
        print('(1) Server send cipher message to client')
        print('    text:', text)
        print('    MAC:', MAC)

    def Server_receive(self):
        print('\n================ Server Receive ================')
        ciphermsg = self.connectionSocket.recv(1024)
        ciphertext, text, MAC = self.Decrypt(ciphermsg)
        print('(1) Server receive text from client')
        print('    MAC:', MAC)
        # 进行 SHA256 加密得到 verifyMAC，验证它和 MAC 是否相同
        verifyMAC = hashlib.sha256(ciphertext).digest()
        print('(2) Server verify MAC')
        print('    verifyMAC:', verifyMAC)
        if verifyMAC != MAC:
            print('    Verification fail\nServer closing...')
            self.Server_close()
        else:
            print('    Verification pass')
            print('    text:', text)

    def Server_close(self):
        print('\n================ Server Close ================')
        print('Server close')
        self.connectionSocket.close()

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
    server = Server()

    # 建立连接
    server.Server_connect()

    # TLS 握手
    server.Server_hello()
    server.Server_send_crt()
    server.Server_generate_sessionkey()

    # 加密通信
    server.Server_receive()
    server.Server_send()

    # 关闭连接
    server.Server_close()


if __name__ == '__main__':
    main()
