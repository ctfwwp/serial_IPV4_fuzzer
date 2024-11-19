# 模糊测试 IPV4 / ESP  协议

from scapy.all import *
from mutation_fuzzer import fuzzer
import time

def bytes_to_hex(a):
    if a <= 15:
        return "0" + hex(a)[2:]
    else:
        return hex(a)[2:]

def replay_fuzzer(fuzzer_number, tl, mac, eth0):
    for i in range(0,fuzzer_number):
        print("第",i,"条异常数据")
        packets = rdpcap('IPV4-1.pcap')
        random_number = random.choice([0])
        pkt = packets[random_number]
        # pkt.show()
        if pkt.haslayer('ESP'):
            fc_code = ""
            for i in pkt[ESP].data:
                fc_code = fc_code + bytes_to_hex(i)
            fc_code = fuzzer(fc_code)
            # fc_code = fc_code
            new_payload = bytes.fromhex(fc_code)
            new_len = pkt[IP].len - len(pkt[ESP].data) + len(new_payload)
            pkt[ESP].data = new_payload
            pkt[IP].len = new_len
            pkt.src = mac   #更改为本机的MAC地址
            #pkt.show()   #显示整个协议
            sendp(pkt, iface=eth0)
            time.sleep(tl)
        elif pkt.haslayer('Raw'):
            time.sleep(tl)
            fc_code = ""
            for i in pkt.load:
                fc_code = fc_code + bytes_to_hex(i)
            fc_code = fuzzer(fc_code)
            # fc_code = fc_code
            new_payload = bytes.fromhex(fc_code)
            new_len = pkt[IP].len - len(pkt.load) + len(new_payload)
            pkt.load = new_payload
            pkt[IP].len = new_len
            pkt.src = mac   #更改为本机的MAC地址
            # pkt.show()   #显示整个协议
            sendp(pkt, iface=eth0)
            time.sleep(tl)
        else:
            pass
if __name__ == "__main__":
    fuzzer_number = 100  # 模糊测试的个数
    tl = 1  # 每个测试用例发送相隔的时间
    mac = "xx:xx:xx:xx:xx:xx"  # 本机的mac地址
    eth0 = "xxxxxx"
    replay_fuzzer(fuzzer_number, tl, mac, eth0)