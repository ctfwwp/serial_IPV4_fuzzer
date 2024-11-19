# 模糊测试 串口协议

import serial
import time
from mutation_fuzzer import fuzzer

class SerialFuzzTester:
    def __init__(self, port, baudrate=9600, timeout=1):
        self.serial_port = serial.Serial(port, baudrate, timeout=timeout)
        print(f"连接到 {port}，波特率：{baudrate}")

    def send_payload(self, payload):
        try:
            self.serial_port.write(payload)
            print(f"发送数据: {payload.hex().upper()}")
        except serial.SerialException as e:
            print(f"发送数据时出错: {e}")

    def read_response(self):
        try:
            time.sleep(0.3)  # 等待设备的响应时间
            if self.serial_port.in_waiting > 0:  # 检查是否有数据可读
                response = self.serial_port.read(self.serial_port.in_waiting)  # 读取所有可用数据
                print(f"接收数据: {response.hex().upper()}")
            else:
                print("没有数据返回")
        except serial.SerialException as e:
            print(f"读取数据时出错: {e}")

    def fuzz_test(self, original_payload, num_tests=100):
        for i in range(num_tests):
            mutated_payload = fuzzer(original_payload)
            mutated_payload = bytes.fromhex(mutated_payload)
            self.send_payload(mutated_payload)
            self.read_response()  # 发送后读取响应
            time.sleep(0.3)  # 等待一段时间，给设备反应的时间

    def close(self):
        self.serial_port.close()
        print("串口已关闭")

if __name__ == "__main__":
    # 原始协议数据

    original_hex = "01020304050607"
    port = "COM3"  # 替换成你的串口号，例如 '/dev/ttyUSB0' 或 'COM3'
    baudrate = 115200  #波特率
    tester = SerialFuzzTester(port, baudrate)
    try:
        tester.fuzz_test(original_hex, num_tests=10000)
    except KeyboardInterrupt:
        print("模糊测试中止")
    finally:
        tester.close()