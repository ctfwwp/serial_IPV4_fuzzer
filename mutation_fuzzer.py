# 模糊测试变异策略
import random

def randomize_bytes(data: bytes, num_changes: int) -> bytes:
    # 随机更改指定数量的字节的值, 随机对1  - len(data)个字节进行随机变化
    data_list = list(data)
    for _ in range(num_changes):
        index = random.randint(0, len(data_list) - 1)
        data_list[index] = random.randint(0, 255)
    return bytes(data_list)

def modify_length(data: bytes, length_change: int) -> bytes:
    # 根据指定的长度变化来修改字节数据的长度。
    if length_change > 0:
        # 随机0-255个添加字节，添加到随机位置
        return data[0:length_change] + bytes.fromhex(format(random.randint(0, 255) , '02x')) * random.randint(1,255) + data[length_change:]
    elif length_change < 0:
        # 随机删除 abs(length_change)/2个数据
        byte_list = list(data)
        for i in range(0, int(abs(length_change)/2)):
            index_to_remove = random.randint(0, len(byte_list) - 1)
            byte_list.pop(index_to_remove)
        updated_byte_data = bytes(byte_list)
        return updated_byte_data # 删除字节
    return data

def mutate_payload(data: bytes, offset: int) -> bytes:
    #替换字节数据中的内容为随机字节，
    random_integer = random.randint(0, 255)
    new_value = bytes([random_integer])
    if offset + len(new_value) <= len(data):
        return data[:offset] + new_value + data[offset + len(new_value):]
    return data

def max_and_min(data: bytes, offset: int) -> bytes:
    #替换字节数据中的内容为最大值或最小值，
    new_value  = random.choice([ b'\x00',b'\x01',b'\x02', b'\xff',b'\xfe',b'\xee'])
    if offset + len(new_value) <= len(data):
        return data[:offset] + new_value + data[offset + len(new_value):]
    return data

def copy_and_paste(data: bytes, start: int, end: int, insert_offset: int) -> bytes:
    # 从字节数据中复制一段，粘贴到另一位置
    if 0 <= start < end <= len(data):
        segment = data[start:end]
        return data[:insert_offset] + segment + data[insert_offset:]
    elif 0 <= end < start <= len(data):
        segment = data[end:start]
        return data[:insert_offset] + segment + data[insert_offset:]
    return data

def flip_bytes(data: bytes, indices: list) -> bytes:
    # 反转指定索引处的字节值（即计算255减当前字节值）
    data_list = list(data)
    for index in indices:
        if 0 <= index < len(data_list):
            data_list[index] = 255 - data_list[index]  # 反转字节
    return bytes(data_list)

def insert_special_characters(data: bytes, indices: list) -> bytes:
    # 从特殊字符中随机选取一个插入
    special_chars = [
        b'\x00',  # 空字符
        b'\n',  # 换行
        b'\r',  # 回车
        b'\t',  # 制表符
        b'\'',  # 单引号
        b'\"',  # 双引号
        b'\\',  # 反斜杠
        b' ',  # 空格
        b'!',  # 感叹号
        b'#',  # 井号
        b'$',  # 美元符号
        b'%',  # 百分号
        b'^',  # 符号 ^
        b'&',  # 和号
        b'*',  # 星号
        b'(',  # 左括号
        b')',  # 右括号
        b'[',  # 左方括号
        b']',  # 右方括号
        b'{',  # 左大括号
        b'}',  # 右大括号
        b';',  # 分号
        b':',  # 冒号
        b'\xff\xff\xff\xff',  # 最大整数（4字节）
        b'\x00\x00\x00\x00',  # 最小整数（4字节）
    ]

    special_char = random.choice(special_chars)
    # 在指定索引位置插入特殊字符
    result = bytearray()
    last_index = 0
    for index in indices:
        result.extend(data[last_index:index])
        result.extend(special_char)
        last_index = index
    result.extend(data[last_index:])
    return bytes(result)


def fuzz_modbus_tcp(data: bytes) -> bytes:
    # 随机选择变异方法应用
    mutations = [
        lambda x: randomize_bytes(x, random.randint(1, len(data)-1)),
        lambda x: modify_length(x, random.randint(-(len(data)-1), (len(data)-1))),
        lambda x: mutate_payload(x, random.randint(0, len(x) - 1)),
        lambda x: max_and_min(x, random.randint(0, len(x) - 1)),
        lambda x: copy_and_paste(x, random.randint(0, len(x) - 1), random.randint(0, len(x) - 1),
                                random.randint(0, len(x))),
        lambda x: flip_bytes(x, random.sample(range(len(x)), random.randint(1, len(x) // 2))),  #这个变异可能会导致
        lambda x: insert_special_characters(x, [random.randint(0, len(x) - 1)]),
    ]

    # 随机选择一到几个变异函数应用
    for _ in range(random.randint(1, len(mutations)-1)):
        mutation = random.choice(mutations)
        data = mutation(data)
    return data

# 随机选择一到多个变异方法进行变异
def fuzzer(fc_code):
    # 输入的 Modbus TCP 数据包（十六进制形式转换为字节）
    original_data = bytes.fromhex(fc_code)
    # 进行模糊测试
    mutated_data = fuzz_modbus_tcp(original_data)
    return mutated_data.hex()
#
# for i in range(0,10):
#     a = "01aacc0203ffee"
#     print(fuzzer(a))