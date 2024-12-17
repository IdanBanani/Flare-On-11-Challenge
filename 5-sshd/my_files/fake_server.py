import socket
import struct

#FILE_PATH = '/root/certificate_authority_signing_key.txt'
#b'+\x00\x00\x00' # 0x2b

FILE_PATH = b'new.txt'

hex_data = (
    "0xda0e76eb1291ec8d"
    "0x351c2743a4877d7c"
    "0xd9b4938987cbe0d9"
    "0xd76621fa34f9ae04"
)

data_to_send = bytes([
    0x8d, 0xec, 0x91, 0x12, 0xeb, 0x76, 0x0e, 0xda,
    0x7c, 0x7d, 0x87, 0xa4, 0x43, 0x27, 0x1c, 0x35,
    0xd9, 0xe0, 0xcb, 0x87, 0x89, 0x93, 0xb4, 0xd9,
    0x04, 0xae, 0xf9, 0x34, 0xfa, 0x21, 0x66, 0xd7
])

# # Remove the "0x" prefixes and concatenate the hex string
# hex_data = hex_data.replace("0x", "")

# # Split the hex data into 64-bit (16 hex characters) chunks
# qwords = [hex_data[i:i+16] for i in range(0, len(hex_data), 16)]

# # Reverse the byte order of each QWORD
# reversed_qwords = [qword[i:i+2] for qword in qwords for i in range(0, len(qword), 2)]

# # Join the reversed bytes and convert to raw bytes
# key_a_32bytes = bytes.fromhex(''.join(reversed_qwords))


key_a_32bytes = data_to_send

print(key_a_32bytes)

key_b_12bytes = bytes([0x11] * 12) 

print(f'{key_a_32bytes=}')
print(f'{key_b_12bytes=}')


length_without_null = len(FILE_PATH)
print(f'{length_without_null=}')
filename_length_packed = struct.pack('<I', length_without_null) 

#encrypted content
# 26:0130│  0x7ffcc6600d18 ◂— 0x1c9e2a420834f6a9
# 27:0138│  0x7ffcc6600d20 ◂— 0x8dbb709408a8030c
# 28:0140│  0x7ffcc6600d28 ◂— 0x247fff247b6ddcaa
# 29:0148│  0x7ffcc6600d30 ◂— 0x1d07f7929e83da7c
# 2a:0150│  0x7ffcc6600d38 ◂— 0x58c12e906302
# search -t dword 0x28 stack
# Searching for value: b'(\x00\x00\x00'
# [stack]         0x7ffcc6600bd8 0x3000000028 /* '(' */
# [stack]         0x7ffcc6601198 0x3000000028 /* '(' */

# pwndbg> x/16gx 0x7ffcc6600d18
# 0x7ffcc6600d18: 0x1c9e2a420834f6a9      0x8dbb709408a8030c
# 0x7ffcc6600d28: 0x247fff247b6ddcaa      0x1d07f7929e83da7c
# 0x7ffcc6600d38: 0x000058c12e906302      0x000055b46d58b4d0
# 0x7ffcc6600d48: 0x00007f4a1978ea20      0x000055b46d58b4d0
# 0x7ffcc6600d58: 0x00007f4a1977d130      0x00007f4a1977cbf0
# 0x7ffcc6600d68: 0x00007f4a19012ae0      0x00007f4a19012000
# 0x7ffcc6600d78: 0x00007f4a197b0ad0      0x968070c64318f8ac
# 0x7ffcc6600d88: 0x97edcde9a64cf8ac      0x00007f4a00000000
# pwndbg> s

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

#TODO: fix, currently using this hack
# sudo ip addr add 10.0.2.15/24 dev eth0
# sudo ip link set dev eth0 up
server_socket.bind(('10.0.2.15', 1337))
server_socket.listen(1)
print("Fake server is listening on 10.0.2.15:1337...")
conn, addr = server_socket.accept()
print(f"Connection established with {addr}")

conn.send(key_a_32bytes)
conn.send(key_b_12bytes)
conn.send(filename_length_packed)
conn.send(FILE_PATH)

len_content = conn.recv(4)
len_content = struct.unpack('<I', len_content)[0] 
print(f"Received length of to be sent data: {len_content}")

decrypted_data = conn.recv(len_content)
print(f"Received second data: {decrypted_data}")

# Close the connection
conn.close()
server_socket.close()
