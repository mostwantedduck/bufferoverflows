runas /user:WIN10-64-VM\Daniel /savecred "taskkill /IM fsws.exe /F"
runas /user:WIN10-64-VM\Daniel /savecred "cscript \"C:\Users\Daniel\Desktop\launch_easy_file_sharing.vbs\""
timeout 2
runas /user:WIN10-64-VM\Daniel /savecred "\"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe\" -g -pn fsws.exe"

