Set x = CreateObject("Wscript.Shell")
x.run """C:\EFS Software\Easy File Sharing Web Server\fsws.exe"""
Wscript.Sleep(300)
x.SendKeys("{TAB}")
x.SendKeys("{TAB}")
x.SendKeys("{TAB}")
x.SendKeys("{ENTER}")
Wscript.Sleep(200)
x.SendKeys("{ENTER}")
