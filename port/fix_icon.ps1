$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut("$env:USERPROFILE\Desktop\StockFW.lnk")
$sc.IconLocation = "C:\Users\H3xCore\StockFW\port\installer\nsis\resources\stockfw_icon.ico,0"
$sc.Save()
