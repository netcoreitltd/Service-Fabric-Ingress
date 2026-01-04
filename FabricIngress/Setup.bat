netsh http add urlacl url=https://+:443/ user="NT AUTHORITY\NETWORK SERVICE"
netsh http add urlacl url=http://+:80/ user="NT AUTHORITY\NETWORK SERVICE"
exit /b 0