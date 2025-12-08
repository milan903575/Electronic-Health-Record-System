@echo off
:: Set the path where backups are stored
set BACKUP_PATH=C:\backups

:: Call PowerShell to find and delete files older than 3 minutes
powershell -Command "Get-ChildItem -Path '%BACKUP_PATH%' -Filter '*.sql' | Where-Object { (Get-Date) - $_.LastWriteTime -gt (New-TimeSpan -Minutes 3) } | Remove-Item -Force"

echo Cleanup completed at %date% %time%.
