@echo off
:loop
set TIMESTAMP=%date:~-4%-%date:~3,2%-%date:~0,2%_%time:~0,2%-%time:~3,2%
set TIMESTAMP=%TIMESTAMP: =0%
set BACKUP_PATH=C:\backups
set MYSQL_PATH=C:\xampp\mysql\bin
set DATABASE_NAME=ehr_system
set USERNAME=root
set PASSWORD=96329

if not exist %BACKUP_PATH% mkdir %BACKUP_PATH%
"%MYSQL_PATH%\mysqldump" -u %USERNAME% -p%PASSWORD% %DATABASE_NAME% > %BACKUP_PATH%\%DATABASE_NAME%_%TIMESTAMP%.sql

timeout /t 1 >nul
goto loop
