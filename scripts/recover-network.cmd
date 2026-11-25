@echo off
rem Экстренное отключение «Раздельный VPN» и возврат обычной сети: запускает recover-network.ps1. Права администратора
rem скрипт запрашивает сам и сообщает понятным текстом, если запрос отклонён (здесь не пишем кириллицу: cmd читает
rem файл в кодовой странице OEM).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0recover-network.ps1"
