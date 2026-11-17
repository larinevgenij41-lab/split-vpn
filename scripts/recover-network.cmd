@echo off
rem Аварийное восстановление сети «Раздельный VPN»: запрашивает повышение и запускает recover-network.ps1.
rem Путь берётся в кавычки: Start-Process в Windows PowerShell 5.1 не экранирует элементы -ArgumentList, а установка лежит в «Program Files».
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File \"{0}\"' -f '%~dp0recover-network.ps1')"
