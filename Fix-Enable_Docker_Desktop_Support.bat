@echo off

dism /Online /Disable-Feature:microsoft-hyper-v-all /NoRestart
dism /Online /Enable-Feature:VirtualMachinePlatform /NoRestart
dism /Online /Enable-Feature:HypervisorPlatform /NoRestart

bcdedit /set hypervisorlaunchtype auto

echo.
echo.
echo.
echo.
echo 可以关闭此窗口了，请重新启动您的计算机。
pause > nul
echo.
echo.