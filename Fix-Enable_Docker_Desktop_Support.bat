@echo off

dism /Online /Disable-Feature:microsoft-hyper-v-all /NoRestart
dism /Online /Enable-Feature:VirtualMachinePlatform /NoRestart
dism /Online /Enable-Feature:HypervisorPlatform /NoRestart

bcdedit /set hypervisorlaunchtype auto

echo.
echo.
echo.
echo.
echo ���Թرմ˴����ˣ��������������ļ������
pause > nul
echo.
echo.