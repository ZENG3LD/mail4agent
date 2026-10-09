# Windows: run m4a-web-client at logon, restart on failure (Scheduled Task, current user).
# Run in PowerShell:  .\install-windows.ps1 -Exe "$env:USERPROFILE\.local\bin\m4a-web-client.exe"
# Settings come from %USERPROFILE%\.config\mail4agent\web-client.env (no secrets here).
param([Parameter(Mandatory=$true)][string]$Exe)
$action  = New-ScheduledTaskAction -Execute $Exe
$trigger = New-ScheduledTaskTrigger -AtLogOn
$set     = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "mail4agent-web-client" -Action $action -Trigger $trigger -Settings $set -Force
Start-ScheduledTask -TaskName "mail4agent-web-client"
