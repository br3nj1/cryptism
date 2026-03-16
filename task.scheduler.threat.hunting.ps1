PowerShell Threat-Hunting Script (Local System)
# ============================================
# Local Scheduled Task Threat Hunting Script
# SOC / IR Investigation Tool
# ============================================
Write-Host "Enumerating scheduled tasks..." -ForegroundColor Cyan
$suspiciousExecutables = @(
"powershell.exe",
"cmd.exe",
"wscript.exe",
"cscript.exe",
"mshta.exe",
"rundll32.exe",
"regsvr32.exe",
"bitsadmin.exe",
"certutil.exe"
)
$suspiciousPaths = @(
"\appdata\",
"\temp\",
"\public\",
"\downloads\",
"\programdata\"
)
$results = @()
$tasks = Get-ScheduledTask
foreach ($task in $tasks) {
$taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
foreach ($action in $task.Actions) {
$reason = @()
$exec = $action.Execute
        $args = $action.Arguments
        $runAs = $task.Principal.UserId
# Suspicious executables
        foreach ($exe in $suspiciousExecutables) {
if ($exec -match $exe) {
                $reason += "Suspicious executable: $exe"
            }
}
# Suspicious paths
        foreach ($path in $suspiciousPaths) {
if ($args -match $path -or $exec -match $path) {
                $reason += "Execution from suspicious path: $path"
            }
}
# Encoded PowerShell
        if ($args -match "EncodedCommand|-enc") {
            $reason += "Encoded PowerShell detected"
        }
# SYSTEM outside Microsoft namespace
        if ($runAs -eq "SYSTEM" -and $task.TaskPath -notlike "\Microsoft\*") {
            $reason += "Runs as SYSTEM outside Microsoft namespace"
        }
# High frequency triggers
        foreach ($trigger in $task.Triggers) {
if ($trigger.Repetition.Interval -match "PT1M|PT5M") {
                $reason += "High frequency trigger (1-5 minutes)"
            }
}
# Suspicious task path
        if ($task.TaskPath -notlike "\Microsoft\*") {
            $reason += "Non-Microsoft task namespace"
        }
if ($reason.Count -gt 0) {
$results += [PSCustomObject]@{
TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                State = $task.State
                RunAsUser = $runAs
                Execute = $exec
                Arguments = $args
                LastRunTime = $taskInfo.LastRunTime
                NextRunTime = $taskInfo.NextRunTime
                Reason = ($reason -join "; ")
}
}
}
}
if ($results.Count -eq 0) {
Write-Host "No suspicious tasks detected." -ForegroundColor Green
} else {
Write-Host "Suspicious tasks detected:" -ForegroundColor Yellow
$results | Format-Table -AutoSize
$outfile = "$env:USERPROFILE\Desktop\suspicious_scheduled_tasks.csv"
$results | Export-Csv $outfile -NoTypeInformation
Write-Host ""
    Write-Host "Results exported to: $outfile" -ForegroundColor Cyan
}








===========================================================================
===========================================================================
===========================================================================

REMOTE PC VERSION | HOSTS.TXT INPUT FILE

===========================================================================






Network Threat Hunting Script
# ==============================================
# Scheduled Task Threat Hunting Script
# Detects suspicious persistence across systems
# ==============================================
$computers = Get-Content "C:\temp\hosts.txt"
$suspiciousExecutables = @(
"powershell.exe",
"cmd.exe",
"wscript.exe",
"cscript.exe",
"mshta.exe",
"rundll32.exe",
"regsvr32.exe",
"bitsadmin.exe",
"certutil.exe"
)
$suspiciousPaths = @(
"\appdata\",
"\temp\",
"\public\",
"\downloads\"
)
$results = @()
foreach ($computer in $computers) {
Write-Host "Scanning $computer"
try {
$tasks = Invoke-Command -ComputerName $computer -ScriptBlock {
Get-ScheduledTask | ForEach-Object {
$info = $_
                $actions = $_.Actions
foreach ($action in $actions) {
[PSCustomObject]@{
Computer = $env:COMPUTERNAME
                        TaskName = $info.TaskName
                        TaskPath = $info.TaskPath
                        State = $info.State
                        Author = $info.Author
                        RunAsUser = $info.Principal.UserId
                        Execute = $action.Execute
                        Arguments = $action.Arguments
}
}
}
}
foreach ($task in $tasks) {
$flag = $false
            $reason = ""
# Check suspicious executables
            foreach ($exe in $suspiciousExecutables) {
if ($task.Execute -like "*$exe*") {
$flag = $true
                    $reason += "Suspicious executable: $exe; "
}
}
# Check suspicious paths
            foreach ($path in $suspiciousPaths) {
if ($task.Arguments -like "*$path*") {
$flag = $true
                    $reason += "Suspicious path: $path; "
}
}
# Detect encoded PowerShell
            if ($task.Arguments -match "EncodedCommand|-enc") {
$flag = $true
                $reason += "Encoded PowerShell detected; "
}
# SYSTEM execution outside Microsoft tasks
            if ($task.RunAsUser -eq "SYSTEM" -and $task.TaskPath -notlike "\Microsoft\*") {
$flag = $true
                $reason += "SYSTEM execution outside Microsoft namespace; "
}
if ($flag) {
$results += [PSCustomObject]@{
Computer = $task.Computer
                    TaskName = $task.TaskName
                    TaskPath = $task.TaskPath
                    RunAsUser = $task.RunAsUser
                    Execute = $task.Execute
                    Arguments = $task.Arguments
                    Reason = $reason
}
}
}
}
catch {
Write-Warning "Failed to scan $computer"
}
}
$results | Export-Csv "C:\temp\suspicious_tasks.csv" -NoTypeInformation
Write-Host "Scan complete. Results saved to suspicious_tasks.csv"




================================================================
3. hosts.txt Example
SERVER01
SERVER02
WORKSTATION15
WORKSTATION27

=====================


Running the Script Safely
Requirements:
WinRM enabled
Local admin rights
Remote PowerShell enabled
Test connectivity first:
Test-WSMan SERVER01




Enterprise Variant (Much Faster)
Instead of remote PowerShell, you can use CIM sessions.
Example:
Get-ScheduledTask -CimSession SERVER01
This scales better for hundreds of systems.



recommended Additional Hunt
Add a search for tasks created recently:
Get-ScheduledTask | Get-ScheduledTaskInfo
Look for:
	• recent creation time
	• unexpected trigger times
	• very frequent triggers
Example malicious trigger:
Every 1 minute
At user logon
At system startup


 Forensic Deep Inspection
Pull full task XML definition:
Export-ScheduledTask -TaskName "TaskName"
Tasks often contain:
	• hidden payload
	• obfuscated PowerShell
remote download commands









