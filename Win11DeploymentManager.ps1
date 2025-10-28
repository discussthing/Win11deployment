# Windows 11 Deployment Manager with Multi-Battery Support
# Features: Multi-battery detection, adjustable thresholds, force install override, 7-day history
# Requires: SCCM/ConfigMgr Software Center, WinRM enabled on target machines
# Version: 2.0

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#region Configuration
$script:PackageID = "WIN001234"  # CHANGE THIS: Your SCCM Package/TS ID
$script:DeploymentType = "TaskSequence"  # Options: "TaskSequence", "Package", "Application"
$script:BatteryThreshold = 75
$script:DefaultCheckInterval = 10  # Default minutes between checks
$script:LogPath = "C:\IT\Logs\Win11Deployment"
$script:HistoryDays = 7
#endregion

#region Error Code Dictionary
$script:ErrorDictionary = @{
    # Scheduled Task Error Codes
    '0x0' = 'Success - Task completed successfully'
    '0x1' = 'Incorrect function called or unknown error'
    '0x2' = 'File not found - Script or executable missing'
    '0xa' = 'Environment is incorrect - Check PowerShell version'
    '0x41300' = 'Task is currently running'
    '0x41301' = 'Task is disabled'
    '0x41302' = 'Task has not yet run'
    '0x41303' = 'No more scheduled runs'
    '0x41304' = 'Properties are not set correctly'
    '0x41306' = 'Task terminated by user'
    '0x8004130F' = 'Credentials became corrupted'
    '0x8004131F' = 'Instance of this task is already running'
    '0x800710E0' = 'Operator or administrator refused the request'
    
    # SCCM/ConfigMgr Error Codes
    '0x87D00324' = 'SCCM: Application not found in Software Center'
    '0x87D00321' = 'SCCM: Application is not available'
    '0x87D00607' = 'SCCM: User cancelled the installation'
    '0x87D00668' = 'SCCM: Content not available - check Distribution Points'
    '0x87D00269' = 'SCCM: Application already installed'
    '0x87D01106' = 'SCCM: Deployment type requirements not met'
    '0x80004005' = 'Unspecified error - Check SCCM logs'
}

function Get-HumanReadableError {
    param([string]$ErrorCode, [string]$RawError)
    
    if ([string]::IsNullOrWhiteSpace($ErrorCode)) { return "Unknown error" }
    
    if ($script:ErrorDictionary.ContainsKey($ErrorCode)) {
        return $script:ErrorDictionary[$ErrorCode]
    }
    
    $hexCode = "0x$($ErrorCode.TrimStart('0x'))"
    if ($script:ErrorDictionary.ContainsKey($hexCode)) {
        return $script:ErrorDictionary[$hexCode]
    }
    
    if ($RawError -match "access.*denied") { return "Access denied - check admin rights" }
    if ($RawError -match "timeout") { return "Connection timeout - check network" }
    if ($RawError -match "not found") { return "Resource not found - verify configuration" }
    if ($RawError -match "already.*running") { return "Task already in progress" }
    
    return "Error Code: $ErrorCode - Check logs for details"
}
#endregion

#region Logging Functions
function Write-DeploymentLog {
    param([string]$Message, [string]$ComputerName, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path $LogPath "Deployment_$(Get-Date -Format 'yyyyMMdd').log"
    
    if (!(Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
    
    $logMessage = "[$timestamp] [$Level] [$ComputerName] $Message"
    Add-Content -Path $logFile -Value $logMessage
    
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
        default { Write-Host $logMessage -ForegroundColor Gray }
    }
}
#endregion

#region Connection Functions
function Test-ComputerConnection {
    param(
        [string]$ComputerName,
        [ref]$ConnectionMethod
    )
    
    # Try methods in order: WinRM -> CIM -> WMI -> PSExec
    $methods = @('WinRM', 'CIM', 'WMI', 'PSExec')
    
    foreach ($method in $methods) {
        switch ($method) {
            'WinRM' {
                if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet) {
                    try {
                        $null = Invoke-Command -ComputerName $ComputerName -ScriptBlock { $true } -ErrorAction Stop
                        $ConnectionMethod.Value = 'WinRM'
                        Write-DeploymentLog -Message "Connected via WinRM" -ComputerName $ComputerName
                        return $true
                    } catch {
                        Write-DeploymentLog -Message "WinRM failed: $($_.Exception.Message)" -ComputerName $ComputerName -Level "WARN"
                    }
                }
            }
            'CIM' {
                try {
                    $session = New-CimSession -ComputerName $ComputerName -ErrorAction Stop -OperationTimeoutSec 10
                    $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -ErrorAction Stop -OperationTimeoutSec 5
                    Remove-CimSession -CimSession $session
                    $ConnectionMethod.Value = 'CIM'
                    Write-DeploymentLog -Message "Connected via CIM" -ComputerName $ComputerName
                    return $true
                } catch {
                    Write-DeploymentLog -Message "CIM failed: $($_.Exception.Message)" -ComputerName $ComputerName -Level "WARN"
                }
            }
            'WMI' {
                try {
                    $os = Get-WmiObject -ComputerName $ComputerName -Class Win32_OperatingSystem -ErrorAction Stop
                    $ConnectionMethod.Value = 'WMI'
                    Write-DeploymentLog -Message "Connected via WMI" -ComputerName $ComputerName
                    return $true
                } catch {
                    Write-DeploymentLog -Message "WMI failed: $($_.Exception.Message)" -ComputerName $ComputerName -Level "WARN"
                }
            }
            'PSExec' {
                if (Test-Path "C:\temp\sysinternal\PsExec.exe") {
                    try {
                        $result = & "C:\temp\sysinternal\PsExec.exe" -accepteula "\\$ComputerName" cmd /c "echo test" 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            $ConnectionMethod.Value = 'PSExec'
                            Write-DeploymentLog -Message "Connected via PSExec" -ComputerName $ComputerName
                            return $true
                        } else {
                            Write-DeploymentLog -Message "PSExec failed with exit code: $LASTEXITCODE" -ComputerName $ComputerName -Level "WARN"
                        }
                    } catch {
                        Write-DeploymentLog -Message "PSExec failed: $($_.Exception.Message)" -ComputerName $ComputerName -Level "WARN"
                    }
                } else {
                    Write-DeploymentLog -Message "PSExec not found at C:\temp\sysinternal\PsExec.exe" -ComputerName $ComputerName -Level "WARN"
                }
            }
        }
    }
    
    Write-DeploymentLog -Message "All connection methods failed" -ComputerName $ComputerName -Level "ERROR"
    $ConnectionMethod.Value = 'None'
    return $false
}
#endregion

#region Battery Functions
function Get-BatteryStatus {
    param(
        [string]$ComputerName,
        [string]$ConnectionMethod = 'WinRM'
    )
    
    try {
        switch ($ConnectionMethod) {
            'WinRM' {
                $batteryInfo = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    $batteries = @(Get-WmiObject -Class Win32_Battery -ErrorAction SilentlyContinue)
                    
                    if ($batteries.Count -gt 0) {
                        $batteryDetails = @()
                        $totalCharge = 0
                        $anyCharging = $false
                        
                        foreach ($battery in $batteries) {
                            $isCharging = ($battery.BatteryStatus -eq 2 -or $battery.BatteryStatus -eq 6 -or $battery.BatteryStatus -eq 7 -or $battery.BatteryStatus -eq 8)
                            if ($isCharging) { $anyCharging = $true }
                            
                            $batteryDetails += [PSCustomObject]@{
                                Name = if ($battery.Name) { $battery.Name } else { "Battery $($battery.DeviceID)" }
                                DeviceID = $battery.DeviceID
                                ChargeLevel = $battery.EstimatedChargeRemaining
                                IsCharging = $isCharging
                                BatteryStatus = switch ($battery.BatteryStatus) {
                                    1 { "Discharging" }
                                    2 { "AC Power/Charging" }
                                    3 { "Fully Charged" }
                                    4 { "Low" }
                                    5 { "Critical" }
                                    default { "Status $($battery.BatteryStatus)" }
                                }
                                Chemistry = switch ($battery.Chemistry) {
                                    6 { "Lithium-ion" }
                                    8 { "Lithium Polymer" }
                                    default { "Battery" }
                                }
                                EstimatedRunTime = $battery.EstimatedRunTime
                                TimeToFullCharge = $battery.TimeToFullCharge
                            }
                            
                            $totalCharge += $battery.EstimatedChargeRemaining
                        }
                        
                        $avgCharge = [math]::Round($totalCharge / $batteries.Count, 1)
                        $minCharge = ($batteryDetails | Measure-Object -Property ChargeLevel -Minimum).Minimum
                        $maxCharge = ($batteryDetails | Measure-Object -Property ChargeLevel -Maximum).Maximum
                        
                        [PSCustomObject]@{
                            HasBattery = $true
                            BatteryCount = $batteries.Count
                            AverageChargeLevel = $avgCharge
                            MinimumChargeLevel = $minCharge
                            MaximumChargeLevel = $maxCharge
                            IsCharging = $anyCharging
                            AllCharging = $false
                            Batteries = $batteryDetails
                            WindowsReportedCharge = $batteries[0].EstimatedChargeRemaining
                        }
                    } else {
                        [PSCustomObject]@{
                            HasBattery = $false
                            BatteryCount = 0
                            AverageChargeLevel = 100
                            MinimumChargeLevel = 100
                            MaximumChargeLevel = 100
                            IsCharging = $false
                            AllCharging = $false
                            Batteries = @()
                            WindowsReportedCharge = 100
                        }
                    }
                } -ErrorAction Stop
            }
            'CIM' {
                $session = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
                $batteries = @(Get-CimInstance -CimSession $session -ClassName Win32_Battery -ErrorAction SilentlyContinue)
                
                if ($batteries.Count -gt 0) {
                    $batteryDetails = @()
                    $totalCharge = 0
                    $anyCharging = $false
                    
                    foreach ($battery in $batteries) {
                        $isCharging = ($battery.BatteryStatus -eq 2 -or $battery.BatteryStatus -eq 6 -or $battery.BatteryStatus -eq 7 -or $battery.BatteryStatus -eq 8)
                        if ($isCharging) { $anyCharging = $true }
                        
                        $batteryDetails += [PSCustomObject]@{
                            Name = if ($battery.Name) { $battery.Name } else { "Battery $($battery.DeviceID)" }
                            DeviceID = $battery.DeviceID
                            ChargeLevel = $battery.EstimatedChargeRemaining
                            IsCharging = $isCharging
                        }
                        $totalCharge += $battery.EstimatedChargeRemaining
                    }
                    
                    Remove-CimSession -CimSession $session
                    
                    $batteryInfo = [PSCustomObject]@{
                        HasBattery = $true
                        BatteryCount = $batteries.Count
                        AverageChargeLevel = [math]::Round($totalCharge / $batteries.Count, 1)
                        MinimumChargeLevel = ($batteryDetails | Measure-Object -Property ChargeLevel -Minimum).Minimum
                        MaximumChargeLevel = ($batteryDetails | Measure-Object -Property ChargeLevel -Maximum).Maximum
                        IsCharging = $anyCharging
                        AllCharging = $false
                        Batteries = $batteryDetails
                        WindowsReportedCharge = $batteries[0].EstimatedChargeRemaining
                    }
                } else {
                    Remove-CimSession -CimSession $session
                    $batteryInfo = [PSCustomObject]@{
                        HasBattery = $false
                        BatteryCount = 0
                        AverageChargeLevel = 100
                        MinimumChargeLevel = 100
                        MaximumChargeLevel = 100
                        IsCharging = $false
                        AllCharging = $false
                        Batteries = @()
                        WindowsReportedCharge = 100
                    }
                }
            }
            'WMI' {
                $batteries = @(Get-WmiObject -ComputerName $ComputerName -Class Win32_Battery -ErrorAction SilentlyContinue)
                
                if ($batteries.Count -gt 0) {
                    $batteryDetails = @()
                    $totalCharge = 0
                    $anyCharging = $false
                    
                    foreach ($battery in $batteries) {
                        $isCharging = ($battery.BatteryStatus -eq 2 -or $battery.BatteryStatus -eq 6 -or $battery.BatteryStatus -eq 7 -or $battery.BatteryStatus -eq 8)
                        if ($isCharging) { $anyCharging = $true }
                        
                        $batteryDetails += [PSCustomObject]@{
                            Name = if ($battery.Name) { $battery.Name } else { "Battery $($battery.DeviceID)" }
                            DeviceID = $battery.DeviceID
                            ChargeLevel = $battery.EstimatedChargeRemaining
                            IsCharging = $isCharging
                        }
                        $totalCharge += $battery.EstimatedChargeRemaining
                    }
                    
                    $batteryInfo = [PSCustomObject]@{
                        HasBattery = $true
                        BatteryCount = $batteries.Count
                        AverageChargeLevel = [math]::Round($totalCharge / $batteries.Count, 1)
                        MinimumChargeLevel = ($batteryDetails | Measure-Object -Property ChargeLevel -Minimum).Minimum
                        MaximumChargeLevel = ($batteryDetails | Measure-Object -Property ChargeLevel -Maximum).Maximum
                        IsCharging = $anyCharging
                        AllCharging = $false
                        Batteries = $batteryDetails
                        WindowsReportedCharge = $batteries[0].EstimatedChargeRemaining
                    }
                } else {
                    $batteryInfo = [PSCustomObject]@{
                        HasBattery = $false
                        BatteryCount = 0
                        AverageChargeLevel = 100
                        MinimumChargeLevel = 100
                        MaximumChargeLevel = 100
                        IsCharging = $false
                        AllCharging = $false
                        Batteries = @()
                        WindowsReportedCharge = 100
                    }
                }
            }
            'PSExec' {
                # PSExec cannot easily query battery info, fallback to WMI
                Write-DeploymentLog -Message "Using WMI for battery status (PSExec connection)" -ComputerName $ComputerName
                $batteries = @(Get-WmiObject -ComputerName $ComputerName -Class Win32_Battery -ErrorAction SilentlyContinue)
                
                if ($batteries.Count -gt 0) {
                    $batteryInfo = [PSCustomObject]@{
                        HasBattery = $true
                        BatteryCount = $batteries.Count
                        AverageChargeLevel = $batteries[0].EstimatedChargeRemaining
                        MinimumChargeLevel = $batteries[0].EstimatedChargeRemaining
                        MaximumChargeLevel = $batteries[0].EstimatedChargeRemaining
                        IsCharging = ($batteries[0].BatteryStatus -eq 2)
                        AllCharging = $false
                        Batteries = @()
                        WindowsReportedCharge = $batteries[0].EstimatedChargeRemaining
                    }
                } else {
                    $batteryInfo = [PSCustomObject]@{
                        HasBattery = $false
                        BatteryCount = 0
                        AverageChargeLevel = 100
                        MinimumChargeLevel = 100
                        MaximumChargeLevel = 100
                        IsCharging = $false
                        AllCharging = $false
                        Batteries = @()
                        WindowsReportedCharge = 100
                    }
                }
            }
        }
        
        return $batteryInfo
    } catch {
        Write-DeploymentLog -Message "Failed to get battery status via $ConnectionMethod : $($_.Exception.Message)" -ComputerName $ComputerName -Level "ERROR"
        return $null
    }
}

function Show-BatteryDetails {
    param(
        [string]$ComputerName,
        [object]$BatteryInfo
    )
    
    $detailForm = New-Object System.Windows.Forms.Form
    $detailForm.Text = "Battery Details: $ComputerName"
    $detailForm.Size = New-Object System.Drawing.Size(700, 500)
    $detailForm.StartPosition = "CenterScreen"
    
    $detailText = New-Object System.Text.StringBuilder
    [void]$detailText.AppendLine("=" * 70)
    [void]$detailText.AppendLine("MULTI-BATTERY SYSTEM ANALYSIS")
    [void]$detailText.AppendLine("=" * 70)
    [void]$detailText.AppendLine("")
    [void]$detailText.AppendLine("Computer: $ComputerName")
    [void]$detailText.AppendLine("Total Batteries Detected: $($BatteryInfo.BatteryCount)")
    [void]$detailText.AppendLine("")
    
    if ($BatteryInfo.BatteryCount -gt 0) {
        [void]$detailText.AppendLine("SUMMARY:")
        [void]$detailText.AppendLine("  Average Charge: $($BatteryInfo.AverageChargeLevel)%")
        [void]$detailText.AppendLine("  Minimum Charge: $($BatteryInfo.MinimumChargeLevel)%")
        [void]$detailText.AppendLine("  Maximum Charge: $($BatteryInfo.MaximumChargeLevel)%")
        [void]$detailText.AppendLine("  Windows Reports: $($BatteryInfo.WindowsReportedCharge)%")
        [void]$detailText.AppendLine("  Any Charging: $($BatteryInfo.IsCharging)")
        [void]$detailText.AppendLine("  All Charging: $($BatteryInfo.AllCharging)")
        [void]$detailText.AppendLine("")
        
        $variance = $BatteryInfo.MaximumChargeLevel - $BatteryInfo.MinimumChargeLevel
        [void]$detailText.AppendLine("VARIANCE ANALYSIS:")
        [void]$detailText.AppendLine("  Battery Variance: $variance%")
        
        if ($variance -gt 30) {
            [void]$detailText.AppendLine("  Status: HIGH VARIANCE DETECTED")
            [void]$detailText.AppendLine("  Impact: Windows may report lower charge than actual capacity")
            [void]$detailText.AppendLine("  Recommendation: Use MAX battery level for deployment decisions")
        } elseif ($variance -gt 15) {
            [void]$detailText.AppendLine("  Status: MODERATE VARIANCE")
            [void]$detailText.AppendLine("  Recommendation: Monitor battery balance")
        } else {
            [void]$detailText.AppendLine("  Status: BATTERIES BALANCED")
            [void]$detailText.AppendLine("  Recommendation: Use average charge level")
        }
        
        [void]$detailText.AppendLine("")
        [void]$detailText.AppendLine("=" * 70)
        [void]$detailText.AppendLine("INDIVIDUAL BATTERY DETAILS")
        [void]$detailText.AppendLine("=" * 70)
        [void]$detailText.AppendLine("")
        
        $batteryNum = 1
        foreach ($battery in $BatteryInfo.Batteries) {
            [void]$detailText.AppendLine("BATTERY #$batteryNum")
            [void]$detailText.AppendLine("  Name: $($battery.Name)")
            [void]$detailText.AppendLine("  Device ID: $($battery.DeviceID)")
            [void]$detailText.AppendLine("  Charge Level: $($battery.ChargeLevel)%")
            [void]$detailText.AppendLine("  Status: $($battery.BatteryStatus)")
            [void]$detailText.AppendLine("  Charging: $($battery.IsCharging)")
            [void]$detailText.AppendLine("  Chemistry: $($battery.Chemistry)")
            
            if ($battery.EstimatedRunTime -and $battery.EstimatedRunTime -ne 71582788) {
                $runTimeHours = [math]::Round($battery.EstimatedRunTime / 60, 1)
                [void]$detailText.AppendLine("  Estimated Runtime: $runTimeHours hours")
            }
            
            if ($battery.TimeToFullCharge -and $battery.TimeToFullCharge -ne 71582788) {
                $chargeTimeHours = [math]::Round($battery.TimeToFullCharge / 60, 1)
                [void]$detailText.AppendLine("  Time to Full Charge: $chargeTimeHours hours")
            }
            
            [void]$detailText.AppendLine("")
            $batteryNum++
        }
        
        [void]$detailText.AppendLine("=" * 70)
        [void]$detailText.AppendLine("DEPLOYMENT RECOMMENDATION")
        [void]$detailText.AppendLine("=" * 70)
        [void]$detailText.AppendLine("")
        
        $effectiveCharge = if ($variance -gt 30) { $BatteryInfo.MaximumChargeLevel } else { $BatteryInfo.AverageChargeLevel }
        [void]$detailText.AppendLine("  Effective Charge for Deployment: $effectiveCharge%")
        [void]$detailText.AppendLine("  Current Threshold Setting: $($script:BatteryThreshold)%")
        
        if ($effectiveCharge -ge $script:BatteryThreshold) {
            [void]$detailText.AppendLine("  READY FOR DEPLOYMENT")
        } else {
            [void]$detailText.AppendLine("  BELOW THRESHOLD (Need $($script:BatteryThreshold - $effectiveCharge)% more)")
            if ($BatteryInfo.IsCharging) {
                [void]$detailText.AppendLine("  Status: Charging in progress...")
            }
        }
    } else {
        [void]$detailText.AppendLine("No batteries detected - This is a desktop system")
        [void]$detailText.AppendLine("Desktop systems can proceed with deployment immediately")
    }
    
    $textBox = New-Object System.Windows.Forms.RichTextBox
    $textBox.Location = New-Object System.Drawing.Point(10, 10)
    $textBox.Size = New-Object System.Drawing.Size(660, 400)
    $textBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $textBox.ReadOnly = $true
    $textBox.WordWrap = $true
    $textBox.Text = $detailText.ToString()
    
    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Location = New-Object System.Drawing.Point(590, 420)
    $closeButton.Size = New-Object System.Drawing.Size(80, 30)
    $closeButton.Text = "Close"
    $closeButton.Add_Click({ $detailForm.Close() })
    
    $detailForm.Controls.Add($textBox)
    $detailForm.Controls.Add($closeButton)
    
    [void]$detailForm.ShowDialog()
}
#endregion

#region Task History Functions
function Get-TaskHistory {
    param([string]$ComputerName, [int]$Days = 7)
    
    try {
        $history = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($taskName, $days)
            
            $startTime = (Get-Date).AddDays(-$days)
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            
            if (!$task) {
                return @{ Success = $false; Message = "Task not found"; Events = @() }
            }
            
            $events = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-TaskScheduler/Operational'
                StartTime = $startTime
            } -ErrorAction SilentlyContinue | Where-Object {
                $_.Message -like "*$taskName*"
            } | Select-Object TimeCreated, Id, LevelDisplayName, Message -First 50
            
            $eventsSummary = $events | ForEach-Object {
                [PSCustomObject]@{
                    Time = $_.TimeCreated
                    EventID = $_.Id
                    Level = $_.LevelDisplayName
                    Message = $_.Message -replace "`n", " " -replace "`r", ""
                }
            }
            
            return @{ Success = $true; Events = $eventsSummary; EventCount = $events.Count }
        } -ArgumentList 'MonitorBatteryForWin11Upgrade', $Days -ErrorAction Stop
        
        return $history
    } catch {
        Write-DeploymentLog -Message "Failed to retrieve task history: $($_.Exception.Message)" -ComputerName $ComputerName -Level "ERROR"
        return @{ Success = $false; Message = $_.Exception.Message; Events = @() }
    }
}

function Get-DeploymentLogs {
    param([string]$ComputerName, [int]$Days = 7)
    
    try {
        $logs = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($logPath, $days)
            
            $results = @()
            $startDate = (Get-Date).AddDays(-$days)
            
            $autoDeployLog = Join-Path $logPath "AutoDeploy.log"
            if (Test-Path $autoDeployLog) {
                $content = Get-Content $autoDeployLog -Tail 100 | Where-Object {
                    if ($_ -match '^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]') {
                        $logDate = [DateTime]::ParseExact($matches[1], 'yyyy-MM-dd HH:mm:ss', $null)
                        $logDate -ge $startDate
                    }
                }
                $results += $content
            }
            
            $errorLog = Join-Path $logPath "AutoDeploy_Error.log"
            if (Test-Path $errorLog) {
                $content = Get-Content $errorLog -Tail 100 | Where-Object {
                    if ($_ -match '^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]') {
                        $logDate = [DateTime]::ParseExact($matches[1], 'yyyy-MM-dd HH:mm:ss', $null)
                        $logDate -ge $startDate
                    }
                }
                $results += $content
            }
            
            return $results
        } -ArgumentList $LogPath, $Days -ErrorAction Stop
        
        return $logs
    } catch {
        Write-DeploymentLog -Message "Failed to retrieve deployment logs: $($_.Exception.Message)" -ComputerName $ComputerName -Level "ERROR"
        return @()
    }
}
#endregion

#region Task Management Functions
function Get-MonitoringTaskStatus {
    param([string]$ComputerName)
    
    try {
        $taskInfo = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $task = Get-ScheduledTask -TaskName 'MonitorBatteryForWin11Upgrade' -ErrorAction SilentlyContinue
            
            if ($task) {
                $taskInfo = Get-ScheduledTaskInfo -TaskName 'MonitorBatteryForWin11Upgrade' -ErrorAction SilentlyContinue
                
                $trigger = $task.Triggers[0]
                $intervalMinutes = $null
                if ($trigger.Repetition) {
                    $interval = $trigger.Repetition.Interval
                    if ($interval -match 'PT(\d+)M') {
                        $intervalMinutes = [int]$matches[1]
                    } elseif ($interval -match 'PT(\d+)H') {
                        $intervalMinutes = [int]$matches[1] * 60
                    }
                }
                
                # Try to extract threshold from task description or action
                $thresholdValue = $null
                $forceInstallEnabled = $false
                
                if ($task.Actions[0].Arguments -match 'batteryThreshold\s*=\s*(\d+)') {
                    $thresholdValue = [int]$matches[1]
                }
                
                if ($task.Actions[0].Arguments -match 'forceInstall\s*=\s*\$true') {
                    $forceInstallEnabled = $true
                }
                
                [PSCustomObject]@{
                    Exists = $true
                    State = $task.State
                    Enabled = ($task.State -ne 'Disabled')
                    LastRunTime = $taskInfo.LastRunTime
                    LastResult = $taskInfo.LastTaskResult
                    NextRunTime = $taskInfo.NextRunTime
                    CheckIntervalMinutes = $intervalMinutes
                    BatteryThreshold = $thresholdValue
                    ForceInstallEnabled = $forceInstallEnabled
                    LastResultHex = "0x{0:X}" -f $taskInfo.LastTaskResult
                }
            } else {
                [PSCustomObject]@{
                    Exists = $false
                    State = 'Not Found'
                    Enabled = $false
                    LastRunTime = $null
                    LastResult = $null
                    NextRunTime = $null
                    CheckIntervalMinutes = $null
                    BatteryThreshold = $null
                    ForceInstallEnabled = $false
                    LastResultHex = $null
                }
            }
        } -ErrorAction Stop
        
        return $taskInfo
    } catch {
        Write-DeploymentLog -Message "Failed to get monitoring task status: $($_.Exception.Message)" -ComputerName $ComputerName -Level "ERROR"
        return $null
    }
}

function New-MonitoringTask {
    param(
        [string]$ComputerName,
        [int]$CheckIntervalMinutes,
        [int]$BatteryThresholdOverride = 0,
        [bool]$ForceInstall = $false
    )
    
    $effectiveThreshold = if ($BatteryThresholdOverride -gt 0) { $BatteryThresholdOverride } else { $script:BatteryThreshold }
    
    $deploymentScript = switch ($script:DeploymentType) {
        "TaskSequence" {
@"
        `$softwareCenter = New-Object -ComObject UIResource.UIResourceMgr
        `$availablePrograms = `$softwareCenter.GetAvailableApplications()
        
        # Try exact Package ID match first
        `$targetDeployment = `$availablePrograms | Where-Object { `$_.PackageID -eq '`$packageID' }
        
        # If not found by ID, try name search
        if (-not `$targetDeployment) {
            `$targetDeployment = `$availablePrograms | Where-Object { 
                `$_.Name -like "*`$packageID*" -or 
                `$_.PackageID -like "*`$packageID*" -or
                `$_.Name -like "*Win*11*24H2*" -or
                `$_.Name -like "*Windows*11*upgrade*24h2*" -or
                `$_.Name -like "*Win11*24H2*Upgrade*"
            } | Select-Object -First 1
        }
        
        if (`$targetDeployment) {
            `$execMgr = New-Object -ComObject UIResource.UIResourceMgr
            `$execMgr.ExecuteProgram(`$targetDeployment.PackageID, `$targetDeployment.ProgramID, `$false)
            Add-Content -Path (Join-Path `$logPath 'AutoDeploy.log') -Value "[`$timestamp] Task Sequence triggered: `$(`$targetDeployment.Name) (ID: `$(`$targetDeployment.PackageID))"
        } else {
            Add-Content -Path (Join-Path `$logPath 'AutoDeploy_Error.log') -Value "[`$timestamp] Task Sequence not found. Searched for: `$packageID or Win 11 24H2 upgrade packages"
            Add-Content -Path (Join-Path `$logPath 'AutoDeploy_Error.log') -Value "[`$timestamp] Available packages: `$((`$availablePrograms | Select-Object -ExpandProperty Name) -join ', ')"
        }
"@
        }
        "Package" {
@"
        # Try exact Package ID match first
        `$deployment = Get-WmiObject -Namespace root/ccm/clientsdk -Class CCM_Program -Filter "PackageID='`$packageID'" -ErrorAction SilentlyContinue
        
        # If not found by ID, try name search
        if (-not `$deployment) {
            `$allDeployments = Get-WmiObject -Namespace root/ccm/clientsdk -Class CCM_Program -ErrorAction SilentlyContinue
            `$deployment = `$allDeployments | Where-Object {
                `$_.Name -like "*`$packageID*" -or
                `$_.PackageID -like "*`$packageID*" -or
                `$_.Name -like "*Win*11*24H2*" -or
                `$_.Name -like "*Windows*11*upgrade*24h2*" -or
                `$_.Name -like "*Win11*24H2*Upgrade*"
            } | Select-Object -First 1
        }
        
        if (`$deployment) {
            Invoke-WmiMethod -Namespace root/ccm/clientsdk -Class CCM_ProgramsManager -Name ExecuteProgram -ArgumentList @(`$deployment.PackageID, `$deployment.ProgramID) -ErrorAction Stop
            Add-Content -Path (Join-Path `$logPath 'AutoDeploy.log') -Value "[`$timestamp] Package deployment triggered: `$(`$deployment.Name) (ID: `$(`$deployment.PackageID))"
        } else {
            Add-Content -Path (Join-Path `$logPath 'AutoDeploy_Error.log') -Value "[`$timestamp] Package not found. Searched for: `$packageID or Win 11 24H2 upgrade packages"
            `$allNames = (`$allDeployments | Select-Object -ExpandProperty Name) -join ', '
            Add-Content -Path (Join-Path `$logPath 'AutoDeploy_Error.log') -Value "[`$timestamp] Available packages: `$allNames"
        }
"@
        }
        "Application" {
@"
        `$softwareCenter = New-Object -ComObject UIResource.UIResourceMgr
        `$pendingApps = `$softwareCenter.GetAvailableApplications()
        
        # Try exact Package ID match first
        `$targetApp = `$pendingApps | Where-Object { `$_.PackageID -eq '`$packageID' }
        
        # If not found by ID, try name search
        if (-not `$targetApp) {
            `$targetApp = `$pendingApps | Where-Object { 
                `$_.Name -like "*`$packageID*" -or 
                `$_.PackageID -like "*`$packageID*" -or
                `$_.Name -like "*Win*11*24H2*" -or
                `$_.Name -like "*Windows*11*upgrade*24h2*" -or
                `$_.Name -like "*Win11*24H2*Upgrade*"
            } | Select-Object -First 1
        }
        
        if (`$targetApp) {
            `$targetApp.Install()
            Add-Content -Path (Join-Path `$logPath 'AutoDeploy.log') -Value "[`$timestamp] Application installation triggered: `$(`$targetApp.Name) (ID: `$(`$targetApp.PackageID))"
        } else {
            Add-Content -Path (Join-Path `$logPath 'AutoDeploy_Error.log') -Value "[`$timestamp] Application not found. Searched for: `$packageID or Win 11 24H2 upgrade packages"
            Add-Content -Path (Join-Path `$logPath 'AutoDeploy_Error.log') -Value "[`$timestamp] Available applications: `$((`$pendingApps | Select-Object -ExpandProperty Name) -join ', ')"
        }
"@
        }
    }

    $scriptBlock = @"
`$batteryThreshold = $effectiveThreshold
`$packageID = '$script:PackageID'
`$logPath = '$LogPath'
`$forceInstall = `$$ForceInstall
`$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

if (!(Test-Path `$logPath)) { New-Item -Path `$logPath -ItemType Directory -Force | Out-Null }

Add-Content -Path (Join-Path `$logPath 'TaskExecution.log') -Value "[`$timestamp] Task executed - Threshold: `$batteryThreshold%, Force: `$forceInstall"

try {
    `$batteries = @(Get-WmiObject -Class Win32_Battery -ErrorAction SilentlyContinue)
    `$shouldDeploy = `$false
    `$reason = ""
    
    if (`$forceInstall) {
        `$shouldDeploy = `$true
        `$reason = "FORCE INSTALL OVERRIDE - All checks bypassed"
        Add-Content -Path (Join-Path `$logPath 'AutoDeploy.log') -Value "[`$timestamp] FORCE INSTALL MODE ACTIVE"
    }
    elseif (`$batteries.Count -gt 0) {
        `$batteryDetails = @()
        `$totalCharge = 0
        `$anyCharging = `$false
        
        foreach (`$battery in `$batteries) {
            `$chargeLevel = `$battery.EstimatedChargeRemaining
            `$isCharging = (`$battery.BatteryStatus -eq 2)
            `$batteryDetails += "Battery `$(`$battery.DeviceID): `$chargeLevel%"
            `$totalCharge += `$chargeLevel
            if (`$isCharging) { `$anyCharging = `$true }
        }
        
        `$avgCharge = [math]::Round(`$totalCharge / `$batteries.Count, 1)
        `$minCharge = (`$batteries | Measure-Object -Property EstimatedChargeRemaining -Minimum).Minimum
        `$maxCharge = (`$batteries | Measure-Object -Property EstimatedChargeRemaining -Maximum).Maximum
        `$batteryVariance = `$maxCharge - `$minCharge
        
        Add-Content -Path (Join-Path `$logPath 'TaskExecution.log') -Value "[`$timestamp] Batteries: `$(`$batteries.Count), Avg: `$avgCharge%, Min: `$minCharge%, Max: `$maxCharge%"
        
        `$effectiveCharge = if (`$batteryVariance -gt 30) { 
            Add-Content -Path (Join-Path `$logPath 'TaskExecution.log') -Value "[`$timestamp] High variance (`$batteryVariance%), using MAX: `$maxCharge%"
            `$maxCharge
        } else { `$avgCharge }
        
        if (`$effectiveCharge -ge `$batteryThreshold) {
            `$shouldDeploy = `$true
            `$reason = "Multi-battery: Effective `$effectiveCharge% >= `$batteryThreshold%"
        }
        elseif (`$anyCharging -and `$effectiveCharge -ge (`$batteryThreshold - 10)) {
            `$shouldDeploy = `$true
            `$reason = "Charging: `$effectiveCharge% (within 10% of threshold)"
        }
        elseif (`$anyCharging -and `$effectiveCharge -ge 50) {
            `$shouldDeploy = `$true
            `$reason = "AC powered: `$effectiveCharge%"
        }
    } else {
        `$shouldDeploy = `$true
        `$reason = "Desktop (no battery)"
    }
    
    if (`$shouldDeploy) {
        Add-Content -Path (Join-Path `$logPath 'AutoDeploy.log') -Value "[`$timestamp] Deploying: `$reason"
        $deploymentScript
        Start-Sleep -Seconds 2
        Unregister-ScheduledTask -TaskName 'MonitorBatteryForWin11Upgrade' -Confirm:`$false -ErrorAction SilentlyContinue
    }
} catch {
    Add-Content -Path (Join-Path `$logPath 'AutoDeploy_Error.log') -Value "[`$timestamp] ERROR: `$(`$_.Exception.Message)"
}
"@

    try {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($script, $interval)
            
            $existing = Get-ScheduledTask -TaskName 'MonitorBatteryForWin11Upgrade' -ErrorAction SilentlyContinue
            if ($existing) { Unregister-ScheduledTask -TaskName 'MonitorBatteryForWin11Upgrade' -Confirm:$false }
            
            $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -Command `"$script`""
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $interval) -RepetitionDuration (New-TimeSpan -Days 90)
            $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
            
            Register-ScheduledTask -TaskName 'MonitorBatteryForWin11Upgrade' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
            Start-ScheduledTask -TaskName 'MonitorBatteryForWin11Upgrade' -ErrorAction SilentlyContinue
        } -ArgumentList $scriptBlock, $CheckIntervalMinutes -ErrorAction Stop
        
        $forceMsg = if ($ForceInstall) { ", FORCE ENABLED" } else { "" }
        Write-DeploymentLog -Message "Task created - Interval: $CheckIntervalMinutes min, Threshold: $effectiveThreshold%$forceMsg" -ComputerName $ComputerName
        return $true
    } catch {
        Write-DeploymentLog -Message "Failed to create task: $($_.Exception.Message)" -ComputerName $ComputerName -Level "ERROR"
        return $false
    }
}

function Invoke-ForceInstall {
    param([string]$ComputerName)
    
    try {
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($packageID, $deploymentType, $logPath)
            
            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            if (!(Test-Path $logPath)) { New-Item -Path $logPath -ItemType Directory -Force | Out-Null }
            
            Add-Content -Path (Join-Path $logPath 'AutoDeploy.log') -Value "[$timestamp] MANUAL FORCE INSTALL initiated by administrator"
            
            try {
                if ($deploymentType -eq "TaskSequence") {
                    $softwareCenter = New-Object -ComObject UIResource.UIResourceMgr
                    $availablePrograms = $softwareCenter.GetAvailableApplications()
                    $targetDeployment = $availablePrograms | Where-Object { $_.PackageID -eq $packageID }
                    
                    if ($targetDeployment) {
                        $execMgr = New-Object -ComObject UIResource.UIResourceMgr
                        $execMgr.ExecuteProgram($targetDeployment.PackageID, $targetDeployment.ProgramID, $false)
                        return @{ Success = $true; Message = "Task Sequence triggered successfully" }
                    } else {
                        return @{ Success = $false; Message = "Task Sequence not found: $packageID" }
                    }
                }
                elseif ($deploymentType -eq "Package") {
                    $deployment = Get-WmiObject -Namespace root/ccm/clientsdk -Class CCM_Program -Filter "PackageID='$packageID'"
                    if ($deployment) {
                        Invoke-WmiMethod -Namespace root/ccm/clientsdk -Class CCM_ProgramsManager -Name ExecuteProgram -ArgumentList @($deployment.PackageID, $deployment.ProgramID)
                        return @{ Success = $true; Message = "Package deployment triggered successfully" }
                    } else {
                        return @{ Success = $false; Message = "Package not found: $packageID" }
                    }
                }
                elseif ($deploymentType -eq "Application") {
                    $softwareCenter = New-Object -ComObject UIResource.UIResourceMgr
                    $pendingApps = $softwareCenter.GetAvailableApplications()
                    $targetApp = $pendingApps | Where-Object { $_.PackageID -eq $packageID -or $_.Name -like "*$packageID*" }
                    
                    if ($targetApp) {
                        $targetApp.Install()
                        return @{ Success = $true; Message = "Application installation triggered successfully" }
                    } else {
                        return @{ Success = $false; Message = "Application not found: $packageID" }
                    }
                }
            } catch {
                return @{ Success = $false; Message = $_.Exception.Message }
            }
        } -ArgumentList $script:PackageID, $script:DeploymentType, $LogPath -ErrorAction Stop
        
        return $result
    } catch {
        Write-DeploymentLog -Message "Force install failed: $($_.Exception.Message)" -ComputerName $ComputerName -Level "ERROR"
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

function Disable-MonitoringTask {
    param([string]$ComputerName)
    
    try {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $task = Get-ScheduledTask -TaskName 'MonitorBatteryForWin11Upgrade' -ErrorAction SilentlyContinue
            if ($task) {
                Disable-ScheduledTask -TaskName 'MonitorBatteryForWin11Upgrade' -ErrorAction Stop
            }
        } -ErrorAction Stop
        
        Write-DeploymentLog -Message "Monitoring task disabled" -ComputerName $ComputerName
        return $true
    } catch {
        Write-DeploymentLog -Message "Failed to disable task: $($_.Exception.Message)" -ComputerName $ComputerName -Level "ERROR"
        return $false
    }
}

function Remove-MonitoringTask {
    param([string]$ComputerName)
    
    try {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $task = Get-ScheduledTask -TaskName 'MonitorBatteryForWin11Upgrade' -ErrorAction SilentlyContinue
            if ($task) {
                Unregister-ScheduledTask -TaskName 'MonitorBatteryForWin11Upgrade' -Confirm:$false -ErrorAction Stop
            }
        } -ErrorAction Stop
        
        Write-DeploymentLog -Message "Monitoring task removed" -ComputerName $ComputerName
        return $true
    } catch {
        Write-DeploymentLog -Message "Failed to remove task: $($_.Exception.Message)" -ComputerName $ComputerName -Level "ERROR"
        return $false
    }
}
#endregion

#region GUI Setup
$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows 11 Deployment Manager"
$form.Size = New-Object System.Drawing.Size(1500, 950)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# Configuration Panel
$configPanel = New-Object System.Windows.Forms.GroupBox
$configPanel.Location = New-Object System.Drawing.Point(10, 10)
$configPanel.Size = New-Object System.Drawing.Size(1460, 150)
$configPanel.Text = "Configuration"

# Row 1
$packageLabel = New-Object System.Windows.Forms.Label
$packageLabel.Location = New-Object System.Drawing.Point(10, 25)
$packageLabel.Size = New-Object System.Drawing.Size(100, 20)
$packageLabel.Text = "Package/TS ID:"
$configPanel.Controls.Add($packageLabel)

$packageTextBox = New-Object System.Windows.Forms.TextBox
$packageTextBox.Location = New-Object System.Drawing.Point(120, 22)
$packageTextBox.Size = New-Object System.Drawing.Size(150, 20)
$packageTextBox.Text = $script:PackageID
$configPanel.Controls.Add($packageTextBox)

$typeLabel = New-Object System.Windows.Forms.Label
$typeLabel.Location = New-Object System.Drawing.Point(290, 25)
$typeLabel.Size = New-Object System.Drawing.Size(110, 20)
$typeLabel.Text = "Deployment Type:"
$configPanel.Controls.Add($typeLabel)

$typeCombo = New-Object System.Windows.Forms.ComboBox
$typeCombo.Location = New-Object System.Drawing.Point(410, 22)
$typeCombo.Size = New-Object System.Drawing.Size(150, 20)
$typeCombo.DropDownStyle = "DropDownList"
$typeCombo.Items.AddRange(@("TaskSequence", "Package", "Application"))
$typeCombo.SelectedItem = $script:DeploymentType
$configPanel.Controls.Add($typeCombo)

$thresholdLabel = New-Object System.Windows.Forms.Label
$thresholdLabel.Location = New-Object System.Drawing.Point(580, 25)
$thresholdLabel.Size = New-Object System.Drawing.Size(130, 20)
$thresholdLabel.Text = "Default Battery %:"
$configPanel.Controls.Add($thresholdLabel)

$thresholdNumeric = New-Object System.Windows.Forms.NumericUpDown
$thresholdNumeric.Location = New-Object System.Drawing.Point(720, 22)
$thresholdNumeric.Size = New-Object System.Drawing.Size(60, 20)
$thresholdNumeric.Minimum = 0
$thresholdNumeric.Maximum = 100
$thresholdNumeric.Value = $script:BatteryThreshold
$configPanel.Controls.Add($thresholdNumeric)

# Row 2
$intervalLabel = New-Object System.Windows.Forms.Label
$intervalLabel.Location = New-Object System.Drawing.Point(10, 55)
$intervalLabel.Size = New-Object System.Drawing.Size(100, 20)
$intervalLabel.Text = "Check Interval:"
$configPanel.Controls.Add($intervalLabel)

$intervalNumeric = New-Object System.Windows.Forms.NumericUpDown
$intervalNumeric.Location = New-Object System.Drawing.Point(120, 52)
$intervalNumeric.Size = New-Object System.Drawing.Size(60, 20)
$intervalNumeric.Minimum = 1
$intervalNumeric.Maximum = 1440
$intervalNumeric.Value = $script:DefaultCheckInterval
$configPanel.Controls.Add($intervalNumeric)

$minutesLabel = New-Object System.Windows.Forms.Label
$minutesLabel.Location = New-Object System.Drawing.Point(185, 55)
$minutesLabel.Size = New-Object System.Drawing.Size(50, 20)
$minutesLabel.Text = "minutes"
$configPanel.Controls.Add($minutesLabel)

$applyConfigButton = New-Object System.Windows.Forms.Button
$applyConfigButton.Location = New-Object System.Drawing.Point(250, 50)
$applyConfigButton.Size = New-Object System.Drawing.Size(120, 25)
$applyConfigButton.Text = "Apply Settings"
$applyConfigButton.BackColor = [System.Drawing.Color]::LightSkyBlue
$configPanel.Controls.Add($applyConfigButton)

$historyLabel = New-Object System.Windows.Forms.Label
$historyLabel.Location = New-Object System.Drawing.Point(410, 55)
$historyLabel.Size = New-Object System.Drawing.Size(90, 20)
$historyLabel.Text = "History Days:"
$configPanel.Controls.Add($historyLabel)

$historyNumeric = New-Object System.Windows.Forms.NumericUpDown
$historyNumeric.Location = New-Object System.Drawing.Point(500, 52)
$historyNumeric.Size = New-Object System.Drawing.Size(60, 20)
$historyNumeric.Minimum = 1
$historyNumeric.Maximum = 30
$historyNumeric.Value = $script:HistoryDays
$configPanel.Controls.Add($historyNumeric)

# Row 3 - Per-Machine Overrides
$overrideLabel = New-Object System.Windows.Forms.Label
$overrideLabel.Location = New-Object System.Drawing.Point(10, 90)
$overrideLabel.Size = New-Object System.Drawing.Size(200, 20)
$overrideLabel.Text = "Per-Machine Overrides:"
$overrideLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$configPanel.Controls.Add($overrideLabel)

$customThresholdLabel = New-Object System.Windows.Forms.Label
$customThresholdLabel.Location = New-Object System.Drawing.Point(10, 115)
$customThresholdLabel.Size = New-Object System.Drawing.Size(100, 20)
$customThresholdLabel.Text = "Custom Battery %:"
$configPanel.Controls.Add($customThresholdLabel)

$customThresholdNumeric = New-Object System.Windows.Forms.NumericUpDown
$customThresholdNumeric.Location = New-Object System.Drawing.Point(120, 112)
$customThresholdNumeric.Size = New-Object System.Drawing.Size(60, 20)
$customThresholdNumeric.Minimum = 0
$customThresholdNumeric.Maximum = 100
$customThresholdNumeric.Value = 0
$configPanel.Controls.Add($customThresholdNumeric)

$customThresholdInfo = New-Object System.Windows.Forms.Label
$customThresholdInfo.Location = New-Object System.Drawing.Point(185, 115)
$customThresholdInfo.Size = New-Object System.Drawing.Size(200, 20)
$customThresholdInfo.Text = "(0 = use default)"
$customThresholdInfo.ForeColor = [System.Drawing.Color]::Gray
$configPanel.Controls.Add($customThresholdInfo)

$forceInstallCheckBox = New-Object System.Windows.Forms.CheckBox
$forceInstallCheckBox.Location = New-Object System.Drawing.Point(410, 112)
$forceInstallCheckBox.Size = New-Object System.Drawing.Size(350, 25)
$forceInstallCheckBox.Text = "Enable FORCE INSTALL (Bypass ALL battery checks)"
$forceInstallCheckBox.ForeColor = [System.Drawing.Color]::DarkRed
$forceInstallCheckBox.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$configPanel.Controls.Add($forceInstallCheckBox)

$form.Controls.Add($configPanel)

# Computer Input
$inputPanel = New-Object System.Windows.Forms.GroupBox
$inputPanel.Location = New-Object System.Drawing.Point(10, 170)
$inputPanel.Size = New-Object System.Drawing.Size(300, 100)
$inputPanel.Text = "Target Computers"

$inputLabel = New-Object System.Windows.Forms.Label
$inputLabel.Location = New-Object System.Drawing.Point(10, 25)
$inputLabel.Size = New-Object System.Drawing.Size(280, 20)
$inputLabel.Text = "Enter computer names (one per line):"
$inputPanel.Controls.Add($inputLabel)

$computersTextBox = New-Object System.Windows.Forms.TextBox
$computersTextBox.Location = New-Object System.Drawing.Point(10, 45)
$computersTextBox.Size = New-Object System.Drawing.Size(280, 45)
$computersTextBox.Multiline = $true
$computersTextBox.ScrollBars = "Vertical"
$computersTextBox.AcceptsReturn = $true
$inputPanel.Controls.Add($computersTextBox)

$form.Controls.Add($inputPanel)

# Action Buttons
$buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$buttonPanel.Location = New-Object System.Drawing.Point(320, 170)
$buttonPanel.Size = New-Object System.Drawing.Size(1150, 100)
$buttonPanel.FlowDirection = "LeftToRight"
$buttonPanel.WrapContents = $true

$checkStatusButton = New-Object System.Windows.Forms.Button
$checkStatusButton.Size = New-Object System.Drawing.Size(140, 30)
$checkStatusButton.Text = "Check Status"
$checkStatusButton.BackColor = [System.Drawing.Color]::LightGreen
$buttonPanel.Controls.Add($checkStatusButton)

$findPackagesButton = New-Object System.Windows.Forms.Button
$findPackagesButton.Size = New-Object System.Drawing.Size(140, 30)
$findPackagesButton.Text = "Find Packages"
$findPackagesButton.BackColor = [System.Drawing.Color]::LightYellow
$buttonPanel.Controls.Add($findPackagesButton)

$viewBatteryButton = New-Object System.Windows.Forms.Button
$viewBatteryButton.Size = New-Object System.Drawing.Size(140, 30)
$viewBatteryButton.Text = "View Batteries"
$viewBatteryButton.BackColor = [System.Drawing.Color]::LightCyan
$buttonPanel.Controls.Add($viewBatteryButton)

$enableMonitoringButton = New-Object System.Windows.Forms.Button
$enableMonitoringButton.Size = New-Object System.Drawing.Size(140, 30)
$enableMonitoringButton.Text = "Enable Monitoring"
$enableMonitoringButton.BackColor = [System.Drawing.Color]::LightBlue
$buttonPanel.Controls.Add($enableMonitoringButton)

$updateTaskButton = New-Object System.Windows.Forms.Button
$updateTaskButton.Size = New-Object System.Drawing.Size(140, 30)
$updateTaskButton.Text = "Update Task Settings"
$updateTaskButton.BackColor = [System.Drawing.Color]::LightSteelBlue
$buttonPanel.Controls.Add($updateTaskButton)

$forceInstallNowButton = New-Object System.Windows.Forms.Button
$forceInstallNowButton.Size = New-Object System.Drawing.Size(140, 30)
$forceInstallNowButton.Text = "FORCE INSTALL NOW"
$forceInstallNowButton.BackColor = [System.Drawing.Color]::OrangeRed
$forceInstallNowButton.ForeColor = [System.Drawing.Color]::White
$forceInstallNowButton.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
$buttonPanel.Controls.Add($forceInstallNowButton)

$disableMonitoringButton = New-Object System.Windows.Forms.Button
$disableMonitoringButton.Size = New-Object System.Drawing.Size(140, 30)
$disableMonitoringButton.Text = "Disable Monitoring"
$disableMonitoringButton.BackColor = [System.Drawing.Color]::LightGoldenrodYellow
$buttonPanel.Controls.Add($disableMonitoringButton)

$removeTaskButton = New-Object System.Windows.Forms.Button
$removeTaskButton.Size = New-Object System.Drawing.Size(140, 30)
$removeTaskButton.Text = "Remove Task"
$removeTaskButton.BackColor = [System.Drawing.Color]::LightCoral
$buttonPanel.Controls.Add($removeTaskButton)

$viewHistoryButton = New-Object System.Windows.Forms.Button
$viewHistoryButton.Size = New-Object System.Drawing.Size(140, 30)
$viewHistoryButton.Text = "View History"
$viewHistoryButton.BackColor = [System.Drawing.Color]::Lavender
$buttonPanel.Controls.Add($viewHistoryButton)

$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Size = New-Object System.Drawing.Size(90, 30)
$clearButton.Text = "Clear"
$buttonPanel.Controls.Add($clearButton)

$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Size = New-Object System.Drawing.Size(90, 30)
$exportButton.Text = "Export CSV"
$buttonPanel.Controls.Add($exportButton)

$form.Controls.Add($buttonPanel)

# Results Grid
$resultsGrid = New-Object System.Windows.Forms.DataGridView
$resultsGrid.Location = New-Object System.Drawing.Point(10, 280)
$resultsGrid.Size = New-Object System.Drawing.Size(1460, 560)
$resultsGrid.AllowUserToAddRows = $false
$resultsGrid.AllowUserToDeleteRows = $false
$resultsGrid.ReadOnly = $true
$resultsGrid.SelectionMode = "FullRowSelect"
$resultsGrid.AutoSizeColumnsMode = "Fill"

$resultsGrid.Columns.Add("Computer", "Computer") | Out-Null
$resultsGrid.Columns.Add("Status", "Connection") | Out-Null
$resultsGrid.Columns.Add("Method", "Method") | Out-Null
$resultsGrid.Columns.Add("BatteryCount", "Batteries") | Out-Null
$resultsGrid.Columns.Add("BatteryLevel", "Battery %") | Out-Null
$resultsGrid.Columns.Add("Charging", "Charging") | Out-Null
$resultsGrid.Columns.Add("TaskExists", "Task") | Out-Null
$resultsGrid.Columns.Add("TaskState", "Task State") | Out-Null
$resultsGrid.Columns.Add("CheckInterval", "Check Every") | Out-Null
$resultsGrid.Columns.Add("Threshold", "Threshold %") | Out-Null
$resultsGrid.Columns.Add("ForceMode", "Force") | Out-Null
$resultsGrid.Columns.Add("LastRun", "Last Run") | Out-Null
$resultsGrid.Columns.Add("LastResult", "Last Result") | Out-Null
$resultsGrid.Columns.Add("LastChecked", "Checked At") | Out-Null

$form.Controls.Add($resultsGrid)

# Status Bar
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point(10, 850)
$statusLabel.Size = New-Object System.Drawing.Size(1200, 20)
$statusLabel.Text = "Ready"
$form.Controls.Add($statusLabel)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(10, 875)
$progressBar.Size = New-Object System.Drawing.Size(1460, 25)
$form.Controls.Add($progressBar)
#endregion

#region Helper Functions
function Get-ComputerList {
    $input = $computersTextBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($input)) { return @() }
    
    $computers = $input -split '[\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    return $computers
}

function Update-GridRow {
    param(
        [string]$ComputerName,
        [string]$ConnectionStatus,
        [string]$ConnectionMethod = "N/A",
        [string]$BatteryCount,
        [string]$BatteryLevel,
        [string]$Charging,
        [string]$TaskExists,
        [string]$TaskState,
        [string]$CheckInterval,
        [string]$Threshold,
        [string]$ForceMode,
        [string]$LastRun,
        [string]$LastResult,
        [System.Drawing.Color]$RowColor
    )
    
    $existingRow = $resultsGrid.Rows | Where-Object { $_.Cells["Computer"].Value -eq $ComputerName }
    
    if ($existingRow) {
        $existingRow.Cells["Status"].Value = $ConnectionStatus
        $existingRow.Cells["Method"].Value = $ConnectionMethod
        $existingRow.Cells["BatteryCount"].Value = $BatteryCount
        $existingRow.Cells["BatteryLevel"].Value = $BatteryLevel
        $existingRow.Cells["Charging"].Value = $Charging
        $existingRow.Cells["TaskExists"].Value = $TaskExists
        $existingRow.Cells["TaskState"].Value = $TaskState
        $existingRow.Cells["CheckInterval"].Value = $CheckInterval
        $existingRow.Cells["Threshold"].Value = $Threshold
        $existingRow.Cells["ForceMode"].Value = $ForceMode
        $existingRow.Cells["LastRun"].Value = $LastRun
        $existingRow.Cells["LastResult"].Value = $LastResult
        $existingRow.Cells["LastChecked"].Value = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $existingRow.DefaultCellStyle.BackColor = $RowColor
    } else {
        $rowIndex = $resultsGrid.Rows.Add($ComputerName, $ConnectionStatus, $ConnectionMethod, $BatteryCount, $BatteryLevel, $Charging, 
            $TaskExists, $TaskState, $CheckInterval, $Threshold, $ForceMode, $LastRun, $LastResult, (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
        $resultsGrid.Rows[$rowIndex].DefaultCellStyle.BackColor = $RowColor
    }
    
    [System.Windows.Forms.Application]::DoEvents()
}
#endregion

#region Event Handlers

# Apply Config
$applyConfigButton.Add_Click({
    $script:PackageID = $packageTextBox.Text.Trim()
    $script:DeploymentType = $typeCombo.SelectedItem
    $script:BatteryThreshold = $thresholdNumeric.Value
    $script:DefaultCheckInterval = $intervalNumeric.Value
    $script:HistoryDays = $historyNumeric.Value
    
    [System.Windows.Forms.MessageBox]::Show(
        "Configuration updated!`n`nPackage: $($script:PackageID)`nType: $($script:DeploymentType)`nThreshold: $($script:BatteryThreshold)%`nInterval: $($script:DefaultCheckInterval) min",
        "Settings Applied",
        "OK",
        "Information"
    )
})

# Find Packages
$findPackagesButton.Add_Click({
    $computers = Get-ComputerList
    if ($computers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please enter at least one computer name.", "No Computers", "OK", "Warning")
        return
    }
    
    $selectedComputer = $computers[0]  # Use first computer
    $statusLabel.Text = "Searching for packages on $selectedComputer..."
    [System.Windows.Forms.Application]::DoEvents()
    
    if (Test-Connection -ComputerName $selectedComputer -Count 1 -Quiet) {
        try {
            $packages = Invoke-Command -ComputerName $selectedComputer -ScriptBlock {
                param($deployType)
                
                $results = @()
                
                if ($deployType -eq "TaskSequence" -or $deployType -eq "Application") {
                    try {
                        $softwareCenter = New-Object -ComObject UIResource.UIResourceMgr
                        $availablePrograms = $softwareCenter.GetAvailableApplications()
                        
                        foreach ($prog in $availablePrograms) {
                            $results += [PSCustomObject]@{
                                Name = $prog.Name
                                PackageID = $prog.PackageID
                                Type = if ($prog.IsMachineTarget) { "Application" } else { "TaskSequence" }
                            }
                        }
                    } catch {
                        $results += [PSCustomObject]@{
                            Name = "Error: $($_.Exception.Message)"
                            PackageID = "N/A"
                            Type = "Error"
                        }
                    }
                }
                
                if ($deployType -eq "Package") {
                    try {
                        $allDeployments = Get-WmiObject -Namespace root/ccm/clientsdk -Class CCM_Program -ErrorAction SilentlyContinue
                        foreach ($dep in $allDeployments) {
                            $results += [PSCustomObject]@{
                                Name = $dep.Name
                                PackageID = $dep.PackageID
                                Type = "Package"
                            }
                        }
                    } catch {
                        $results += [PSCustomObject]@{
                            Name = "Error: $($_.Exception.Message)"
                            PackageID = "N/A"
                            Type = "Error"
                        }
                    }
                }
                
                return $results
            } -ArgumentList $script:DeploymentType -ErrorAction Stop
            
            if ($packages -and $packages.Count -gt 0) {
                $output = New-Object System.Text.StringBuilder
                [void]$output.AppendLine("AVAILABLE PACKAGES ON: $selectedComputer")
                [void]$output.AppendLine("Current Deployment Type: $($script:DeploymentType)")
                [void]$output.AppendLine("Current Package ID: $($script:PackageID)")
                [void]$output.AppendLine("=" * 90)
                [void]$output.AppendLine("")
                
                # Filter Windows 11 packages
                $win11Packages = $packages | Where-Object { 
                    $_.Name -like "*Win*11*" -or 
                    $_.Name -like "*Windows*11*" -or
                    $_.Name -like "*24H2*" -or
                    $_.PackageID -like "*WIN11*"
                }
                
                if ($win11Packages) {
                    [void]$output.AppendLine(">>> WINDOWS 11 PACKAGES FOUND <<<")
                    [void]$output.AppendLine("-" * 90)
                    foreach ($pkg in $win11Packages) {
                        [void]$output.AppendLine("  Name: $($pkg.Name)")
                        [void]$output.AppendLine("  Package ID: $($pkg.PackageID)")
                        [void]$output.AppendLine("  Type: $($pkg.Type)")
                        [void]$output.AppendLine("")
                    }
                }
                
                [void]$output.AppendLine("ALL AVAILABLE PACKAGES ($($packages.Count) total):")
                [void]$output.AppendLine("-" * 90)
                
                foreach ($pkg in $packages) {
                    [void]$output.AppendLine("  Name: $($pkg.Name)")
                    [void]$output.AppendLine("  Package ID: $($pkg.PackageID)")
                    [void]$output.AppendLine("  Type: $($pkg.Type)")
                    [void]$output.AppendLine("")
                }
                
                [void]$output.AppendLine("")
                [void]$output.AppendLine("HOW TO CONFIGURE:")
                [void]$output.AppendLine("-" * 90)
                [void]$output.AppendLine("Update lines 10-11 in the script with one of these options:")
                [void]$output.AppendLine("")
                [void]$output.AppendLine("Option 1 - Use exact Package ID:")
                [void]$output.AppendLine('  $script:PackageID = "ABC00123"  # Replace with actual PackageID from above')
                [void]$output.AppendLine("")
                [void]$output.AppendLine("Option 2 - Use name search (recommended for Win 11):")
                [void]$output.AppendLine('  $script:PackageID = "Win 11 24H2"  # Script will search by name')
                [void]$output.AppendLine('  $script:PackageID = "Windows 11 upgrade 24h2"  # Also works')
                [void]$output.AppendLine("")
                [void]$output.AppendLine("The script automatically searches for packages containing:")
                [void]$output.AppendLine('  - Your PackageID value')
                [void]$output.AppendLine('  - "Win 11 24H2", "Windows 11 upgrade 24h2", "Win11 24H2 Upgrade"')
                
                # Show in dialog
                $outputForm = New-Object System.Windows.Forms.Form
                $outputForm.Text = "Available Packages - $selectedComputer"
                $outputForm.Size = New-Object System.Drawing.Size(1000, 700)
                $outputForm.StartPosition = "CenterScreen"
                
                $outputTextBox = New-Object System.Windows.Forms.TextBox
                $outputTextBox.Multiline = $true
                $outputTextBox.ScrollBars = "Both"
                $outputTextBox.WordWrap = $false
                $outputTextBox.Location = New-Object System.Drawing.Point(10, 10)
                $outputTextBox.Size = New-Object System.Drawing.Size(960, 600)
                $outputTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
                $outputTextBox.Text = $output.ToString()
                $outputTextBox.ReadOnly = $true
                $outputForm.Controls.Add($outputTextBox)
                
                $closeButton = New-Object System.Windows.Forms.Button
                $closeButton.Text = "Close"
                $closeButton.Location = New-Object System.Drawing.Point(450, 620)
                $closeButton.Size = New-Object System.Drawing.Size(100, 30)
                $closeButton.Add_Click({ $outputForm.Close() })
                $outputForm.Controls.Add($closeButton)
                
                $outputForm.ShowDialog()
                
            } else {
                [System.Windows.Forms.MessageBox]::Show("No packages found on $selectedComputer or unable to query SCCM client.`n`nMake sure:`n- SCCM client is installed`n- Machine policy has been refreshed`n- Deployments are targeted to this computer", "No Packages", "OK", "Information")
            }
            
            $statusLabel.Text = "Package search completed"
            
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error searching for packages:`n$($_.Exception.Message)`n`nCheck:`n- WinRM is enabled on target`n- You have admin rights`n- SCCM client is installed", "Error", "OK", "Error")
            $statusLabel.Text = "Package search failed"
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Cannot connect to $selectedComputer`n`nVerify:`n- Computer is online`n- Network connectivity`n- Firewall allows ping", "Connection Failed", "OK", "Error")
        $statusLabel.Text = "Ready"
    }
})

# Check Status
$checkStatusButton.Add_Click({
    $computers = Get-ComputerList
    if ($computers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please enter at least one computer name.", "No Computers", "OK", "Warning")
        return
    }
    
    # Disable buttons during processing
    $checkStatusButton.Enabled = $false
    $enableMonitoringButton.Enabled = $false
    $updateTaskButton.Enabled = $false
    $forceInstallNowButton.Enabled = $false
    
    $progressBar.Value = 0
    $progressBar.Maximum = $computers.Count
    $statusLabel.Text = "Checking status..."
    
    # Process each computer
    $jobCount = 0
    foreach ($computer in $computers) {
        $jobCount++
        $statusLabel.Text = "Checking: $computer... ($jobCount of $($computers.Count))"
        [System.Windows.Forms.Application]::DoEvents()
        
        # Run connection test in a faster way
        $connMethod = ''
        $connected = $false
        
        # Quick ping test first
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            # Try WinRM quickly
            try {
                $null = Invoke-Command -ComputerName $computer -ScriptBlock { $true } -ErrorAction Stop
                $connMethod = 'WinRM'
                $connected = $true
            } catch {
                # Try WMI as fallback (faster than full method chain)
                try {
                    $null = Get-WmiObject -ComputerName $computer -Class Win32_OperatingSystem -ErrorAction Stop
                    $connMethod = 'WMI'
                    $connected = $true
                } catch {
                    # Try CIM
                    try {
                        $session = New-CimSession -ComputerName $computer -ErrorAction Stop -OperationTimeoutSec 5
                        $null = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -ErrorAction Stop
                        Remove-CimSession -CimSession $session
                        $connMethod = 'CIM'
                        $connected = $true
                    } catch {
                        # Try PSExec if available
                        if (Test-Path "C:\temp\sysinternal\PsExec.exe") {
                            try {
                                $result = & "C:\temp\sysinternal\PsExec.exe" -accepteula "\\$computer" cmd /c "echo test" 2>&1
                                if ($LASTEXITCODE -eq 0) {
                                    $connMethod = 'PSExec'
                                    $connected = $true
                                }
                            } catch {
                                $connected = $false
                            }
                        }
                    }
                }
            }
        }
        
        if ($connected) {
            try {
                $battery = Get-BatteryStatus -ComputerName $computer -ConnectionMethod $connMethod
                $taskStatus = Get-MonitoringTaskStatus -ComputerName $computer
                
                if ($battery) {
                    $batteryCountDisplay = if ($battery.HasBattery) { "$($battery.BatteryCount)" } else { "None" }
                    $batteryDisplay = if ($battery.HasBattery) {
                        if ($battery.BatteryCount -gt 1) {
                            "Avg:$($battery.AverageChargeLevel)% Min:$($battery.MinimumChargeLevel)% Max:$($battery.MaximumChargeLevel)%"
                        } else {
                            "$($battery.AverageChargeLevel)%"
                        }
                    } else { "Desktop" }
                    $chargingDisplay = if ($battery.HasBattery) { if ($battery.IsCharging) { "Yes" } else { "No" } } else { "N/A" }
                    
                    $taskExistsDisplay = if ($taskStatus.Exists) { "Yes" } else { "No" }
                    $taskStateDisplay = $taskStatus.State
                    $checkIntervalDisplay = if ($taskStatus.CheckIntervalMinutes) { "$($taskStatus.CheckIntervalMinutes) min" } else { "N/A" }
                    $thresholdDisplay = if ($taskStatus.BatteryThreshold) { "$($taskStatus.BatteryThreshold)%" } else { "N/A" }
                    $forceModeDisplay = if ($taskStatus.ForceInstallEnabled) { "YES" } else { "No" }
                    
                    $lastRunDisplay = if ($taskStatus.LastRunTime) { $taskStatus.LastRunTime.ToString("MM/dd HH:mm") } else { "Never" }
                    $lastResultDisplay = if ($taskStatus.LastResult -ne $null) {
                        $errorHex = $taskStatus.LastResultHex
                        "$errorHex"
                    } else { "N/A" }
                    
                    $rowColor = [System.Drawing.Color]::LightGreen
                    if (!$taskStatus.Exists) { $rowColor = [System.Drawing.Color]::LightYellow }
                    elseif ($taskStatus.ForceInstallEnabled) { $rowColor = [System.Drawing.Color]::LightSalmon }
                    elseif ($taskStatus.State -eq 'Disabled') { $rowColor = [System.Drawing.Color]::LightGray }
                    elseif ($taskStatus.LastResult -ne 0 -and $taskStatus.LastResult -ne $null) { $rowColor = [System.Drawing.Color]::LightCoral }
                    
                    Update-GridRow -ComputerName $computer -ConnectionStatus "Connected" -ConnectionMethod $connMethod `
                        -BatteryCount $batteryCountDisplay -BatteryLevel $batteryDisplay -Charging $chargingDisplay `
                        -TaskExists $taskExistsDisplay -TaskState $taskStateDisplay -CheckInterval $checkIntervalDisplay `
                        -Threshold $thresholdDisplay -ForceMode $forceModeDisplay `
                        -LastRun $lastRunDisplay -LastResult $lastResultDisplay -RowColor $rowColor
                }
            } catch {
                Write-DeploymentLog -Message "Error getting details: $($_.Exception.Message)" -ComputerName $computer -Level "ERROR"
                Update-GridRow -ComputerName $computer -ConnectionStatus "Error" -ConnectionMethod $connMethod -BatteryCount "N/A" -BatteryLevel "N/A" `
                    -Charging "N/A" -TaskExists "N/A" -TaskState "N/A" -CheckInterval "N/A" `
                    -Threshold "N/A" -ForceMode "N/A" -LastRun "N/A" -LastResult "N/A" `
                    -RowColor ([System.Drawing.Color]::LightCoral)
            }
        } else {
            Update-GridRow -ComputerName $computer -ConnectionStatus "Offline" -ConnectionMethod "None" -BatteryCount "N/A" -BatteryLevel "N/A" `
                -Charging "N/A" -TaskExists "N/A" -TaskState "N/A" -CheckInterval "N/A" `
                -Threshold "N/A" -ForceMode "N/A" -LastRun "N/A" -LastResult "N/A" `
                -RowColor ([System.Drawing.Color]::LightCoral)
        }
        
        $progressBar.Value++
        [System.Windows.Forms.Application]::DoEvents()
    }
    
    # Re-enable buttons
    $checkStatusButton.Enabled = $true
    $enableMonitoringButton.Enabled = $true
    $updateTaskButton.Enabled = $true
    $forceInstallNowButton.Enabled = $true
    
    $statusLabel.Text = "Status check completed"
    $progressBar.Value = 0
})

# View Battery Details
$viewBatteryButton.Add_Click({
    $selectedComputer = $null
    
    if ($resultsGrid.SelectedRows.Count -gt 0) {
        $selectedComputer = $resultsGrid.SelectedRows[0].Cells["Computer"].Value
    } else {
        $computers = Get-ComputerList
        if ($computers.Count -eq 1) {
            $selectedComputer = $computers[0]
        } else {
            [System.Windows.Forms.MessageBox]::Show("Please select a computer from the grid or enter a single computer name.", "No Selection", "OK", "Warning")
            return
        }
    }
    
    $connMethod = ''
    if (Test-ComputerConnection -ComputerName $selectedComputer -ConnectionMethod ([ref]$connMethod)) {
        $battery = Get-BatteryStatus -ComputerName $selectedComputer -ConnectionMethod $connMethod
        if ($battery) {
            Show-BatteryDetails -ComputerName $selectedComputer -BatteryInfo $battery
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Cannot connect to $selectedComputer", "Connection Failed", "OK", "Error")
    }
})

# Enable Monitoring
$enableMonitoringButton.Add_Click({
    $computers = Get-ComputerList
    if ($computers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please enter at least one computer name.", "No Computers", "OK", "Warning")
        return
    }
    
    $customThreshold = [int]$customThresholdNumeric.Value
    $forceInstall = $forceInstallCheckBox.Checked
    
    $confirmMsg = "Create monitoring tasks on $($computers.Count) computer(s)?`n`n"
    $confirmMsg += "Settings:`n"
    $confirmMsg += "- Check Interval: $($script:DefaultCheckInterval) minutes`n"
    $confirmMsg += "- Battery Threshold: $(if ($customThreshold -gt 0) { "$customThreshold% (CUSTOM)" } else { "$($script:BatteryThreshold)% (default)" })`n"
    $confirmMsg += "- Force Install: $(if ($forceInstall) { 'ENABLED (bypasses all checks)' } else { 'Disabled' })"
    
    $result = [System.Windows.Forms.MessageBox]::Show($confirmMsg, "Confirm Operation", "YesNo", "Question")
    if ($result -eq "No") { return }
    
    $progressBar.Value = 0
    $progressBar.Maximum = $computers.Count
    $successCount = 0
    $failCount = 0
    
    foreach ($computer in $computers) {
        $statusLabel.Text = "Enabling monitoring on: $computer..."
        [System.Windows.Forms.Application]::DoEvents()
        
        if (Test-ComputerConnection -ComputerName $computer) {
            if (New-MonitoringTask -ComputerName $computer -CheckIntervalMinutes $script:DefaultCheckInterval -BatteryThresholdOverride $customThreshold -ForceInstall $forceInstall) {
                $successCount++
            } else {
                $failCount++
            }
        } else {
            $failCount++
        }
        
        $progressBar.Value++
    }
    
    $statusLabel.Text = "Completed: $successCount succeeded, $failCount failed"
    $progressBar.Value = 0
    
    [System.Windows.Forms.MessageBox]::Show("Operation completed:`n`nSuccessful: $successCount`nFailed: $failCount", "Complete", "OK", "Information")
    
    # Reset overrides
    $customThresholdNumeric.Value = 0
    $forceInstallCheckBox.Checked = $false
})

# Update Task Settings
$updateTaskButton.Add_Click({
    $computers = Get-ComputerList
    if ($computers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please enter at least one computer name.", "No Computers", "OK", "Warning")
        return
    }
    
    $customThreshold = [int]$customThresholdNumeric.Value
    $forceInstall = $forceInstallCheckBox.Checked
    
    $confirmMsg = "Update existing tasks on $($computers.Count) computer(s)?`n`n"
    $confirmMsg += "New Settings:`n"
    $confirmMsg += "- Check Interval: $($script:DefaultCheckInterval) minutes`n"
    $confirmMsg += "- Battery Threshold: $(if ($customThreshold -gt 0) { "$customThreshold%" } else { "$($script:BatteryThreshold)% (default)" })`n"
    $confirmMsg += "- Force Install: $(if ($forceInstall) { 'ENABLED' } else { 'Disabled' })"
    
    $result = [System.Windows.Forms.MessageBox]::Show($confirmMsg, "Confirm Update", "YesNo", "Question")
    if ($result -eq "No") { return }
    
    $progressBar.Value = 0
    $progressBar.Maximum = $computers.Count
    $successCount = 0
    $failCount = 0
    
    foreach ($computer in $computers) {
        $statusLabel.Text = "Updating task on: $computer..."
        [System.Windows.Forms.Application]::DoEvents()
        
        if (Test-ComputerConnection -ComputerName $computer) {
            if (New-MonitoringTask -ComputerName $computer -CheckIntervalMinutes $script:DefaultCheckInterval -BatteryThresholdOverride $customThreshold -ForceInstall $forceInstall) {
                $successCount++
            } else {
                $failCount++
            }
        } else {
            $failCount++
        }
        
        $progressBar.Value++
    }
    
    $statusLabel.Text = "Update completed: $successCount succeeded, $failCount failed"
    $progressBar.Value = 0
    
    [System.Windows.Forms.MessageBox]::Show("Task update completed:`n`nSuccessful: $successCount`nFailed: $failCount", "Complete", "OK", "Information")
    
    $customThresholdNumeric.Value = 0
    $forceInstallCheckBox.Checked = $false
})

# Force Install NOW
$forceInstallNowButton.Add_Click({
    $selectedComputer = $null
    
    if ($resultsGrid.SelectedRows.Count -gt 0) {
        $selectedComputer = $resultsGrid.SelectedRows[0].Cells["Computer"].Value
    } else {
        $computers = Get-ComputerList
        if ($computers.Count -eq 1) {
            $selectedComputer = $computers[0]
        } else {
            [System.Windows.Forms.MessageBox]::Show("Please select ONE computer from the grid or enter a single computer name.", "No Selection", "OK", "Warning")
            return
        }
    }
    
    # Get battery status first
    $battery = Get-BatteryStatus -ComputerName $selectedComputer
    
    $warningMsg = "FORCE INSTALL WARNING`n`n"
    $warningMsg += "Computer: $selectedComputer`n`n"
    
    if ($battery -and $battery.HasBattery) {
        $warningMsg += "BATTERY STATUS:`n"
        $warningMsg += "  Batteries: $($battery.BatteryCount)`n"
        $warningMsg += "  Average Charge: $($battery.AverageChargeLevel)%`n"
        $warningMsg += "  Min Charge: $($battery.MinimumChargeLevel)%`n"
        $warningMsg += "  Max Charge: $($battery.MaximumChargeLevel)%`n"
        $warningMsg += "  Charging: $($battery.IsCharging)`n`n"
        
        if ($battery.BatteryCount -gt 1) {
            $warningMsg += "Multi-battery system detected!`n"
            $warningMsg += "Click 'View Batteries' for detailed analysis before proceeding.`n`n"
        }
        
        if ($battery.AverageChargeLevel -lt 30) {
            $warningMsg += "WARNING: Battery level is VERY LOW!`n"
            $warningMsg += "Installation may fail or cause data loss!`n`n"
        }
    } else {
        $warningMsg += "BATTERY STATUS: Desktop system (no battery)`n`n"
    }
    
    $warningMsg += "This will IMMEDIATELY trigger the Windows 11 upgrade`n"
    $warningMsg += "bypassing ALL battery and safety checks!`n`n"
    $warningMsg += "Are you ABSOLUTELY SURE you want to proceed?"
    
    $result = [System.Windows.Forms.MessageBox]::Show($warningMsg, "CONFIRM FORCE INSTALL", "YesNo", "Warning")
    
    if ($result -eq "Yes") {
        $statusLabel.Text = "Forcing install on: $selectedComputer..."
        [System.Windows.Forms.Application]::DoEvents()
        
        $installResult = Invoke-ForceInstall -ComputerName $selectedComputer
        
        if ($installResult.Success) {
            [System.Windows.Forms.MessageBox]::Show(
                "Force install triggered successfully!`n`n$($installResult.Message)`n`nMonitor the machine for deployment progress.",
                "Install Triggered",
                "OK",
                "Information"
            )
            $statusLabel.Text = "Force install triggered on $selectedComputer"
        } else {
            [System.Windows.Forms.MessageBox]::Show(
                "Force install FAILED!`n`nError: $($installResult.Message)",
                "Install Failed",
                "OK",
                "Error"
            )
            $statusLabel.Text = "Force install failed"
        }
    }
})

# Disable Monitoring
$disableMonitoringButton.Add_Click({
    $computers = Get-ComputerList
    if ($computers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please enter at least one computer name.", "No Computers", "OK", "Warning")
        return
    }
    
    $result = [System.Windows.Forms.MessageBox]::Show("Disable monitoring tasks on $($computers.Count) computer(s)?", "Confirm", "YesNo", "Question")
    if ($result -eq "No") { return }
    
    $progressBar.Value = 0
    $progressBar.Maximum = $computers.Count
    $successCount = 0
    $failCount = 0
    
    foreach ($computer in $computers) {
        if (Test-ComputerConnection -ComputerName $computer) {
            if (Disable-MonitoringTask -ComputerName $computer) { $successCount++ } else { $failCount++ }
        } else {
            $failCount++
        }
        $progressBar.Value++
    }
    
    $statusLabel.Text = "Disable completed: $successCount succeeded, $failCount failed"
    $progressBar.Value = 0
    
    [System.Windows.Forms.MessageBox]::Show("Disable completed:`n`nSuccessful: $successCount`nFailed: $failCount", "Complete", "OK", "Information")
})

# Remove Task
$removeTaskButton.Add_Click({
    $computers = Get-ComputerList
    if ($computers.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please enter at least one computer name.", "No Computers", "OK", "Warning")
        return
    }
    
    $result = [System.Windows.Forms.MessageBox]::Show("PERMANENTLY REMOVE monitoring tasks from $($computers.Count) computer(s)?`n`nThis cannot be undone!", "Confirm Deletion", "YesNo", "Warning")
    if ($result -eq "No") { return }
    
    $progressBar.Value = 0
    $progressBar.Maximum = $computers.Count
    $successCount = 0
    $failCount = 0
    
    foreach ($computer in $computers) {
        if (Test-ComputerConnection -ComputerName $computer) {
            if (Remove-MonitoringTask -ComputerName $computer) { $successCount++ } else { $failCount++ }
        } else {
            $failCount++
        }
        $progressBar.Value++
    }
    
    $statusLabel.Text = "Removal completed: $successCount succeeded, $failCount failed"
    $progressBar.Value = 0
    
    [System.Windows.Forms.MessageBox]::Show("Task removal completed:`n`nSuccessful: $successCount`nFailed: $failCount", "Complete", "OK", "Information")
})

# View History
$viewHistoryButton.Add_Click({
    $selectedComputer = $null
    
    if ($resultsGrid.SelectedRows.Count -gt 0) {
        $selectedComputer = $resultsGrid.SelectedRows[0].Cells["Computer"].Value
    } else {
        $computers = Get-ComputerList
        if ($computers.Count -eq 1) {
            $selectedComputer = $computers[0]
        } else {
            [System.Windows.Forms.MessageBox]::Show("Please select a computer from the grid or enter a single computer name.", "No Selection", "OK", "Warning")
            return
        }
    }
    
    if (!(Test-ComputerConnection -ComputerName $selectedComputer)) {
        [System.Windows.Forms.MessageBox]::Show("Cannot connect to $selectedComputer", "Connection Failed", "OK", "Error")
        return
    }
    
    $history = Get-TaskHistory -ComputerName $selectedComputer -Days $script:HistoryDays
    $deploymentLogs = Get-DeploymentLogs -ComputerName $selectedComputer -Days $script:HistoryDays
    
    $historyForm = New-Object System.Windows.Forms.Form
    $historyForm.Text = "History: $selectedComputer (Last $($script:HistoryDays) Days)"
    $historyForm.Size = New-Object System.Drawing.Size(1000, 700)
    $historyForm.StartPosition = "CenterScreen"
    
    $historyTextBox = New-Object System.Windows.Forms.RichTextBox
    $historyTextBox.Location = New-Object System.Drawing.Point(10, 10)
    $historyTextBox.Size = New-Object System.Drawing.Size(960, 630)
    $historyTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $historyTextBox.ReadOnly = $true
    $historyTextBox.WordWrap = $false
    
    $historyContent = New-Object System.Text.StringBuilder
    
    [void]$historyContent.AppendLine("=" * 100)
    [void]$historyContent.AppendLine("TASK SCHEDULER HISTORY")
    [void]$historyContent.AppendLine("=" * 100)
    [void]$historyContent.AppendLine("")
    
    if ($history.Success -and $history.Events.Count -gt 0) {
        foreach ($event in $history.Events) {
            [void]$historyContent.AppendLine("[$($event.Time.ToString('yyyy-MM-dd HH:mm:ss'))] [Event $($event.EventID)] [$($event.Level)]")
            [void]$historyContent.AppendLine("  $($event.Message)")
            [void]$historyContent.AppendLine("")
        }
    } else {
        [void]$historyContent.AppendLine("No task scheduler events found in the last $($script:HistoryDays) days.")
    }
    
    [void]$historyContent.AppendLine("")
    [void]$historyContent.AppendLine("=" * 100)
    [void]$historyContent.AppendLine("DEPLOYMENT LOGS")
    [void]$historyContent.AppendLine("=" * 100)
    [void]$historyContent.AppendLine("")
    
    if ($deploymentLogs.Count -gt 0) {
        foreach ($logLine in $deploymentLogs) {
            if ($logLine -match 'ERROR|Error|error') {
                if ($logLine -match '(0x[0-9A-Fa-f]+)') {
                    $errorCode = $matches[1]
                    $humanError = Get-HumanReadableError -ErrorCode $errorCode -RawError $logLine
                    [void]$historyContent.AppendLine($logLine)
                    [void]$historyContent.AppendLine("  -> INTERPRETATION: $humanError")
                } else {
                    $humanError = Get-HumanReadableError -ErrorCode "" -RawError $logLine
                    [void]$historyContent.AppendLine($logLine)
                    [void]$historyContent.AppendLine("  -> INTERPRETATION: $humanError")
                }
            } else {
                [void]$historyContent.AppendLine($logLine)
            }
            [void]$historyContent.AppendLine("")
        }
    } else {
        [void]$historyContent.AppendLine("No deployment logs found.")
    }
    
    $historyTextBox.Text = $historyContent.ToString()
    
    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Location = New-Object System.Drawing.Point(890, 645)
    $closeButton.Size = New-Object System.Drawing.Size(80, 25)
    $closeButton.Text = "Close"
    $closeButton.Add_Click({ $historyForm.Close() })
    
    $historyForm.Controls.Add($historyTextBox)
    $historyForm.Controls.Add($closeButton)
    
    [void]$historyForm.ShowDialog()
})

# Clear
$clearButton.Add_Click({
    $resultsGrid.Rows.Clear()
    $statusLabel.Text = "Results cleared"
})

# Export
$exportButton.Add_Click({
    if ($resultsGrid.Rows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No data to export.", "Export", "OK", "Warning")
        return
    }
    
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV files (*.csv)|*.csv"
    $saveDialog.FileName = "Win11_Deployment_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    if ($saveDialog.ShowDialog() -eq "OK") {
        try {
            $csvData = @()
            foreach ($row in $resultsGrid.Rows) {
                $csvData += [PSCustomObject]@{
                    Computer = $row.Cells["Computer"].Value
                    ConnectionStatus = $row.Cells["Status"].Value
                    ConnectionMethod = $row.Cells["Method"].Value
                    BatteryCount = $row.Cells["BatteryCount"].Value
                    BatteryLevel = $row.Cells["BatteryLevel"].Value
                    Charging = $row.Cells["Charging"].Value
                    TaskExists = $row.Cells["TaskExists"].Value
                    TaskState = $row.Cells["TaskState"].Value
                    CheckInterval = $row.Cells["CheckInterval"].Value
                    Threshold = $row.Cells["Threshold"].Value
                    ForceMode = $row.Cells["ForceMode"].Value
                    LastRun = $row.Cells["LastRun"].Value
                    LastResult = $row.Cells["LastResult"].Value
                    LastChecked = $row.Cells["LastChecked"].Value
                }
            }
            
            $csvData | Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show("Data exported to:`n$($saveDialog.FileName)", "Export Successful", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error exporting: $($_.Exception.Message)", "Export Error", "OK", "Error")
        }
    }
})

#endregion

Write-Host "Starting Windows 11 Deployment Manager..." -ForegroundColor Cyan
Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Package ID: $($script:PackageID)" -ForegroundColor Gray
Write-Host "  Deployment Type: $($script:DeploymentType)" -ForegroundColor Gray
Write-Host "  Battery Threshold: $($script:BatteryThreshold)%" -ForegroundColor Gray
Write-Host "  Check Interval: $($script:DefaultCheckInterval) minutes" -ForegroundColor Gray
Write-Host ""

[void]$form.ShowDialog()
