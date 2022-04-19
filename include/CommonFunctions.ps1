function Get-RDPEventsForUser ($server, $user,$daysToGoBack)
{
	If (!($daysToGoBack))
	{
		Get-WinEvent -ComputerName $server -LogName Microsoft-Windows-TerminalServices-LocalSessionManager/OperatiWhere-Object| <BS><BS><BS><BS><BS><BS><BS><BS>_.ID -match "21|23|24|25" -and $_.Message -match "$user"
	}
	Else
	{
		$startDate = (Get-Date) - (New-TimeSpan -Days $daysToGoBack)
		Get-WinEvent -ComputerName $server -LogName Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | Where-Object {$_.ID -match "21|23|24|25" -and $_.Message -match "$user" -and $_.TimeCreated -ge $startDate}
	}
}

Function Invoke-WindowsFeatureInstall($serverName,$windowsFeatureName)
    {
        $Error.Clear()
        $WindowsFeatures = Invoke-Command -ComputerName $servername { param ($windowsFeatureName);Get-WindowsFeature $windowsFeatureName } -ArgumentList $windowsFeatureName
        Foreach ($WindowsFeature in $WindowsFeatures)
            {
                If (!($WindowsFeature.InstallState -eq "Installed"))
                    {
                        Write-Host "$(Get-date -Format t) --> $servername - Installing $windowsFeatureName ..."
                        $retVal = Invoke-Command -ComputerName $servername { param ($windowsFeature);Install-WindowsFeature $WindowsFeature.Name } -ArgumentList $WindowsFeature
                        If ($retVal.ExitCode -match "Success")
                            {
                                Write-Host "$(Get-date -Format t) --> $servername - $($WindowsFeature.DisplayName) installed successfully ($($retval.ExitCode))"
                            }
                        Else
                            {
                                ErrorHandle -Error $Error -blnTerminate $false -EntryType $ErrorLogType -EventID $ErrorLogID -evtMessage ""
                            }
                    }
                Else
                    {
                        Write-Host "$(Get-date -Format t) --> $servername - $($WindowsFeature.DisplayName) already installed"
                    }
            }
    }


Function Invoke-WindowsFeatureUnInstall($serverName,$windowsFeatureName)
    {
        $Error.Clear()
        $WindowsFeatures = Invoke-Command -ComputerName $servername { param ($windowsFeatureName);Get-WindowsFeature $windowsFeatureName } -ArgumentList $windowsFeatureName
        Foreach ($WindowsFeature in $WindowsFeatures)
            {
                If (!($WindowsFeature.InstallState -eq "Installed"))
                    {
                        Write-Host "$(Get-date -Format t) --> $servername - UnInstalling $windowsFeatureName ..."
                        $retVal = Invoke-Command -ComputerName $servername { param ($windowsFeature);UnInstall-WindowsFeature $WindowsFeature.Name } -ArgumentList $WindowsFeature
                        If ($retVal.ExitCode -match "Success")
                            {
                                Write-Host "$(Get-date -Format t) --> $servername - $($WindowsFeature.DisplayName) uninstalled successfully ($($retval.ExitCode))"
                            }
                        Else
                            {
                                ErrorHandle -Error $Error -blnTerminate $false -EntryType $ErrorLogType -EventID $ErrorLogID -evtMessage ""
                            }
                    }
                Else
                    {
                        Write-Host "$(Get-date -Format t) --> $servername - $($WindowsFeature.DisplayName) already uninstalled"
                    }
            }
    }
    
    Function Get-CustomWarnErrEventByIndex($server,$eventLog,$previousIndexValue,$eventIndexFile,$serverEventsFile)
    {
        $events = Invoke-Command -ComputerName $server { param($eventlog,$previousIndexValue);Get-EventLog -LogName $eventLog -EntryType Warning,Error | Where-Object {$_.Index -gt $previousIndexValue} } -ArgumentList $eventLog,$previousIndexValue
        If ($events)
            {
                If ($eventIndexFile)
                    {
                        $lastEvent = $events | Select-Object -First 1
                        $lastIndexLogged = $lastEvent.Index
                        $events | Where-Object {$_.Source -ne 'LsaSrv' -and $_.EventID -ne 6037} | Sort-Object TimeGenerated | Export-Csv -Path $serverEventsFile -NoTypeInformation -Append
                        Set-Content -Path $eventIndexFile -Value "$lastIndexLogged,$eventLog"
                    }
                Else
                    {
                        $events
                    }
            }
        Else
            {
                Write-Host "$(Get-Date -Format t) --> $($server.ToUpper()) : No new Warning|Error events in the $EventLog log found after Index value $previousIndexValue"
            }
        Clear-variable previousIndexValue
        Clear-Variable events
        Clear-Variable lastEvent
        Clear-Variable lastIndexLogged
    }
    
    Function Get-CustomEventSummary($serverName,$LogName,$AfterDateTime)
    {
        Foreach ($server in $serverName)
            {
                If ($AfterDateTime.Gettype().Name -ne "DateTime") { $AfterDateTime = [datetime]"$AfterDateTime" }
                $timeframe = (New-TimeSpan -Start $AfterDateTime -End (get-date)).TotalHours
                Foreach ($log in $logName)
                    {
                        Write-Host "$($server.ToUpper())\$Log Log Events - previous $([math]::Round($timeframe,2)) hours" -ForegroundColor Green
                        Write-Host "-------------------------------------------------------"
                        Invoke-Command -ComputerName $server `
                                                        { 
                                                            param($Log,$AfterDateTime)
                                                            Get-EventLog -LogName $Log -After $AfterDateTime | Where-Object {$_.EntryType -match "Warning|Critical"} | Group-Object EntryType,Source | Sort-Object Count -Descending | Format-Table -AutoSize `
                                                        } -ArgumentList $Log,$AfterDateTime
                                                        Clear-Variable serverName
                    }
            }
    }

Function Get-CustomWarnErrEventByIndex($server,$eventLog,$previousIndexValue,$eventIndexFile,$serverEventsFile)
    {
        $events = Invoke-Command -ComputerName $server { param($eventlog,$previousIndexValue);Get-EventLog -LogName $eventLog -EntryType Warning,Error | Where-Object {$_.Index -gt $previousIndexValue} } -ArgumentList $eventLog,$previousIndexValue
        If ($events)
            {
                If ($eventIndexFile)
                    {
                        $lastEvent = $events | Select-Object -First 1
                        $lastIndexLogged = $lastEvent.Index
                        $events | Where-Object {$_.Source -ne 'LsaSrv' -and $_.EventID -ne 6037} | Sort-Object TimeGenerated | Export-Csv -Path $serverEventsFile -NoTypeInformation -Append
                        Set-Content -Path $eventIndexFile -Value "$lastIndexLogged,$eventLog"
                    }
                Else
                    {
                        $events
                    }
            }
        Else
            {
                Write-Host "$(Get-Date -Format t) --> $($server.ToUpper()) : No new Warning|Error events in the $EventLog log found after Index value $previousIndexValue"
            }
        Clear-variable previousIndexValue
        Clear-Variable events
        Clear-Variable lastEvent
        Clear-Variable lastIndexLogged
    }    
    
    Function Get-CustomServerRebootEvents($serverName,$hoursToGoBack)
    {
        Foreach ($server in $serverName)
            {
                Write-Host $server -ForegroundColor Green
                Write-Host "---------"
                $afterDate = (get-date).AddHours(-$hoursToGoBack)
                [array]$ServerRebootEvents = Invoke-Command -ComputerName $server `
                                    { 
                                        param($afterDate)
                                        Get-EventLog -LogName System -After $afterDate | Where-Object {$_.EventID -eq 6009}
                                    } -ArgumentList $afterDate
                If (!($ServerRebootEvents))
                    {
                        Write-Host "$server has not been rebooted in the past $hoursToGoBack hours`n"
                    }
                Else
                    {
                        $ServerRebootEvents | ForEach-Object {$_}
                        Write-Host "`n"
                        #Write-Host "$server has been rebooted $($ServerRebootEvents.Count) time(s) the past $hoursToGoBack hours`n" -ForegroundColor Yellow
                    }
                Clear-Variable ServerRebootEvents
            }
        Write-Host "-------------------------------------------------------"
    }
    
    Function Get-CustomLogicalDiskFreeSpace($ServerName)
    {
        Foreach ($server in $ServerName)
            {
                Write-Host $server -ForegroundColor Green
                Write-Host "---------"
                $logicalDisks = Get-WmiObject -ComputerName $server Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3}
                foreach ($logicalDisk in $logicalDisks) 
                    { 
                        $driveSize = $logicalDisk.Size
                        $freespace = $logicalDisk.FreeSpace
                        i# $totalfreespace = $driveSize - $freespace
                        $percentFree = ($freespace / $drivesize)*100
                        If ($percentFree -le 15 -and $percentFree -ge 11)
                            {
                                Write-Host "Drive $($logicalDisk.DeviceID) has $([math]::Round($percentFree))% free space" -ForegroundColor Yellow
                                #Write-Host "Drive $($logicalDisk.DeviceID) has $("{0:N0}" -f ($logicalDisk.FreeSpace / 1024 / 1024)) MB free"
                            }
                        ElseIf ($percentFree -le 10 -and $percentFree -ge 0)
                            {
                                Write-Host "Drive $($logicalDisk.DeviceID) has $([math]::Round($percentFree))% free space" -ForegroundColor Red
                                #Write-Host "Drive $($logicalDisk.DeviceID) has $("{0:N0}" -f ($logicalDisk.FreeSpace / 1024 / 1024)) MB free"
                            }
                        Else
                            {
                                Write-Host "Drive $($logicalDisk.DeviceID) has $([math]::Round($percentFree))% free space"
                                #Write-Host "Drive $($logicalDisk.DeviceID) has $("{0:N0}" -f ($logicalDisk.FreeSpace / 1024 / 1024)) MB free"
                            }
                    }
                Write-Host ""
            }
        Write-Host "-------------------------------------------------------"
    }
    
    Function Get-CustomServiceRestartEvents($serviceName,$serverName,$hoursToGoBack)
    {
        Foreach ($server in $serverName)
            {
                Write-Host $server -ForegroundColor Green
                Write-Host "---------"
                Foreach ($service in $serviceName)
                    {
                        $svcDisplayName = (Get-Service -ComputerName $server -Name $service).DisplayName
                        $afterDate = (get-date).AddHours(-$hoursToGoBack)
                        $restartEvents = Invoke-Command -ComputerName $server `
                                                        { 
                                                           param($afterDate,$svcDisplayName)
                                                           Get-EventLog -LogName System -After $afterDate -Source "Service Control Manager" `
                                                           | Where-Object {$_.Message -match "The $svcDisplayName service entered" } } -ArgumentList $afterDate,$svcDisplayName
                        If (!($restartEvents))
                            {
                                Write-Host "There were no start/stop events for '$service' in the past $hoursToGoBack hours"
                            }
                        Else
                            {
                                $restartEvents | ForEach-Object {$_}
                            }
                    }
            }
        Write-Host "-------------------------------------------------------"
    }
    
    Function Get-CustomServiceStatus($serviceName,$serverName)
    {
        Foreach ($server in $serverName)
            {
                Write-Host $server -ForegroundColor Green
                Write-Host "---------"
                Foreach ($service in $serviceName)
                    {
                        [string]$svcStatus = (Get-Service -ComputerName $server -Name $service).Status
                        If ($svcStatus -eq "Running")
                            {
                                Write-Host "'$service' service is $($svcStatus.ToUpper())"
                            }
                        Else
                            {
                                 Write-Host "'$service' service is $($svcStatus.ToUpper())" -ForegroundColor Red
                            }
                    }
            }
        Write-Host "-------------------------------------------------------"
    }

Function Get-CustomPercentMemoryUsed($serverName)
    {
        Foreach ($server in $serverName)
            {
                $installedMemory = [math]::Round((Get-WmiObject -ComputerName $server Win32_OperatingSystem).TotalVisibleMemorySize / 1024)
                $metric = (Get-Counter -ComputerName $server -Counter "\Memory\Available MBytes").CounterSamples.CookedValue
                $percent = [math]::Round(($metric/$installedMemory) * 100,0)
                Write-Host $server -ForegroundColor Green
                Write-Host "---------"
                $percentmemused = $(100 - $percent)
                If ($percentmemused -ge 80 -and $percentmemused -le 89)
                    {
                        Write-Host "Percent Memory Used - $percentmemused%`n" -ForegroundColor Yellow
                    }
                ElseIf ($percentmemused -ge 90 -and $percentmemused -le 100)
                    {
                        $isSQLServer = Get-WmiObject -ComputerName $server Win32Reg_AddRemovePrograms | Where-Object {$_.DisplayName -match "Database Engine Services"}
                        If (!($isSQLServer))
                            {
                                Write-Host "Percent Memory Used - $percentmemused%`n" -ForegroundColor Red
                            }
                        Else
                            {
                                Write-Host "Percent Memory Used - $percentmemused% (SQL Server)`n"
                            }
                    }
                Else
                    {
                        Write-Host "Percent Memory Used - $percentmemused%`n"
                    }
            }
        Write-Host "-------------------------------------------------------"
    }

Function Get-CustomPerfMonCounters($serverName,$CounterName,$intInterval)
    {
        Switch ($CounterName)
            {
                "\Memory\PercentUsed"
                    {
                        $installedMemory = [math]::Round((Get-WmiObject -ComputerName $serverName Win32_OperatingSystem).TotalVisibleMemorySize / 1024)
                        For ($i = 1;$i -le $intInterval;$i++)
                            {
                                $metric = (Get-Counter -ComputerName $serverName -Counter "\Memory\Available MBytes").CounterSamples.CookedValue
                                $percent = [math]::Round(($metric/$installedMemory) * 100,2)
                                Write-Host "$(Get-date -Format t) : $serverName\Percent Memory Used - $(100 - $percent)%"
                            }
                    }
                Default
                    {
                        For ($i = 1;$i -le $intInterval;$i++)
                            {
                                $metric = (Get-Counter -ComputerName $serverName -Counter $CounterName).CounterSamples.CookedValue
                                Write-Host "$(Get-date -Format t) : $serverName$CounterName - $([math]::Round($metric,2))"
                            }
                    }
            }
    }
    
#### Script Functions
    
    
    Function ErrorHandle($Error,$blnTerminate,$EntryType,$EventID)
	{
		$LogName = "Application"
        If ($Error.Count -ne 0)
			{
		        $ErrorPositionMessage = $Error.InvocationInfo.PositionMessage
				$errMessage = "Error Message: $Error.Exception.Message`n$ErrorPositionMessage"
				Write-EventLog -LogName $LogName -EntryType $EntryType -EventId $EventID -Source $EventSource -Message $errMessage
		        If ($blnTerminate -eq $True) { Exit }
			}
	}

#### Utility Functions


function Get-Permissions ($folder) {
    (get-acl $folder).access | S `
          @{Label="Identity";Expression={$_.IdentityReference}}, `
          @{Label="Right";Expression={$_.FileSystemRights}}, `
          @{Label="Access";Expression={$_.AccessControlType}}, `
          @{Label="Inherited";Expression={$_.IsInherited}}, `
          @{Label="Inheritance Flags";Expression={$_.InheritanceFlags}}, `
          @{Label="Propagation Flags";Expression={$_.PropagationFlags}} | Format-Table -auto
          }
          
##SVN. Did I mention I dislike working with SVN?

Function Get-SVNFileStatus($path)
    {
		$Error.Clear()
		Write-Host "$(Get-date -Format t) --> Checking for uncommitted changes in $path ..."
        $svnFileStatusResults = @(Invoke-Command { svn status $path })

        If (!($Error))
            {
                If (!($svnFileStatusResults) -or $svnFileStatusResults -like "?       *\ibi\apps")
                    {
                        $resultsMessage = "No changes detected in path $path"
                        Write-Host "$(Get-date -Format t) --> $resultsMessage" -ForegroundColor Green
                    }
                Else
                    {
                        $resultsMessage = "$($svnFileStatusResults.Count) change(s) detected in path $path`nResolve these changes before proceeding with script."
                        Write-Host "$(Get-date -Format t) --> $resultsMessage" -ForegroundColor Yellow
                        Exit
                    }
                
                Clear-Variable svnFileStatusResults
            }
        Else
            {
                ErrorHandle -Error $Error -blnTerminate $true -EntryType $ErrorLogType -EventID $ErrorLogID
            }
    }