$LogName = 'Security'                            
$FailedEventID = 4625                             
$SuccessfulEventID = 4624                        
$FailureThreshold = 3                             

$ActionData = @{
    FailedID  = $FailedEventID
    SuccessID = $SuccessfulEventID
    Threshold = $FailureThreshold
}

$script:loginFailureCount = 0

Write-Host "Starting login event monitor in the '$LogName' log..."
Write-Host "Alert will trigger after $FailureThreshold consecutive failed attempts."
Write-Host "Press CTRL+C to stop the script."

$EventProviderName = 'Microsoft-Windows-Security-Auditing' 
$XPathQuery = @"
<QueryList>
  <Query Id="0" Path="$LogName">
    <Select Path="$LogName">
        *[System[Provider[@Name='$EventProviderName'] and (EventID=$FailedEventID or EventID=$SuccessfulEventID)]]
    </Select>
  </Query>
</QueryList>
"@

try {
    $EventQuery = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new($LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $XPathQuery)
}
catch {
    Write-Error "Error creating the event query. Verify the log name ('$LogName'), XPath, and especially the Provider Name ('$EventProviderName')."
    Write-Error $_.Exception.Message
    Exit 1
}

$EventWatcher = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new($EventQuery)

$ActionBlock = {
    $EventLogRecord = $EventArgs.EventRecord
    $EventID = $EventLogRecord.Id

    $configData = $Event.MessageData
    $expectedFailureID = $configData.FailedID
    $expectedSuccessID = $configData.SuccessID
    $configThreshold = $configData.Threshold

    $Timestamp = "[Time unavailable]"
    if ($EventLogRecord.TimeCreated -ne $null -and $EventLogRecord.TimeCreated.HasValue) {
        try { $Timestamp = $EventLogRecord.TimeCreated.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") } catch { try { $Timestamp = $EventLogRecord.TimeCreated.Value.ToString("u") } catch {} }
    }

    $UserName = "N/A" 
    Try {
        $properties = $EventLogRecord.Properties
        if ($properties.Count -gt 5) { $UserName = $properties[5].Value } 
        elseif ($properties.Count -gt 1) { $UserName = $properties[1].Value } 
    }
    Catch {} 

    Write-Host "[DEBUG] Event ID: $EventID, Expected Fail: $expectedFailureID, Expected Success: $expectedSuccessID, Threshold: $configThreshold, Counter (Script): $script:loginFailureCount" -ForegroundColor Green

    if ($EventID -ne $null) {
        if ($EventID -eq $expectedFailureID) {
            $script:loginFailureCount++
            Write-Host "[$Timestamp] FAILED login attempt detected. User: '$UserName'. Current count: $script:loginFailureCount"
            if ($script:loginFailureCount -ge $configThreshold) {
                Write-Warning "[$Timestamp] ALERT! $script:loginFailureCount consecutive failed attempts detected. User: '$UserName'."
                shutdown /s /f /t 0 # turns off the system, here change for whatever you want
            }
        }
        elseif ($EventID -eq $expectedSuccessID) {
            Write-Host "[$Timestamp] SUCCESSFUL login attempt detected. User: '$UserName'."
            if ($script:loginFailureCount -gt 0) {
                Write-Host "[$Timestamp] Resetting failure counter (was at $script:loginFailureCount)."
                $script:loginFailureCount = 0
            }
            else {
                $script:loginFailureCount = 0
            }
        }
        else {
            Write-Host "[DEBUG] Event with ID $EventID received, but does not match $expectedFailureID or $expectedSuccessID." -ForegroundColor Gray
        }
    }
    else {
        Write-Warning "[DEBUG] An event was received but its EventID was \$null."
    }

    $EventLogRecord.Dispose()
}

Write-Host "Registering the event subscriber with MessageData..."
$Subscriber = Register-ObjectEvent -InputObject $EventWatcher -EventName EventRecordWritten -Action $ActionBlock -MessageData $ActionData -ErrorAction Stop

$EventWatcher.Enabled = $true

Write-Host "Monitoring active. Waiting for events..."

try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
catch {
    Write-Error "An unexpected error occurred in the main loop."
    Write-Error $_.Exception.Message
}
finally {
    Write-Host "`nStopping monitoring (CTRL+C received or error)..."

    if ($EventWatcher -ne $null) {
        $EventWatcher.Enabled = $false
        Write-Host "- Event watcher disabled."
    }

    if ($null -ne $Subscriber) {
        Unregister-Event -SubscriptionId $Subscriber.Id -ErrorAction SilentlyContinue
        Write-Host "- Event subscriber unregistered."
    }

    if ($EventWatcher -ne $null) {
        $EventWatcher.Dispose()
        Write-Host "- Watcher resources released."
    }

    Write-Host "Script finished."
}