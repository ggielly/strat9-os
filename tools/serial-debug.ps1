$pipeName = "strat9"

Write-Host "=== Serial Port Debugger for strat9-os ===" -ForegroundColor Cyan
Write-Host "Pipe: \\.\pipe\$pipeName"
Write-Host "Retrying connection until VM creates pipe..."
Write-Host "Press Ctrl+C to stop`n"

$connected = $false
$attempts = 0
$maxAttempts = 300

while (-not $connected -and $attempts -lt $maxAttempts) {
    $attempts++
    Write-Host "Connection attempt $attempts/$maxAttempts..." -NoNewline
    
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::In, [System.IO.Pipes.PipeOptions]::Asynchronous)
        $pipe.Connect(2000)
        
        if ($pipe.IsConnected) {
            $connected = $true
            Write-Host " SUCCESS!" -ForegroundColor Green
            Write-Host "`n=== Connected to serial port! Capturing boot output ===`n" -ForegroundColor Green
            
            $reader = New-Object System.IO.StreamReader($pipe)
            $buffer = New-Object char[] 1024
            
            while ($pipe.IsConnected) {
                try {
                    $bytesRead = $reader.Read($buffer, 0, $buffer.Length)
                    if ($bytesRead -gt 0) {
                        $output = -join $buffer[0..($bytesRead-1)]
                        Write-Host $output -NoNewline
                    }
                } catch {
                    Start-Sleep -Milliseconds 100
                }
            }
            
            Write-Host "`n`nDisconnected from serial port." -ForegroundColor Yellow
        } else {
            Write-Host " waiting..." -ForegroundColor Yellow
        }
    } catch {
        Write-Host " waiting..." -ForegroundColor Yellow
    }
    
    if (-not $connected) {
        if ($pipe) { $pipe.Dispose() }
        Start-Sleep -Seconds 1
    }
}

if (-not $connected) {
    Write-Host "`nTimeout: Could not connect to pipe. Check VMware serial port configuration." -ForegroundColor Red
}
