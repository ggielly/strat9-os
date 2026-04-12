$pipeName = "strat9"
$logFile = "C:\serial-output.log"

Write-Host "=== Serial Port Capture: $pipeName ===" -ForegroundColor Cyan
Write-Host "Log file: $logFile"
Write-Host "Waiting for VM to connect..."
Write-Host ""

# Clear log file
"" | Out-File -FilePath $logFile -Encoding ASCII

$retryCount = 0
while ($true) {
    $retryCount++
    Write-Host "[$retryCount] Attempting connection..." -NoNewline
    
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::In, [System.IO.Pipes.PipeOptions]::None)
        $pipe.Connect(3000)x-special/nautilus-clipboard
copy
file:///tmp/VMwareDnD/UNKRos/serial-capture.ps1
file:///tmp/VMwareDnD/UNKRos/serial-debug.ps1

        
        if ($pipe.IsConnected) {
            Write-Host " CONNECTED!" -ForegroundColor Green
            Write-Host "`n=== Capturing serial output ===" -ForegroundColor Green
            
            $reader = New-Object System.IO.StreamReader($pipe)
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            
            while ($pipe.IsConnected) {
                try {
                    if ($reader.Peek() -ge 0) {
                        $line = $reader.ReadLine()
                        if ($line) {
                            $timestamp = $stopwatch.Elapsed.ToString("hh\:mm\:ss\.fff")
                            $output = "[$timestamp] $line"
                            Write-Host $output
                            $output | Out-File -FilePath $logFile -Append -Encoding UTF8
                        }
                    }
                } catch {
                    Start-Sleep -Milliseconds 50
                }
            }
            
            $stopwatch.Stop()
            Write-Host "`nConnection lost at $($stopwatch.Elapsed)" -ForegroundColor Yellow
        } else {
            Write-Host " waiting" -ForegroundColor Gray
        }
    } catch {
        Write-Host " waiting" -ForegroundColor Gray
    }
    
    if ($pipe) { $pipe.Dispose() }
    Start-Sleep -Seconds 2
}
