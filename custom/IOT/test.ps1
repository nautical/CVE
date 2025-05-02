
param (
    [string]$ComPort = "COM1",
    [int]$BaudRate = 9600,
    [string]$Parity = "Even",
    [int]$DataBits = 7,
    [int]$StopBits = 2,
    [switch]$LogToFile = $false,
    [string]$LogFilePath = "rs232c_log.txt"
)

# Constants for STX/ETX characters
$STX = [char]0x02
$ETX = [char]0x03
$ENQ = [char]0x05
$ACK = [char]0x06
$NAK = [char]0x15

# Create a serial port object
try {
    $port = New-Object System.IO.Ports.SerialPort
    $port.PortName = $ComPort
    $port.BaudRate = $BaudRate
    $port.Parity = $Parity
    $port.DataBits = $DataBits
    $port.StopBits = $StopBits
    $port.ReadTimeout = 500
    $port.Open()

    Write-Host "Serial port $ComPort opened successfully"
    Write-Host "Settings: $BaudRate baud, $Parity parity, $DataBits data bits, $StopBits stop bits"
    Write-Host "Press Ctrl+C to exit"
    Write-Host "Monitoring for RS-232C commands..."
    Write-Host "-----------------------------------------"

    if ($LogToFile) {
        "RS-232C Monitor Log - $(Get-Date)" | Out-File -FilePath $LogFilePath
        "Settings: $ComPort, $BaudRate baud, $Parity parity, $DataBits data bits, $StopBits stop bits" | Out-File -FilePath $LogFilePath -Append
        "-----------------------------------------" | Out-File -FilePath $LogFilePath -Append
    }

    # Buffer for command collection
    $commandBuffer = New-Object System.Text.StringBuilder
    $inCommand = $false

    # Main monitoring loop
    while ($true) {
        try {
            # Check if there's data to read
            if ($port.BytesToRead -gt 0) {
                $byte = $port.ReadByte()
                $char = [char]$byte
                
                # For debugging: Show all characters
                # Write-Host "Received: $char (Hex: 0x$('{0:X2}' -f $byte))"
                
                # Process the character
                if ($char -eq $STX) {
                    # Start of command
                    $commandBuffer.Clear()
                    $inCommand = $true
                    $commandBuffer.Append("<STX>")
                }
                elseif ($char -eq $ETX -and $inCommand) {
                    # End of command
                    $commandBuffer.Append("<ETX>")
                    $inCommand = $false
                    
                    # Display the complete command
                    $command = $commandBuffer.ToString()
                    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                    
                    # Extract command number if possible
                    $cmdNumber = "Unknown"
                    if ($command -match "<STX>(\d{4})") {
                        $cmdNumber = $matches[1]
                    }
                    
                    $output = "[$timestamp] Command: $cmdNumber | Raw: $command"
                    Write-Host $output -ForegroundColor Green
                    
                    if ($LogToFile) {
                        $output | Out-File -FilePath $LogFilePath -Append
                    }
                }
                elseif ($inCommand) {
                    # Within command - add to buffer
                    $commandBuffer.Append($char)
                }
                elseif ($char -eq $ENQ) {
                    Write-Host "[$timestamp] Control: <ENQ> (Enquiry)" -ForegroundColor Yellow
                    if ($LogToFile) {
                        "[$timestamp] Control: <ENQ> (Enquiry)" | Out-File -FilePath $LogFilePath -Append
                    }
                }
                elseif ($char -eq $ACK) {
                    Write-Host "[$timestamp] Control: <ACK> (Acknowledge)" -ForegroundColor Yellow
                    if ($LogToFile) {
                        "[$timestamp] Control: <ACK> (Acknowledge)" | Out-File -FilePath $LogFilePath -Append
                    }
                }
                elseif ($char -eq $NAK) {
                    Write-Host "[$timestamp] Control: <NAK> (Negative Acknowledge)" -ForegroundColor Red
                    if ($LogToFile) {
                        "[$timestamp] Control: <NAK> (Negative Acknowledge)" | Out-File -FilePath $LogFilePath -Append
                    }
                }
            }
            else {
                # No data available, sleep briefly to reduce CPU usage
                Start-Sleep -Milliseconds 10
            }
        }
        catch [System.IO.IOException] {
            # Timeout or other IO exception
            # Just continue the loop
        }
        catch {
            Write-Host "Error: $_" -ForegroundColor Red
            if ($LogToFile) {
                "Error: $_" | Out-File -FilePath $LogFilePath -Append
            }
        }
    }
}
catch {
    Write-Host "Failed to open serial port: $_" -ForegroundColor Red
}
finally {
    # Clean up
    if ($port -ne $null -and $port.IsOpen) {
        $port.Close()
        Write-Host "Serial port closed"
    }
} 
