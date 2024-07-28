# github.com/spencershepard

# This script will determine if the current user can write to the binary of any scheduled tasks. 
# If a low privileged user can write to a binary, they can potentially escalate their privileges.

# To-do:  Display the task name and the user it runs as, if different from the current user.

if ($args -contains "-v") {
    $verbose = $true
}

$currentUser = whoami

Write-Host "Starting Scheduled Tasks vulnerability scanner for user $currentUser"

# Get the tasks
$scheduledTasks = schtasks /query /v /fo csv | ConvertFrom-Csv

$paths = @()

foreach ($task in $scheduledTasks) {

    $binaryPath = $task.'Task To Run'

    # Remove arguements from the binary path (split strings on whitespace followed by / or - or $(
    $binaryPath = $binaryPath -split '\s+[-/$\(]' | Select-Object -First 1

    # Remove stray quotes
    $binaryPath = $binaryPath -replace '"', ''

    # Skip if not a real path
    if ($binaryPath -notmatch ".*\\.*") {
        if ($verbose) {
            Write-Host "Skipping 'Task To Run' $binaryPath as it is not a valid path"
        }
        continue
    }

    # Add the binary path to the list if not already in it
    if ($binaryPath -notin $paths) {
        $paths += $binaryPath
        if ($verbose) {
            Write-Host "Unique binary path:" $binaryPath
        }
    }
    
}

Write-Host "Found" $paths.Length "unique binary paths. Testing if any are writable..."

$writeablePaths = @()

# Check if the binary is writable by the current user
foreach ($path in $paths) {
    Try {
        [io.file]::OpenWrite($path).close()
        Write-Host "Binary $path is writable by $currentUser" -ForegroundColor Red
        $writeablePaths += $path
    }
    Catch {  }
}

if ($writeablePaths.Length -eq 0) {
    Write-Host "No writable binaries found" -ForegroundColor Green
    Exit 0
}

Write-Host "Found" $writeablePaths.Length "writable binaries.  If the scheduled tasks run as a higher privileged user, this is exploitable."

Exit 1