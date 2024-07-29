# github.com/spencershepard

# This script will determine if the current user can write to the binary of any scheduled tasks. 
# If a low privileged user can write to a binary, they can potentially escalate their privileges.

# To-do:  Display the task name and the user it runs as, if different from the current user.

if ($args -contains "-v") {
    $verbose = $true
}

$currentUser = whoami

Write-Host "Starting Scheduled Tasks vulnerability scanner for user $currentUser" -ForegroundColor Blue
Write-Host ""

# Get the tasks
$scheduledTasks = schtasks /query /v /fo csv | ConvertFrom-Csv

function getTaskPath($taskToRun) {
    # Remove arguements from the binary path (split strings on whitespace followed by / or - or $(
    $binaryPath = $taskToRun -split '\s+[-/$\(]' | Select-Object -First 1

    # Remove stray quotes
    $binaryPath = $binaryPath -replace '"', ''

    # Skip if not a real path
    if ($binaryPath -notmatch ".*\\.*") {
        if ($verbose) {
            Write-Host "Skipping 'Task To Run' $binaryPath as it is not a valid path"
        }
        return $null
    }

    $binaryPath = $binaryPath.Trim()

    return $binaryPath

}

$paths = @()

foreach ($task in $scheduledTasks) {

    $binaryPath = getTaskPath($task.'Task To Run')

    # Add the binary path to the list if not already in it
    if ($binaryPath -notin $paths) {
        $paths += $binaryPath
        if ($verbose) {
            Write-Host "Unique binary path:" $binaryPath
        }
    }

}

Write-Host "Found" $paths.Length "unique binary paths. Testing if any are writable..."
Write-Host ""

$writeablePaths = @()

# Check if the binary is writable by the current user
foreach ($path in $paths) {
    Try {
        [io.file]::OpenWrite($path).close()
        Write-Host "Binary $path is writable by $currentUser"
        Write-Host ""
        $writeablePaths += $path
    }
    Catch {  }
}

if ($writeablePaths.Length -eq 0) {
    Write-Host "No writable binaries found" -ForegroundColor Red
    Exit 1
}

Write-Host "Found" $writeablePaths.Length "writable binaries.  If the scheduled tasks run as a higher privileged user, this is exploitable. Checking..."
Write-Host ""


function tasksFromPath($path) {
    $tasks = @()
    foreach ($task in $scheduledTasks) {
        $taskpath = getTaskPath($task.'Task To Run')
        if ($taskpath -eq $path) {
            $tasks += $task
        }
    }
    return $tasks
}


$exploitableTasks = @()

foreach ($path in $writeablePaths) {
    $tasks = tasksFromPath($path)
    Write-Host ""
    if ($verbose) {
        Write-Host "Binary $path is writable by $currentUser.  Checking if any tasks run it as a different user..."
    }
    foreach ($task in $tasks) {
        if ($task.'Run As User' -ne $currentUser) {
            Write-Host "You can write to the binary and the task runs as a different user. Potentially exploitable task:" -ForegroundColor Yellow
            Write-Host "Task Name:" $task.TaskName
            Write-Host "Run As User:" $task.'Run As User'
            Write-Host "Binary Path:" $path
            Write-Host ""
            $exploitableTasks += $task
        }
    }
}

if ($exploitableTasks.Length -eq 0) {
    Write-Host "No exploitable tasks found" -ForegroundColor Red
    Exit 1
}
else {
    Write-Host "Found" $exploitableTasks.Length "exploitable tasks" -ForegroundColor Green
    Exit 0
}