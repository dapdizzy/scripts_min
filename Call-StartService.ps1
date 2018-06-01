$commonps1Path = (join-path (Split-Path -Parent $MyInvocation.MyCommand.Path) "Common.ps1")
$c = . $commonps1Path

Call-StartService $args[0] $args[1]