# Copyright (c) Microsoft 
# All rights reserved.
# Microsoft Limited Public License:
# This license governs use of the accompanying software. If you use the software, you 
# accept this license. If you do not accept the license, do not use the software.
# 1. Definitions 
# The terms "reproduce," "reproduction," "derivative works," and "distribution" have the 
# same meaning here as under U.S. copyright law. 
# A "contribution" is the original software, or any additions or changes to the software. 
# A "contributor" is any person that distributes its contribution under this license. 
# "Licensed patents" are a contributor's patent claims that read directly on its contribution.
# 2. Grant of Rights 
# (A) Copyright Grant- Subject to the terms of this license, including the license conditions and limitations in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free copyright license to reproduce its contribution, prepare derivative works of its contribution, and distribute its contribution or any derivative works that you create. 
# (B) Patent Grant- Subject to the terms of this license, including the license conditions and limitations in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free license under its licensed patents to make, have made, use, sell, offer for sale, import, and/or otherwise dispose of its contribution in the software or derivative works of the contribution in the software.
# 3. Conditions and Limitations 
# (A) No Trademark License- This license does not grant you rights to use any contributors' name, logo, or trademarks. 
# (B) If you bring a patent claim against any contributor over patents that you claim are infringed by the software, your patent license from such contributor to the software ends automatically. 
# (C) If you distribute any portion of the software, you must retain all copyright, patent, trademark, and attribution notices that are present in the software. 
# (D) If you distribute any portion of the software in source code form, you may do so only under this license by including a complete copy of this license with your distribution. If you distribute any portion of the software in compiled or object code form, you may only do so under a license that complies with this license. 
# (E) The software is licensed "as-is." You bear the risk of using it. The contributors give no express warranties, guarantees or conditions. You may have additional consumer rights under your local laws which this license cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties of merchantability, fitness for a particular purpose and non-infringement.
# (F) Platform Limitation - The licenses granted in sections 2(A) and 2(B) extend only to the software or derivative works that you create that run on a Microsoft Windows operating system product.

#File version: 1.0.2.0
function Get-OverrideParameters
{
    $RunDeployParmFile = (Join-Path $AxBuildDir "OverrideParameters.txt")
    if ((Test-Path $RunDeployParmFile) -ne $false)
    {
        $fileContent = Get-Content $RunDeployParmFile
        foreach ($line in $fileContent)
        {
            $line = $line.split("=")
            [System.Environment]::SetEnvironmentVariable($line[0],$line[1])     
        }       
    }   
    
    <#$script:CompileCILTimeout        = [int](Set-Parameter "CompileCILTimeout" "60" )
    $script:SyncTimeout              = [int](Set-Parameter "SyncTimeout" "60" )
    $script:ImportTimeout            = [int](Set-Parameter "ImportTimeout" "60" )
    $script:CombineTimeout           = [int](Set-Parameter "CombineTimeout" "60" )
    $script:AOSRestartTimeout        = [int](Set-Parameter "AOSRestartTimeout" "60" )
    $script:CompileAllTimeout        = [int](Set-Parameter "CompileAllTimeout" "360" )
    $script:SetupRegistryPath        = (Set-Parameter "SetupRegistryPath" "HKLM:\SOFTWARE\Microsoft\Dynamics\6.0\Setup" )
    $script:ServerRegistryPath       = (Set-Parameter "ServerRegistryPath" "HKLM:\SYSTEM\CurrentControlSet\services\Dynamics Server\6.0" )
    $script:ClientRegistryPath       = (Set-Parameter "ClientRegistryPath" "HKCU:\SOFTWARE\Microsoft\Dynamics\6.0\Configuration" )
    $script:labelsFolder             = (Set-Parameter "LabelsFolder" "label files" )#>
}

function Get-DefaultParameters
{
    $script:CompileCILTimeout        = [int](Set-Parameter "CompileCILTimeout" "60" )
    $script:SyncTimeout              = [int](Set-Parameter "SyncTimeout" "60" )
    $script:ImportTimeout            = [int](Set-Parameter "ImportTimeout" "60" )
    $script:CombineTimeout           = [int](Set-Parameter "CombineTimeout" "60" )
    $script:AOSRestartTimeout        = [int](Set-Parameter "AOSRestartTimeout" "60" )
    $script:CompileAllTimeout        = [int](Set-Parameter "CompileAllTimeout" "360" )
    $script:SetupRegistryPath        = (Set-Parameter "SetupRegistryPath" "HKLM:\SOFTWARE\Microsoft\Dynamics\6.0\Setup" )
    $script:ServerRegistryPath       = (Set-Parameter "ServerRegistryPath" "HKLM:\SYSTEM\CurrentControlSet\services\Dynamics Server\6.0" )
    $script:ClientRegistryPath       = (Set-Parameter "ClientRegistryPath" "HKCU:\SOFTWARE\Microsoft\Dynamics\6.0\Configuration" )
    $script:labelsFolder             = (Set-Parameter "LabelsFolder" "label files" )
}

function Get-ImportOverrideParameters
{
    Write-InfoLog ("Start Get-ImportOverrideParameters : {0}" -f (Get-Date)) 
    $RunDeployParmFile = (Join-Path $AxBuildDir "ImportOverrideParameters.txt")
    if ((Test-Path $RunDeployParmFile) -ne $false)
    {
        $script:importOverrideParams = @{}

        $fileContent = Get-Content $RunDeployParmFile
        if ($fileContent -ne $null)
        {
            Write-InfoLog ("Override file content :")
            Write-InfoLog $fileContent 
            foreach ($line in $fileContent)
            {
                $line = $line.split("=")
                $importOverrideParams.Set_Item($line[0].Trim(),$line[1].Trim())
            }
        }       
    }
    
    Write-InfoLog ("Import override params:")
    Write-InfoLog $importOverrideParams
    
    Write-InfoLog ("End Get-ImportOverrideParameters : {0}" -f (Get-Date))        
}

function Set-Parameter($name, $defaultVal)
{
    $value = GetEnvironmentVariable($name)
    if($value -eq $null)
    {
        $value = $defaultVal
    }
    
    $value
}

function Write-InfoLog($message)
{
    Write-Output ($message) 
}

function Write-ErrorLog($message)
{
    Write-InfoLog (" ")
    Write-Host "ERROR: *********" -ForegroundColor Red -BackgroundColor Black
    Write-Host $message -ForegroundColor Red -BackgroundColor Black
    Write-Host "****************" -ForegroundColor Red -BackgroundColor Black
    Write-InfoLog (" ")
    
    if($transcriptStarted -eq $true)
    {
        if($scriptName -eq 'DEPLOY')
        {
            if($currentLogFolder -ne $null)
            {
                $message | out-file -append (join-path $currentLogFolder 'DeployErrors.err')
            }
        }
        else
        {
            if($dropLocation -ne $null)
            {
                $message | out-file -append (join-path $dropLocation 'BuildErrors.err')
            }
        }
    }
}

function Write-TerminatingErrorLog($message, $errorMsg)
{
    Write-ErrorLog $message
    Write-InfoLog $errorMsg
 
    if($buildModelStarted -eq $true)
    {
        $script:buildModelStarted = $false
        try
        {
            if($NoCleanOnError -ne $true)
            {
                Write-InfoLog ("                                                                 ") 
                Write-InfoLog ("*****************************************************************") 
                Write-InfoLog ("****************TRYING TO REVERT BUILD***************************") 
                Clean-Build
                Write-InfoLog ("*****************************************************************") 
                Write-InfoLog ("*****************************************************************") 
                Write-InfoLog ("                                                                 ") 
            }
        }
        catch
        {
            Write-ErrorLog ("Failed to revert build.")
            Write-ErrorLog ($Error[0])
        }
    }

    Write-InfoLog ("{0} Failed" -f $scriptName)    
    Exit
}

function Register-SQLSnapIn
{
    Write-InfoLog ("Begin: Register-SQLSnapIn: {0}" -f (Get-Date)) 
    if ( Get-PSSnapin -Registered | where {$_.name -eq 'SqlServerProviderSnapin100'} ) 
    { 
        if( !(Get-PSSnapin | where {$_.name -eq 'SqlServerProviderSnapin100'})) 
        {  
            Add-PSSnapin SqlServerProviderSnapin100 | Out-Null 
        }
        if( !(Get-PSSnapin | where {$_.name -eq 'SqlServerCmdletSnapin100'})) 
        {  
            Add-PSSnapin SqlServerCmdletSnapin100 | Out-Null 
        } 
    } 
    else 
    { 
        if( !(Get-Module | where {$_.name -eq 'sqlps'})) 
        {  
            Import-Module 'sqlps' �DisableNameChecking 
        } 
    }
    Write-InfoLog ("End: Register-SQLSnapIn: {0}" -f (Get-Date))  
}

function Check-PowerShellVersion
{
    $pv = get-host
    if($pv -ne $null -and $pv.Version -ne $null -and $pv.Version.Major -ne 2)
    {
        Write-TerminatingErrorLog ("Powershell version {0} not supported." -f $pv.Version.Major)
    }
}

function GetEnvironmentVariable($variableName)
{
    if ([System.Environment]::GetEnvironmentVariable($variableName) -ne $null)
    {
        ([System.Environment]::GetEnvironmentVariable($variableName).Trim())
    }
}

function Create-CurrentLogFolder
{
    $date = "Logs" + (Get-Date)
    $date = $date.Replace(' ', '')
    $date = $date.Replace('/', '')
    $date = $date.Replace(':', '')
    $script:currentLogFolder = (join-path $logFolder $date)
    New-Item $currentLogFolder -type directory
}

function Create-BuildFolders
{
    if ((Test-Path (Join-Path $dropLocation $currentVersion)) -eq $false) {$n = New-Item (Join-Path $dropLocation $currentVersion) -ItemType directory}
    $script:dropLocation = join-path $dropLocation $currentVersion
    if ((Test-Path (Join-Path $dropLocation "Logs")) -eq $false) {$n = New-Item (Join-Path $dropLocation "Logs") -ItemType directory}
    $script:currentLogFolder = join-path $dropLocation "Logs"
    if ((Test-Path (Join-Path $currentLogFolder "DetailedLogs")) -eq $false) {$n = New-Item (Join-Path $currentLogFolder "DetailedLogs") -ItemType directory}
    if ((Test-Path (Join-Path $dropLocation "Application")) -eq $false) {$n = New-Item (Join-Path $dropLocation "Application") -ItemType directory}
    if ((Test-Path (Join-Path $dropLocation "Application\bin")) -eq $false) {$n = New-Item (Join-Path $dropLocation "Application\bin") -ItemType directory}
    if ((Test-Path (Join-Path $dropLocation "Application\Appl")) -eq $false) {$n = New-Item (Join-Path $dropLocation "Application\Appl") -ItemType directory}
    if ((Test-Path (Join-Path $dropLocation "VSProjBin")) -eq $false) {$n = New-Item (Join-Path $dropLocation "VSProjBin") -ItemType directory}
    $script:vsProjBinFolder = join-path $dropLocation "VSProjBin"
}

function Output-LatestBuildInfo([string]$dropFolder)
{
    Write-Output (Get-LatestBuildFolder $dropFolder).Name
    Write-Output (Get-LastSuccessfulBuild $dropFolder).Name
}

function Get-LastSuccessfulBuild([string]$dropRoot)
{
    gci $dropRoot | Sort-Object CreationTime -Descending |? { Test-Path (Join-Path $_.FullName 'BuildCompleted.txt') } | Select-Object -First 1
}

function Get-LatestBuildFolder([string]$dropRoot)
{
    gci $dropRoot | Sort-Object CreationTime -Descending | Select-Object -First 1
}

function Remove-AXModelstoreOnFailedBuilds($dropFolder)
{
    foreach ($f in (gci -Path $dropFolder -Directory))
    {
        if (Test-Path -Path (Join-Path -Path $f.FullName -ChildPath 'BuildErrors.err'))
        {
            $modelstoreFolder = Join-Path -Path $f.fullName -ChildPath 'Application' | Join-Path -ChildPath 'Appl'
            Remove-Item -Path "$modelstoreFolder\*.axmodelstore" -Force -ErrorAction SilentlyContinue
        }
    }
}

function Is-BuildFolder([string]$folder)
{
    if ((Test-Path -Path (Join-Path $folder 'BuildCompleted.txt')) `
    -or (Test-Path -Path (Join-Path $folder 'BuildErrors.err')))
    {
        return $true
    }
    return $false
}

############################################################################################
#COMMON AX FUNCTIONS
############################################################################################
function Synchronize-AX($tableId = 0)
{
	Write-InfoLog ("Start synchronize : {0}" -f (Get-Date)) 
	$SynchStartTime = Get-Date 
    if ($tableId -eq 0)
    {
	   $arguments = '-lazyclassloading -lazytableloading -StartupCmd=Synchronize -internal=noModalBoxes'
    }
    else
    {
        # We make use of interpolation here
        $arguments = "-lazyclassloading -lazytableloading -StartupCmd=Synchronize_$tableId -internal=noModalBoxes"
    }   
    Write-InfoLog ("Calling Start-Process Synchronize: {0}" -f (Get-Date)) 
    $axProcess = Start-Process $ax32 -WorkingDirectory $clientBinDir -PassThru -WindowStyle minimized -ArgumentList $arguments -OutVariable out
	Write-InfoLog $out
    if ($axProcess.WaitForExit(60000*$SyncTimeout) -eq $false)
	{
		Write-ErrorLog("Error: AX synchronize did not complete within {0} minutes" -f $SyncTimeout)
		$axProcess.Kill()
		foreach($event in Get-EventLog Application | Where-Object {$_.Source -match "Dynamics Server" -and $_.EntryType -eq "Error" -and $_.Timegenerated -gt $SynchStartTime})
		{
			Write-ErrorLog($event.Message.Substring($event.Message.IndexOf('[SQL Server]')+'[SQL Server]'.get_length()))
		}
        # Fail the whole script only for the Build script
        if ($script:scriptName -eq 'BUILD')
        {
		    Write-TerminatingErrorLog("Synchronize didn't finish on time. Stopping the build")
        }
	}
	Write-InfoLog ("Synchronize finished : {0}" -f (Get-Date)) 
    Write-InfoLog (" ")
}

function Stop-WMIService($serviceName, $timeout = (5 * 60))
{
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $service = Get-WmiObject Win32_Service -ComputerName "$($env:computername)" -Filter "name=""$serviceName""" -Outvariable out -Verbose
    if ($service.State -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped)
    {
        $rv = $service.StopService().ReturnValue
        if ($rv -ne 0)
        {
            throw "An error occured during attempt to stop service $serviceName. Exit code: $rv"
        }
        Write-Host "Stopping the service $serviceName"
        $service = Get-WmiObject Win32_Service -ComputerName "$($env:computername)" -Filter "name=""$serviceName""" -Outvariable out -Verbose
        if ($service.State -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped)
        {
            <#$service = Get-WmiObject Win32_Service -ComputerName "$($env:computername)" -Filter "name=""$serviceName""" -Outvariable out -Verbose
            if ($service.State -eq [System.ServiceProcess.ServiceControllerStatus]::Running)
            {
                $rv = $service.StopService().ReturnValue
                if ($rv -ne 0)
                {
                    throw "An error occured while trying to stop service $serviceName. Exit code: $rv"
                }
            }#>
            $service = Get-WmiObject Win32_Service -ComputerName "$($env:computername)" -Filter "name=""$serviceName""" -Outvariable out -Verbose
            while ($service.State -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped)
            {
                if ($sw.Elapsed.Seconds -gt $timeout)
                {
                    throw "Service $serviceName was unable to stop in $timeout seconds"
                }
                Write-Host "Service status if $($service.State). Sleep for 20 seconds ..."
                Start-Sleep -Seconds 20
                $service = Get-WmiObject Win32_Service -ComputerName "$($env:computername)" -Filter "name=""$serviceName""" -Outvariable out -Verbose
            }
        }
    }

    $service = Get-WmiObject Win32_Service -ComputerName "$($env:computername)" -Filter "name=""$serviceName""" -Outvariable out -Verbose
    if ($service.State -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped)
    {
        Write-Host "Service $srviceName has been successfully stopped"
    }

    return 0
}

function Call-StartService($serviceName, $computername)
{
    $service = Get-WmiObject Win32_Service -ComputerName $computername -Filter "name=""$serviceName""" -Outvariable out -Verbose
    if ($service -eq $null)
    {
        throw "Service $serviceName does not exist"
    }
    $rv = 0
    if ($service.State -ne [System.ServiceProcess.ServiceControllerStatus]::Running)
    {
        $rv = $service.StartService().ReturnValue
    }
    $rv
}

function Call-StopService($serviceName, $computername)
{
    $service = Get-WmiObject Win32_Service -ComputerName $computername -Filter "name=""$serviceName""" -Outvariable out -Verbose
    if ($service -eq $null)
    {
        throw "Service $serviceName does not exist"
    }
    $rv = 0
    if ($service.State -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped)
    {
        $rv = $service.StopService().ReturnValue
    }
    $rv
}

function Get-ServiceState($serviceName, $computername)
{
    $service = Get-WmiObject Win32_Service -ComputerName $computername -Filter "name=""$serviceName""" -Outvariable out -Verbose
    if ($service -eq $null)
    {
        throw "Service $serviceName does not exist"
    }
    "$($service.State)"
}

function Stop-AOS
{
    Write-InfoLog ("Begin: Stop-AOS method : {0}" -f (Get-Date)) 
    $startDateTime = $(get-date)
    
    Write-InfoLog ("Calling Get-WmiObject Win32_Service: {0}" -f (Get-Date)) 
    $aos = Get-WmiObject Win32_Service -ComputerName $AxAOSServerName -Filter "name=""$AOSName"""  -OutVariable out -Verbose
    Write-InfoLog $out
    if ($aos.State -ne [system.ServiceProcess.ServiceControllerStatus]::Stopped) 
    {
        Write-InfoLog ("Stopping AOS")        
        $rv = $aos.StopService().ReturnValue 
        
        if ($rv -ne 0) { 
           Write-TerminatingErrorLog ("AOS cannot be stopped. Got error code {0}" -f $rv)        
        }
    }
    
    Write-InfoLog ("Calling Get-WmiObject Win32_Service: {0}" -f (Get-Date)) 
    $aos = Get-WmiObject Win32_Service -ComputerName $AxAOSServerName -Filter "name=""$AOSName"""  -OutVariable out -Verbose
    Write-InfoLog $out
	while ($aos.State -ne [system.ServiceProcess.ServiceControllerStatus]::Stopped)
	{
		if (($(get-date) - $startDateTime).get_Minutes() -gt $AOSRestartTimeout)
		{
     		Write-TerminatingErrorLog('The AOS can not be stopped after {0} minutes.' -f $AOSRestartTimeout)			
    		break
		}
		Start-Sleep 20
        Write-InfoLog ("Calling Get-WmiObject Win32_Service: {0}" -f (Get-Date)) 
		$aos = Get-WmiObject Win32_Service -ComputerName $AxAOSServerName -Filter "name=""$AOSName""" -OutVariable out -Verbose
        Write-InfoLog $out
	}
    Write-InfoLog ("End: Stop-AOS method : {0}" -f (Get-Date)) 	
    Write-InfoLog (" ") 	
}

function Start-WMIService($serviceName, $timeout = (5 * 60))
{
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $service = Get-WmiObject Win32_Service -ComputerName "$($env:computername)" -Filter "name=""$serviceName""" -OutVariable out
    if ($service.State -ne [System.ServiceProcess.ServiceConrollerStatus]::Running)
    {
        $rv = $service.StartService().ReturnValue
        if ($rv -ne 0)
        {
            throw "An error occured during service start operation. Exit code $rv"
        }

        while ($service.State -ne [System.ServiceProcess.ServiceControllerStatus]::Running)
        {
            if ($service.State -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped)
            {
                $rv = $service.StartService()
                if ($rv -ne 0)
                {
                    throw "An error occure while attempting to start the service $serviceName. Exit code $rv"
                }
            }
            if ($sw.Elapsed.Seconds -gt $timeout)
            {
                throw "Service was unable to start in $timeout seconds"
            }
            Write-InfoLog "Sleeping for 20 seconds..."
            Start-Sleep -Seconds 20
        }
    }

    return 0
}

function Start-AOS
{
    Write-InfoLog ("Begin: Start-AOS method : {0}" -f (Get-Date)) 
	$startDateTime = $(get-date)

    Write-InfoLog ("Calling Get-WmiObject Win32_Service: {0}" -f (Get-Date)) 
    $aos = Get-WmiObject Win32_Service -ComputerName $AxAOSServerName -Filter "name=""$AOSName""" -OutVariable out
    Write-InfoLog $out

    Write-InfoLog ("Current AOS state : {0}" -f ($aos.State)) 
    if ($aos.State -ne [system.ServiceProcess.ServiceControllerStatus]::Running)
    {
	   	Write-InfoLog ("Starting AOS")
        $rv = $aos.StartService().ReturnValue
        if ($rv -ne 0) {
            Write-TerminatingErrorLog ("AOS service can't be started. Got error code {0}" -f $rv)        
        } 
    }   

    Write-InfoLog ("Calling Get-WmiObject Win32_Service: {0}" -f (Get-Date)) 
	$aos = Get-WmiObject Win32_Service -ComputerName $AxAOSServerName -Filter "name=""$AOSName""" -OutVariable out
    Write-InfoLog $out

	while ($aos.State -ne [system.ServiceProcess.ServiceControllerStatus]::Running)
	{
        if ($aos.State -eq [system.ServiceProcess.ServiceControllerStatus]::Stopped)
        {
            # Start AOS one more time in case it stopped for some reason during the process of starting
            Write-InfoLog ("Starting AOS")
            $rv = $aos.StartService().ReturnValue
            if ($rv -ne 0) {
                Write-TerminatingErrorLog ("AOS service can't be started. Got error code {0}" -f $rv)
            }
        }
        
		if (($(get-date) - $startDateTime).get_Minutes() -gt $AOSRestartTimeout)
		{
			Write-TerminatingErrorLog('The AOS can not be started after {0} minutes.' -f $AOSRestartTimeout)			
			break
		}
		Start-Sleep 20
        
        Write-InfoLog ("Calling Get-WmiObject Win32_Service: {0}" -f (Get-Date)) 
		$aos = Get-WmiObject Win32_Service -ComputerName $AxAOSServerName -Filter "name=""$AOSName""" -OutVariable out
        Write-InfoLog $out
	}		
    Write-InfoLog ("End: Start-AOS method : {0}" -f (Get-Date)) 
    Write-InfoLog (" ") 	
}

function Read-AXClientConfiguration
{
    $Path = $clientRegistryPath 
    Write-Output "Path: $path"
	$Path = Join-Path $Path (Get-ItemProperty (get-item ($Path)).PSPath).Current
    Write-Output "Current configuration: $path"
	$script:clientBinDir = (Get-ItemProperty (get-item ($Path)).PSPath).bindir.TrimEnd('\')
	$script:clientLogDir = (Get-ItemProperty (get-item ($Path)).PSPath).logdir.TrimEnd('\')
    $script:AxAOS 	  	 = (Get-ItemProperty (get-item ($Path)).PSPath).aos2
	$script:clientLogDir = [System.Environment]::ExpandEnvironmentVariables("$clientLogDir")    
	$script:clientBinDir = [System.Environment]::ExpandEnvironmentVariables("$clientBinDir")    
    $script:ax32  = join-path $clientBinDir "ax32.exe"
    
    Write-Output "Client log folder: $script:clientLogDir"
    if ($script:LogFolder -eq $null -or [string]::IsNullOrEmpty($script:LogFolder))
    {
        # Override with active AX configuration log placement in case not defined
        $script:LogFolder = $script:clientLogDir
    }

    $parts = ($AxAOS.Split(';')[0]).Split('@')
    if($parts.Length -eq 2)
    {
        $AxAOSServerName = $parts[1]
        $AxAOSInstance = $parts[0]
    }
    elseif($parts.Length -eq 1) { $AxAOSServerName = $parts[0] }
    
    $parts = $AxAOSServerName.Split(':')
    if($parts.Length -eq 2) { 
        $AxAOSServerName = $parts[0]
        $port = $parts[1] }
    elseif($parts.Length -eq 1) { $AxAOSServerName = $parts[0] }

    $script:AxAOSServerName  = $AxAOSServerName
    $script:AxAOSInstance  = $AxAOSInstance
    $script:port  = $port

    #Write-Host (Get-Variable) -ForegroundColor Cyan
}

function Read-AxServerConfiguration 
{    
    Write-Host "AOS server name: $axaosservername`nXomputer name: $env:computername" -ForegroundColor Cyan
    if($env:computername -eq $axaosservername)
    {
        Write-Host "Server registry path: $serverRegistryPath" -ForegroundColor Cyan
        $serverPath = $serverRegistryPath 
    	foreach ($item in Get-ChildItem $serverPath)
    	{
    		$subpath = Join-Path $serverPath $item.PSChildName
    		$InstanceName = (Get-ItemProperty (get-item ($subPath)).PSPath).InstanceName
            Write-Host "Instance name: $InstanceName" -ForegroundColor Cyan
            $Path = Join-Path $subPath $CurrentServerConfig
            $portNumber = (Get-ItemProperty (get-item ($Path)).PSPath).port
            Write-Host "Instance name: $InstanceName`nAX AOS Instance: $AxAOSInstance`nportNumber = $portNumber, port = $port" -ForegroundColor Cyan
            if ( ($AxAOSInstance -eq $null) -or ($InstanceName -eq $AxAOSInstance) -or ($portNumber -eq $port))
    		{
    			$script:AOSName = $script:AOSname = "AOS60`${0}" -f $item.PSChildName #The ` character makes powershell know that the next character is to be handled as a part of the string
                $script:aosNumber = "{0}" -f $item.PSChildName
    			$CurrentServerConfig =  (Get-ItemProperty (get-item ($subPath)).PSPath).current
    		    $Path = Join-Path $subPath $CurrentServerConfig
                Write-Host "Path: $Path" -ForegroundColor Cyan
                $portNumber = (Get-ItemProperty (get-item ($Path)).PSPath).port
                if( $port -eq $null -or ($portNumber -eq $port))
                {
        			$script:sqlServer 	  = (Get-ItemProperty (get-item ($Path)).PSPath).dbserver
        			$script:sqlDatabase   = (Get-ItemProperty (get-item ($Path)).PSPath).database
                    $script:sqlModelDatabase = $sqlDatabase
                    if( (Get-ItemProperty (get-item ($Path)).PSPath).split_modeldb -ne $null -and (Get-ItemProperty (get-item ($Path)).PSPath).split_modeldb -eq '1')
                    {
                        $script:sqlModelDatabase = "{0}_model" -f $sqlDatabase
                    }

        	    	$script:serverBinDir  = (Get-ItemProperty (get-item ($Path)).PSPath).bindir.TrimEnd('\') 
                    $script:serverLogDir  = (Get-ItemProperty (get-item ($Path)).PSPath).logdir.TrimEnd('\') 
        	    	$script:serverApplDir = (Get-ItemProperty (get-item ($Path)).PSPath).directory + "\Appl\" +
        	        	                    (Get-ItemProperty (get-item ($Path)).PSPath).application 
                    $script:AxAOSServerName = $AxAOSServerName
                    $script:axBuild = Join-Path $serverBinDir "AXBuild.exe"

                    if ($script:scriptName -eq 'DEPLOY')
                    {
                        if ($script:ApplicationSourceDir -eq $null -or [string]::isNullOrEmpty($script:ApplicationSourceDir))
                        {
                            $local:systemName = GetEnvironmentVariable("SystemName")
                            $script:ApplicationSourceDir = Join-Path $script:ServerBinDir "Application\$local:systemName"
                            if ((Test-Path $script:ApplicationSourceDir) -ne $true)
                            {
                                New-Item -Path $script:ApplicationSourceDir -ItemType Directory -Confirm
                            }
                        }
                    }
                    
                    break #Break once we've found the matching AOS server
                }
    		}		
    	}
    }
    #Write-Host (Get-Variable) -ForegroundColor Cyan
}

############################################################################################
#END COMMON AX FUNCTIONS
############################################################################################


############################################################################################
#COMPILE-AX
############################################################################################
function Compile-Build
{
    try
    {
        #Step: Compile layer
        if ($AxCompileAll -eq "True")   
        {
            $script:compileErrors = $false
            
            $aolParm = ''
            $compileInLayerParm = ''
            if($compileInLayer -ne $null)
            {
                $AolCode = Get-AolCode $compileInLayer
                if ($aolCode -ne '') {$aolParm = '-aolCode={0}' -f $aolCode}
                
                $compileInLayerParm = '-aol={0}' -f $compileInLayer
            }
            
            Stop-AOS
             
            $arguments = 'xppcompileall /s={0}' -f $script:aosNumber
            #$arguments = '{0} {1} -lazyclassloading -lazytableloading -StartupCmd=compileall -novsprojcompileall -internal=noModalBoxes' -f $compileInLayerParm,$aolParm
            Write-InfoLog ("Calling CompileAll API : {0}" -f (Get-Date)) 
            #$axProcess = Start-Process $ax32 -WorkingDirectory $clientBinDir -PassThru -WindowStyle minimized -ArgumentList $arguments -OutVariable out
            $axBuildProcess = Start-Process $axBuild -WorkingDirectory $serverBinDir -PassThru -WindowStyle minimized -ArgumentList $arguments -OutVariable out
            Write-InfoLog $out
            Write-InfoLog ("                                                                 ") 
            Write-InfoLog ("                                                                 ") 

            if ($axBuildProcess.WaitForExit(60000*$CompileAllTimeout) -eq $false)
            {
                $axBuildProcess.Kill()
                Throw ("Error: AX compile did not complete within {0} minutes" -f $CompileAllTimeout)
            }
            
            Write-InfoLog ("End of CompileAll API: {0}" -f (Get-Date))
            
            Copy-Item -Path (Join-Path $script:serverLogDir AxCompileAll.html) -Destination (join-path $clientLogDir AxCompileAll_Pass1.html) -Force -ErrorAction SilentlyContinue 
            Copy-Item -Path (Join-Path $script:serverLogDir AOTprco.log) -Destination (join-path $clientLogDir AOTprco.log) -Force -ErrorAction SilentlyContinue 
            Copy-Item -Path (Join-Path $script:serverLogDir AOTComp.log) -Destination (join-path $clientLogDir AOTComp.log) -Force -ErrorAction SilentlyContinue 
            
            #Step: Compile CIL
            if ($CompileCIL -eq 'True') 
            {
                if ($scriptName -eq 'Build')
                {
                    # We need an active AOS for some stuff related to tasks like SetAXConfiguration
                    Start-AOS
                    Compile-VSComponents

                    # Need to restart AOS after compiling VS Components as they produce dlls which are loaded during AOS startup normally
                    Stop-AOS
                    # copy compiled dlls to Client & Server Bin dirs
                    Copy-VSProjectsBinaries
                    Start-AOS
                    
                    Write-InfoLog (" ")
                    Write-InfoLog ("Compiling remaining objects after VS Components have been recompiled")
                    Write-InfoLog (" ")
                    
                    $arguments = '{0} {1} -lazyclassloading -lazytableloading -StartupCmd=compilepartial -novsprojcompileall -internal=noModalBoxes' -f $compileInLayerParm,$aolParm
                    Write-host ("Calling CompilePartial API : {0}" -f (Get-Date)) 
                    $axProcess = Start-Process $ax32 -WorkingDirectory $clientBinDir -PassThru -WindowStyle minimized -ArgumentList $arguments -OutVariable out
                    Write-host $out
                    Write-InfoLog (" ")
                    Write-InfoLog (" ")
                    if ($axProcess.WaitForExit(60000*$CompileAllTimeout) -eq $false)
                    {
                        $axProcess.Kill()
                        Throw ("Error: AX compile partial did not complete within {0} minutes" -f $CompileAllTimeout)
                    }
                }
                else
                {
                    # Need to start AOS after AXBuild run in case we are not in the Build script (i.e., in the Deploy script)
                    Start-AOS
                }

                Compile-CIL
        
                Write-InfoLog ("                                                                 ") 
                Write-InfoLog ("                                                                 ") 
            }
                
            #Step 
            Stop-AOS
            Write-InfoLog ("                                                                 ") 
            Write-InfoLog ("                                                                 ") 
            
            #Step 
            Start-AOS
            Write-InfoLog ("                                                                 ") 
            Write-InfoLog ("                                                                 ") 

            #Step 
            Synchronize-AX
            Write-InfoLog ("                                                                 ") 
            Write-InfoLog ("                                                                 ") 
        }
    }
    finally
    {
        if($AxCompileAll -eq $true)
        {
            #Step     
            Check-CompilerErrors
            Write-InfoLog ("                                                                 ") 
            Write-InfoLog ("                                                                 ") 
            Write-InfoLog ("Collecting AxCompileAll.html: {0}" -f (Get-Date)) 
            Copy-Item -Path (Join-Path $clientLogDir AxCompileAll.html) -Destination $currentLogFolder -Force -ErrorAction SilentlyContinue 
            Copy-Item -Path (Join-Path $clientLogDir AOTprco.log) -Destination $currentLogFolder -Force -ErrorAction SilentlyContinue 
            Copy-Item -Path (Join-Path $clientLogDir AOTcomp.log) -Destination $currentLogFolder -Force -ErrorAction SilentlyContinue 

            if ($CompileCIL -eq 'True') 
            {
                Check-CILErrors
                if((Test-path (join-path $serverBinDir XppIL)) -eq $True)
                {
                    Copy-Item -Path (Join-Path (join-path $serverBinDir XppIL) Dynamics.Ax.Application.dll.log) -Destination $currentLogFolder -Force -ErrorAction SilentlyContinue 
                }
            }
        }    
    }
}

function Compile-AX
{
    Write-InfoLog ("                                                                 ") 
    Write-InfoLog ("*****************************************************************") 
    Write-InfoLog ("****************COMPILE AX***************************************") 
    Write-InfoLog ("Begin: AX compile : {0}" -f (Get-Date)) 
    Write-InfoLog ("                                                                 ") 
    Write-InfoLog ("                                                                 ") 
    
    #Step 1: Stop AOS
    Stop-AOS
    Write-InfoLog ("                                                                 ") 
    Write-InfoLog ("                                                                 ") 
    
    #Step 2: Update compiler Info
    <#Update-CompilerInfo
    Write-InfoLog ("                                                                 ") 
    Write-InfoLog ("                                                                 ") 
    #>
    #Step 3: Delete auc files
    Remove-Item -Path (Join-Path $env:LOCALAPPDATA "ax_*.auc") -ErrorAction SilentlyContinue
    if((Test-path ($serverBinDir)) -eq $True)
    {
        $xpplPath = join-path $serverBinDir XppIL
        if (((Test-path ($xpplPath)) -eq $True) -and ((Test-path (join-path $xpplPath Dynamics.Ax.Application.dll.log)) -eq $True))
        {
            Remove-Item -Path (join-path $xpplPath Dynamics.Ax.Application.dll.log) -ErrorAction SilentlyContinue    
        }
    }
        
    #Step 4: Restart AOS
    Start-AOS
    Write-InfoLog ("                                                                 ") 
    Write-InfoLog ("                                                                 ") 
    
    #Step 5: Set model store
    Write-InfoLog ("Calling Set-AXModelStore: {0}" -f (Get-Date)) 
    Set-AXModelStore -NoInstallMode -Server $sqlServer -Database $sqlModelDatabase -Verbose   
    Write-InfoLog ("                                                                 ") 
    Write-InfoLog ("                                                                 ") 
    Write-InfoLog ("Starting compile : {0}" -f (Get-Date)) 
    Write-InfoLog ("                                                                 ") 
    Write-InfoLog ("                                                                 ") 

    #Step 6:
    #Compile-Build
    Synchronize-AX
    Write-InfoLog ("                                                                 ") 
    Write-InfoLog ("                                                                 ") 
        
    Compile-Build
    
    Write-InfoLog ("Compile finished : {0}" -f (Get-Date)) 

    Write-InfoLog ("End: AX compile : {0}" -f (Get-Date)) 
    Write-InfoLog ("*****************************************************************") 
    Write-InfoLog ("*****************************************************************")
    Write-InfoLog ("                                                                 ")
}

function Compile-CIL
{
   	Write-InfoLog ("Starting CIL compile : {0}" -f (Get-Date)) 
	$CilXmlFile = join-path $currentLogFolder 'GenerateIL.XML'
	$CilLogFile = join-path $currentLogFolder 'GenerateIL.log' 
	$newFile = @()
	$newFile += '<?xml version="1.0" encoding="utf-8"?>' 
	$newFile += '<AxaptaAutoRun version="4.0" logFile="{0}">' -f $CilLogFile
	$newFile += '<Run type="class" name="SysCompileIL" method="generateIL" parameters="true" />'
	$newfile += '</AxaptaAutoRun>'
	$newfile | Out-File $CilXmlFile -Encoding Default
	$arguments = '-lazyclassloading -lazytableloading "-StartupCmd=autorun_{0}"' -f $CilXmlFile
   	$axProcess = Start-Process $ax32 -WorkingDirectory $clientBinDir -PassThru -WindowStyle minimized -ArgumentList $arguments 
	if ($axProcess.WaitForExit(60000*$CompileCILTimeout) -eq $false)
	{
		$axProcess.Kill()
		Throw ("Error: AX CIL compile did not complete within {0} minutes" -f $CompileCILTimeout)
	}
    
    try
    {
    	[xml]$LogFile = Get-Content($CilLogFile)
    	$Infolog = $LogFile.AxaptaAutoRun.Infolog.Split([char]10)
    	foreach($line in $Infolog)
    	{
    		if ($line.Length -gt 0)
    		{
    			$i = $line.LastIndexOf([char]9)
    			if ($i -gt 0) {$line = $line.Substring($i+1)}
    			if ($line.Contains('Service group started:') -eq $false)
    			{
    				if ($line -eq 'The full CIL generation from X++ is done.')
    				{
    					Write-InfoLog '.   ' + $line 
    				}			
    				else
    				{
    					Write-ErrorLog(('Compile-CIL Error   ' + $line))
    				}
    			}			
    		}			
    	}
    }
    catch
    {
        Write-ErrorLog "Exception in Compile-CIL."
        Write-ErrorLog $Error[0].Exception
    }
    
    Write-InfoLog ("End CIL compile : {0}" -f (Get-Date)) 	
}

function Update-CompilerInfo
{
    Write-InfoLog ("Starting update compiler info : {0}" -f (Get-Date)) 
    try
    {
        #Compiler settings
        $query = "select COMPILERWARNINGLEVEL,DEBUGINFO,id from {0}..USERINFO where NETWORKALIAS = '{1}'" -f $sqlDatabase,$env:USERNAME
        $table = Invoke-Sqlcmd -Query "$query" -ServerInstance "$SQLserver" -Verbose
        if($table -ne $null)
        {
            foreach($row in $table)  
            {
                $COMPILERWARNINGLEVEL = $row.get_Item('COMPILERWARNINGLEVEL')
                $DEBUGINFO            = $row.get_Item('DEBUGINFO')
                $AxId                 = $row.get_Item('ID')
            }
            if  (($COMPILERWARNINGLEVEL -ne 4) -or ($DEBUGINFO -ne 524))
            {
                $query = "update {0}..USERINFO set COMPILERWARNINGLEVEL=4, DEBUGINFO=524 where NETWORKALIAS = '{1}'" -f $sqlDatabase,$env:USERNAME
                Invoke-Sqlcmd -Query "$query" -ServerInstance "$SQLserver" -Verbose
            }
        }
        if ($AxId -ne $null)
        {
            #Best Practise settings
            $query = "select LAYERSETTING,WARNINGLEVEL from {0}..SYSBPPARAMETERS where USERID = '{1}'" -f $sqlDatabase,$AxId
            $table = Invoke-Sqlcmd -Query "$query" -ServerInstance "$SQLserver" -Verbose
            if($table -ne $null)
            {
                foreach($row in $table)  
                {
                    $LayerSetting = $row.get_Item('LAYERSETTING')
                    $WARNINGLEVEL = $row.get_Item('WARNINGLEVEL')
                }
                if (($LayerSetting -ne 1) -or ($WARNINGLEVEL -ne 0))
                {
                    $query = "update {0}..SYSBPPARAMETERS set LAYERSETTING=1, WARNINGLEVEL=0 where USERID = '{1}'" -f $sqlDatabase,$AxId
                    Invoke-Sqlcmd -Query "$query" -ServerInstance "$SQLserver" -Verbose
                }
            }
        }
    }
    catch{
       Write-TerminatingErrorLog  "Exception in Update-CompilerInfo" $Error[0]
    }    
    
    Write-InfoLog ("Done update compiler info : {0}" -f (Get-Date))
}

function Check-CILErrors
{
    Write-InfoLog ("Begin Check-CILErrors: {0}" -f (Get-Date))

    $xpplPath = join-path $serverBinDir XppIL
    if (((Test-path ($xpplPath)) -eq $True) -and ((Test-path (join-path $xpplPath Dynamics.Ax.Application.dll.log)) -eq $True))
    {
        foreach ($line in (Get-Content (join-path $xpplPath Dynamics.Ax.Application.dll.log)))
		{
            if($line -ne $null -and $line.Trim() -ne '')
            {
                if($lastLine -ne $null)
                {
                    $secondLastLine = $lastLine
                    $lastLine = $line
                }
                else
                {
                    $lastLine = $line
                }
            }
        }
        
        if($secondLastLine -ne $null) 
        {
            if($secondLastLine.Contains('Errors:') -and $secondLastLine.Split(':')[0].Trim() -eq 'Errors' -and $secondLastLine.Split(':')[1].Trim() -ne 0)
            { 
                Write-ErrorLog "IL Compile errors. See Dynamics.Ax.Application.dll.log file."
            }
        }
        
        if($lastLine -ne $null) 
        {
            if($lastLine.Contains('Warnings:') -and $lastLine.Split(':')[0].Trim() -eq 'Warnings' -and $lastLine.Split(':')[1].Trim() -ne 0)
            { Write-Warning "Warnings while compiling IL."}
        }
    }
    
    Write-InfoLog ("End Check-CILErrors: {0}" -f (Get-Date))
}
    
function Check-CompilerErrors
{
    Write-InfoLog ("Begin Check-CompilerErrors: {0}" -f (Get-Date))
    $compileErrors = $false
    $compileLogFile = (join-path $clientLogDir "AxCompileAll.html")
 	if ((test-Path $compileLogFile) -eq $true)
	{
		foreach ($line in (Get-Content $compileLogFile))
		{
			if (($XMLstarted -eq $true) -and ($line.Contains('</XML>')))
			{
				$XMLstarted = $false
				$xmlContent += $line.Replace('</XML>','')
			}
			if ($XMLstarted -eq $true)
            {
                # Add a space inbetween in case we are in the middle of the xml
                if ($xmlContent) {$xmlContent += ' '}
                $xmlContent += $line.Trim()
            }
			if ($line -eq '<XML ID="compilerinfo">') {$XMLstarted = $true}
		}	
        $xmlcontent | out-file -filepath (join-path $clientLogDir 'CompileErrors.xml')
		[xml]$AxXml = $xmlcontent
		foreach($record in $axXml.AxaptaCompilerOutput.Record)
		{
			if ($record -ne $null -and (($record.field[7]).get_InnerText()) -eq "0") 
			{
                $compileErrors = $true
				$line = "Compiler ERROR: {0}\{1} : {2}" -f ($record.field[0]).get_InnerText(),($record.field[6]).get_InnerText(),($record.field[10]).get_InnerText()		
				Write-ErrorLog($line)
			}
		}		
	}
    
    if ($compileErrors -eq $true)
    {
        Write-ErrorLog "Errors while compiling code."
    }
        
    Write-InfoLog ("End Check-CompilerErrors: {0}" -f (Get-Date))		
}

function Compile-VSComponents
{
	Write-InfoLog ("BEGIN: Compile-VSComponents: {0}" -f (Get-Date)) 
    if($modelLayerMap -ne $null)
    {        
        foreach($m in ($modelLayerMap.GetEnumerator()))
        {
            if($m -ne $null)
            {
                foreach($file in $m.Value)
                {
                    $fileInfo = Get-Item -Path $file
                    if($fileInfo -ne $null)
                    {
                        if($fileInfo.Name -eq 'Model.xml')
                        {
                            Compile-VisualStudioProjects ($fileInfo)
                        }
                    }
                }
            }
        }
    }
    
	Write-InfoLog ("END: Compile-VSComponents: {0}" -f (Get-Date)) 
}

function Compile-VisualStudioProjects([System.IO.FileSystemInfo]$model)
{
    Write-InfoLog ("Begin: Compile-VisualStudioProjects: {0}" -f (Get-Date)) 
    $manifest = new-object "System.Xml.XmlDocument"
    $manifest.Load($model.FullName)
    [String]$modelName=$manifest.SelectSingleNode("//Name").get_InnerText()
    $publisher=$manifest.SelectSingleNode("//Publisher").get_InnerText()
    $axLayer= $manifest.SelectSingleNode("//Layer").get_InnerText()
    
    $aolCode = Get-AolCode $axlayer
    $aolParm = ''
    if ($aolCode -ne '') {$aolParm = '/p:axAolCode={0}' -f $aolCode}
    $projPath = (join-path $AxBuildDir 'CompileVSProjects.proj')
    $logFile = join-path $currentLogFolder ('VSCompile.{0}.log' -f $modelName)
    $errlogFile = join-path $currentLogFolder ('VSCompileError.{0}.err' -f $modelName)
    $wrnlogFile = join-path $currentLogFolder ('VSCompileWarning.{0}.wrn' -f $modelName)
    
    $arguments = '"{0}" /p:srcFolder="{1}" /p:axLayer={2} {3} /p:ModelName="{4}" /p:Configuration=Release /l:FileLogger,Microsoft.Build.Engine;logfile="{5}" /p:ModelPublisher="{6}" /flp1:errorsonly;logfile="{7}" /flp2:WarningsOnly;logfile="{8}" /p:RDLParameterLanguage="{9}" /p:OutDir="{10}"' -f $projPath, $Model.Directory.FullName,$axLayer,$aolParm,$modelName,$logFile, $publisher,$errlogFile, $wrnlogFile,$rdlLanguage, $vsProjBinFolder
    Write-InfoLog 'Msbuild arguments'
    Write-InfoLog $arguments
    $msBuildProcess = Start-Process "msbuild.exe" -WorkingDirectory $msBuildPath -PassThru -WindowStyle minimized -ArgumentList $arguments -Verbose
    if ($msBuildProcess.WaitForExit(60000*$CompileCILTimeout) -eq $false)
    {
        $msBuildProcess.Kill()
        Throw ("Error: Visual studio project didn't compile in {0} min." -f $CompileCILTimeout)
    }

    $retError = $true
    if((test-path $logfile) -eq $true)
    {
        $fileContent = Get-Content $logFile -ErrorAction SilentlyContinue
        $lineNum = 0
        foreach ($line in $fileContent)
        {
            $err = $line.Contains('0 Error(s)')
            if($err -eq $true)
            {
                $retError = $false
            }
        }
    }
    
    if((test-path $errlogFile) -eq $true)
    {
        $fileContent = Get-Content $errlogFile -ErrorAction SilentlyContinue
        if($errlogFile -eq $null -or $errlogFile.Trim() -eq '')
        {
            $retError = $false        
        }
    }
    
    if($retError -eq $true)
    {
        Write-TerminatingErrorLog('Failed to compile VS project for model {0}' -f $modelName)
    }
    
    Write-InfoLog('Compilation of VS projects succeded at {0}' -f (Get-Date))
}

function Kill-AX32Processes
{
    # Kill All active Ax32.exe processes if any
    Get-Process -Name 'Ax32' -ErrorAction SilentlyContinue | Stop-Process -Force
    # Sleep for 5 seconds in order to give enough time for the resources to be reclaimed
    Start-Sleep -s 5
}

function Copy-VSProjectsBinaries
{
    # copy compiled dlls to Client & Server Bin dirs
    Kill-AX32Processes

    robocopy "$vsProjBinFolder" "$clientBinDir" /s /z
    #Copy-Item "$vsProjBinFolder\*" $clientBinDir -Force -Recurse -ErrorAction SilentlyContinue 
    Write-Infolog ("Compiled VS projected have been copied to $clientBinDir")
    #iex "robocopy `"$vsProjBinFolder`" `"$serverBinDir`" /s /z"
    robocopy "$vsProjBinFolder" "$serverBinDir" /s /z
    #Copy-Item "$vsProjBinFolder\*" $serverBinDir -Force -Recurse -ErrorAction SilentlyContinue 
    Write-Infolog ("Compiled VS projected have been copied to $serverBinDir")
}

###############################################################################################
#END COMPILE-AX
###############################################################################################

###############################################################################################
#COMBINE AND EXPORT-AX
###############################################################################################

#Read the VCSDEF.xml file with the AX TFS setup.
function Get-ModelsToBuild
{
    Write-InfoLog ("Start getting models to build: {0}" -f (Get-Date)) 
    $Definition = new-object "System.Xml.XmlDocument"
    $Definition.Load($LocalProject)
    $Definition.SelectSingleNode("//VCSParameters").SelectSingleNode("//Models").ChildNodes
}

function Get-AolCode([string]$Layer)
{
    $aolCode = ''
    foreach ($fileName in Get-ChildItem $AxBuildDir -Filter 'aolcodes.*' ) 
    {
        $fileContent = Get-Content $fileName.fullName
        foreach ($line in $fileContent)
        {
            $line = $line.Trim().Split(':')
            if ($line[0].length -ge 2)
            {
                if ($Layer.SubString(0,2).ToUpper() -eq $line[0].SubString(0,2).ToUpper())
                {
                    $aolCode = $line[1]
                }                   
            }           
        }
    }       
    $aolCode
}

function Get-Model([System.IO.FileSystemInfo]$model)
{
    Write-InfoLog ("Begin Get-Model: {0}" -f (Get-Date))		
    Write-InfoLog ("Model: {0}" -f $model.FullName)		
    $manifest = new-object "System.Xml.XmlDocument"
    $manifest.Load($model.FullName)
    [String]$ModelLayer         = $manifest.SelectSingleNode("//Layer").get_InnerText()
    [String]$script:ModelName   = $manifest.SelectSingleNode("//Name").get_InnerText()
    [String]$ModelVssersion       = $manifest.SelectSingleNode("//Version").get_InnerText()
	$script:AolCode = Get-AolCode $ModelLayer
    $script:AxLayer = $ModelLayer
    $script:ModelVersion = $ModelVssersion
    Write-InfoLog ("End Get-Model: {0}" -f (Get-Date))		
}

function Combine-Xpos([System.IO.FileSystemInfo]$modelPath)
{
    Write-InfoLog ("Begin: Combine-Xpos: {0}" -f (Get-Date))  
    Start-Sleep 2
    $combinedXpoFile = (Join-Path $currentLogFolder ("Combined.{0}.xpo" -f $modelName))
    $arguments = ' -XpoDir "{0}" -Verbose -CombinedXpoFile "{1}" -utf8' -f $modelPath,$combinedXpoFile
    $cmdName = Join-Path $AxBuildDir 'combinexpos.exe'
    $logfile = Join-Path $CurrentLogFolder ('Combined.{0}.log' -f $modelName)
    Write-InfoLog ("Calling Start-Process: {0}" -f (Get-Date)) 
    $result = Start-Process $cmdName -WorkingDirectory $axbuildDir -PassThru -ArgumentList $arguments -RedirectStandardOutput $logFile
    Write-InfoLog $result
    if ($result.WaitForExit(60000*$CombineTimeout) -eq $false)
    {
        $axProcess.Kill()
        Throw ("Combine XPO for {0} didn't complete after {1} minutes." -f $modelName, $CombineTimeout)			
    }
    
    CreateSpecificXPOs($combinedXpoFile)
    
    Write-InfoLog ("End: Combine-Xpos: {0}" -f (Get-Date))  
}

function Check-CombineXpoError
{    
    $logfile = Join-Path $CurrentLogFolder ('Combined.{0}.log' -f $modelName)
    $fileContent = Get-Content $logFile -ErrorAction SilentlyContinue
    $lineNum = 0
    foreach ($line in $fileContent)
    {
        $lineNum++
        if (($lineNum -gt 1) -and ($line -eq 'Ok')) {$importOk = $true}         
    }
    $importOk
}

function Extract-References([string]$xpoFileName)
{
    $fileContents = Get-Content $xpoFileName -ErrorAction SilentlyContinue
    $referencesFileName = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($xpoFileName), ('{0}_refs.xpo' -f [System.IO.Path]::GetFileNameWithoutExtension($xpoFileName)))
    $writer = [System.IO.StreamWriter] $referencesFileName
    $writer.WriteLine('Exportfile for AOT version 1.0 or later')
    $writer.WriteLine('Formatversion: 1')
    $writer.WriteLine()
    foreach ($line in $fileContents)
    {
        if ($line -match 'Element: REF')
        {
            $writer.WriteLine()
            $copyLine = $true
        }
        if ($copyLine -eq $true)
        {
            $writer.WriteLine($line)
        }
        if ($line -match 'ENDREFERENCE' -and $copyLine -eq $true)
        {
            $writer.WriteLine()
            $copyLine = $false
        }
    }
    $writer.WriteLine()
    $writer.WriteLine('***Element: END')
    $writer.Close()
}

function GetWritersList($writers)
{
    if (!$writers)
    {
        $writers = new-object 'System.Collections.Generic.List[System.IO.StreamWriter]'
    }
    $writers
}

function Coalesce($a, $b)
{
    if ($a) {$a} else {$b}
}

function InitXpoWriter([string]$fileName)
{
    $writer = new-object 'System.IO.StreamWriter' $fileName
    $writer.WriteLine('Exportfile for AOT version 1.0 or later')
    $writer.WriteLine('Formatversion: 1')
    $writer.WriteLine()
    $writer
}

function CreateSpecificXPOs([string]$xpoFileName)
{
    $fileContents = Get-Content $xpoFileName -ErrorAction SilentlyContinue
    $writer = $null
    $shouldDecide = $false
    $buffer = $null
    $exceptionalTables = @()
    foreach ($line in (Get-Content (Join-Path (Split-Path -Parent $script:startupDir) 'ExceptionalTables.txt')))
    {
        $exceptionalTables += $line.Trim()
    }
    foreach ($line in $fileContents)
    {
        # Finalize current element writing
        if ($line -match 'Element:' -and $copyLine -eq $true -and $writer -ne $null)
        {
            $writer.WriteLine()
            $copyLine = $false
        }
        if ($shouldDecide -eq $true -and $line -match '; Microsoft Dynamics AX')
        {
            $isExceptionalTable = $false
            foreach ($table in $exceptionalTables)
            {
                if (($line -match "Table : $table") -or ($line -match "View : $table"))
                {
                    $isExceptionalTable = $true
                    break
                }
            }
            if ($isExceptionalTable -or ($line -match 'Table : Sys' -or $line -match 'EventInbox' -or $line -match 'Table : DirPartyTable')) # i.e., a System table
            {
                if (!$sysTabWriter)
                {
                    $sysTabXpoFileName = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($xpoFileName), ('{0}_sysTab.xpo' -f [System.IO.Path]::GetFileNameWithoutExtension($xpoFileName)))
                    $sysTabWriter = InitXpoWriter $sysTabXpoFileName
                    if (!$writers)
                    {
                        $writers = new-object 'System.Collections.Generic.List[System.IO.StreamWriter]'
                    }
                    $writers.Add($sysTabWriter)
                }
                $writer = $sysTabWriter
            }
            elseif ($line -match 'Class: SysImportElements' -or $line -match 'SysStartupCmd' -or $line -match 'Class: SysStartupCmdAOTImport' -or $line -match 'Class: SysStartupCmdCompilePartial' -or $line -match 'MMS_VerifyImportedAOTObjects')  # special case for SysImportElements
            {
                if (!$sysClsWriter)
                {
                    $sysClsXpoFileName = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($xpoFileName), ('{0}_sysCls.xpo' -f [System.IO.Path]::GetFileNameWithoutExtension($xpoFileName)))
                    $sysClsWriter = InitXpoWriter $sysClsXpoFileName
                    if (!$writers)
                    {
                        $writers = new-object 'System.Collections.Generic.List[System.IO.StreamWriter]'
                    }
                    $writers.Add($sysClsWriter)
                }
                $writer = $sysClsWriter
            }
            
            # At this point we have already determined (i.e., decided) which writer to use
            $shouldDecide = $false            
            $writer.WriteLine()
            # Flush accumulated buffer
            $writer.Write($buffer)
        }
        if ($line -match 'Element: REF')
        {
            if (!$refWriter)
            {
                $refXpoFileName = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($xpoFileName), ('{0}_refs.xpo' -f [System.IO.Path]::GetFileNameWithoutExtension($xpoFileName)))
                $refWriter = InitXpoWriter $refXpoFileName
                if (!$writers)
                {
                    $writers = new-object 'System.Collections.Generic.List[System.IO.StreamWriter]'
                }
                $writers.Add($refWriter)
            }
            $refWriter.WriteLine()
            $writer = $refWriter
            $copyLine = $true
        }
        elseif ($line -match 'Element: DBT' -or $line -match 'Element: VIE')
        {
            if (!$ddWriter)
            {
                $ddXpoFileName = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($xpoFileName), ('{0}_dd.xpo' -f [System.IO.Path]::GetFileNameWithoutExtension($xpoFileName)))
                $ddWriter = InitXpoWriter $ddXpoFileName
                if (!$writers)
                {
                    $writers = new-object 'System.Collections.Generic.List[System.IO.StreamWriter]'
                }
                $writers.Add($ddWriter)
            }
            $ddWriter.WriteLine()
            $writer = $ddWriter
            $copyLine = $true
            $shouldDecide = $true
            $buffer = ''
        }
        elseif ($line -match 'Element: SRP')
        {
            if (!$ssrsWriter)
            {
                $ssrsXpoFileName = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($xpoFileName), ('{0}_ssrs.xpo' -f [System.IO.Path]::GetFileNameWithoutExtension($xpoFileName)))
                $ssrsWriter = InitXpoWriter $ssrsXpoFileName
                if (!$writers)
                {
                    $writers = new-object 'System.Collections.Generic.List[System.IO.StreamWriter]'
                }
                $writers.Add($ssrsWriter)
            }
            $ssrsWriter.WriteLine()
            $writer = $ssrsWriter
            $copyLine = $true
        }
        elseif ($line -match 'Element: CLS')
        {
            if (!$clsWriter)
            {
                $clsXpoFileName = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($xpoFileName), ('{0}_cls.xpo' -f [System.IO.Path]::GetFileNameWithoutExtension($xpoFileName)))
                $clsWriter = InitXpoWriter $clsXpoFileName
                if (!$writers)
                {
                    $writers = new-object 'System.Collections.Generic.List[System.IO.StreamWriter]'
                }
                $writers.Add($clsWriter)
            }
            $clsWriter.WriteLine()
            $writer = $clsWriter
            $copyLine = $true
            $shouldDecide = $true
            $buffer = ''
        }
        elseif ($line -match 'Element: SDT' -or $line -match 'Element: SPV' -or $line -match 'Element: SPC' -or $line -match 'Element: SRO')
        {
            if (!$secWriter)
            {
                $secXpoFileName = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($xpoFileName), ('{0}_sec.xpo' -f [System.IO.Path]::GetFileNameWithoutExtension($xpoFileName)))
                $secWriter = InitXpoWriter $secXpoFileName
                if (!$writers)
                {
                    $writers = new-object 'System.Collections.Generic.List[System.IO.StreamWriter]'
                }
                $writers.Add($secWriter)
            }
            $secWriter.WriteLine()
            $writer = $secWriter
            $copyLine = $true
        }
        elseif ($line -match 'Element: SVC')
        {
            if (!$svcWriter)
            {
                $svcXpoFileName = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($xpoFileName), ('{0}_svc.xpo' -f [System.IO.Path]::GetFileNameWithoutExtension($xpoFileName)))
                $svcWriter = InitXpoWriter $svcXpoFileName
                if (!$writers)
                {
                    $writers = new-object 'System.Collections.Generic.List[System.IO.StreamWriter]'
                }
                $writers.Add($svcWriter)
            }
            $svcWriter.WriteLine()
            $writer = $svcWriter
            $copyLine = $true
        }
        elseif ($line -match 'Element: PRN')
        {
            if (!$prjWriter -or ($prjWriter.BaseStream.Position -gt 102400))
            {
                if (!$prjCounter)
                {
                    $prjCounter = 0
                }
                $prjCounter++
                $prjXpoFileName = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($xpoFileName), ("{0}_prj($prjCounter).xpo" -f [System.IO.Path]::GetFileNameWithoutExtension($xpoFileName)))
                $prjWriter = InitXpoWriter $prjXpoFileName
                if (!$writers)
                {
                    $writers = new-object 'System.Collections.Generic.List[System.IO.StreamWriter]'
                }
                $writers.Add($prjWriter)
            }
            $prjWriter.WriteLine()
            $writer = $prjWriter
            $copyLine = $true
        }
        if ($copyLine -eq $true)
        {
            if ($shouldDecide -eq $true)
            {
                # Add a space before the line break symbol to facilitate import via SysImportElements class (due to SysImportElements parser weirdness)
                $buffer += $line + " `n" #F*cking 'new line' symbol in powershell
            }
            else
            {
                $writer.WriteLine($line)
            }
        }
    }
    foreach ($w in $writers)
    {
        $w.WriteLine()
        $w.WriteLine('***Element: END')
        $w.Close()
    }
}

###############################################################################################
#END COMBINE AND EXPORT-AX
###############################################################################################

function Create-AXModel($AxModelManifest)
{
    Write-InfoLog ("Begin: Create-AXModel: {0}" -f (Get-Date))  

    Write-InfoLog ("Calling Set-AXModelStore: {0}" -f (Get-Date)) 
    $Result = Set-AXModelStore -NoInstallMode -Server $sqlServer -Database $sqlModelDatabase -Verbose
    
    Write-InfoLog ("Calling New-AXModel: {0}" -f (Get-Date)) 
    $Result = New-AXModel -ManifestFile $AxModelManifest -Server $sqlServer -Database $sqlModelDatabase -OutVariable out
    Write-InfoLog $out
    Write-InfoLog ("End: Create-AXModel: {0}" -f (Get-Date))  
}

function Put-BuildNumber($AxModelManifest)
{
    Write-InfoLog ("Begin: Put-BuildNumber: {0}" -f (Get-Date))  
    #update the build number in the model.xml file
    $manifest = new-object "System.Xml.XmlDocument"
    $manifest.Load($AxModelManifest)
    
    Write-InfoLog ("Calling Edit-AXModelManifest: {0}" -f (Get-Date)) 
    try
    {
        $Result = Edit-AXModelManifest -ManifestFile $AxModelManifest -ManifestProperty ('Version={0}' -f $ModelVersion) -Server $sqlServer -Database $sqlModelDatabase -OutVariable out
        Write-InfoLog $out
    }
    catch
    {
        Write-WarningLog ('An error occured while calling Edit-AXModelManifest: {0}' -f $Error[0])
    }
    
    Write-InfoLog ("End: Put-BuildNumber: {0}" -f (Get-Date))  
}

function Install-DependentBinaries
{
    # Kill AX32.exe processes that may block dependent binaries from being copied to client bin dir
    Kill-AX32Processes
    Write-InfoLog ("Start Install-DependentBinaries: {0}" -f (Get-Date)) 
    if ($dependencyPath -ne $null -and (Test-Path $dependencyPath) -eq $True)
    {
        $Path = Join-Path $dependencyPath "Bin"
        if((Test-Path $Path) -eq $True)
        {
            foreach ($file in (Get-ChildItem -Path $Path -Recurse -ErrorAction Stop))
            {
                if ($file.PSIsContainer -eq $False)
                {
                    Copy-Item -Path (Join-Path $file.directory $file.Name) -Destination $serverBinDir -Force 
                    Copy-Item -Path (Join-Path $file.directory $file.Name) -Destination $clientBinDir -Force 
                }   
            }
        }       
    }
    Write-InfoLog ("End Install-DependentBinaries: {0}" -f (Get-Date)) 
}

function Import-XPO([string]$xpoName, [bool]$isAbsolutePath = $false)
{
    $aolParm = ''
    if ($aolCode -ne '') {$aolParm = '-aolCode={0}' -f $aolCode}
    if ($isAbsolutePath -eq $true)
    {
        $basePath = Split-Path -Path $xpoName -Parent
        $xpoName = Split-Path -Path $xpoName -Leaf
    }
    else
    {
        $basePath = $currentLogFolder
    }
    Write-InfoLog($xpoName)
    $arguments = '-aol={0} {1} "-aotimportfile={2}\{4}" -lazyclassloading -lazytableloading -nocompileonimport -internal=noModalBoxes "-model=@{3}"' -f $axLayer,$aolParm,$basePath,$Model.FullName, $xpoName
    Write-InfoLog($arguments)
    $axProcess = Start-Process $ax32 -WorkingDirectory $clientBinDir -PassThru -WindowStyle minimized -ArgumentList $arguments -Verbose
    if ($axProcess.WaitForExit(60000*$ImportTimeout) -eq $false)
    {
        $axProcess.Kill()
        Throw ("Error: AX .XPO import did not complete within {0} minutes" -f $ImportTimeout)
    }
    Write-InfoLog ("Done Import combined xpo $xpoName for model {0}: {1}" -f $modelName,(Get-Date))
}

function Create-AOTObjectsTxt([System.IO.FileSystemInfo]$model)
{
    $basePath = $model.Directory.FullName
    $fileName = ('{0}-AOTObjects.txt' -f $model.Directory.Name)
    $fullFileName = (Join-Path $clientLogDir $fileName)
    Write-host "Full AOT objects file name: $fullFileName" -ForegroundColor Cyan
    <#gci -Path $basePath -File -Recurse -Include *.xpo -ErrorAction SilentlyContinue `
    |% {gc $_.FullName -totalcount 20} |? {$_ -match 'Microsoft Dynamics AX \w+: (?<objectName>\w+) \w+$'} |% {$Matches['objectName']} `
    | Out-File -FilePath $fullFileName -Encoding ascii -ErrorAction Continue#>
    gci -Path $basePath -File -Recurse -Include *.xpo, *.csproj, *.dynamicsproj -ErrorAction SilentlyContinue `
    |% {$_.FullName.Remove(0, $basePath.Length)} `
    | Out-File -FilePath $fullFileName -Encoding ascii -ErrorAction Continue # -Append
    Write-Host "Created $fullfileName" -ForegroundColor Cyan
    Write-Host ''
    Write-Host ''
}

function Import-MissedObjects([bool]$updateAOTObjectsTxt = $true)
{
    foreach ($file in (gci -Path "$clientLogDir\*" -File -Include *-AOTMissingObjects.txt -ErrorAction Continue))
    {
        $modelName = $file.Name |? {$_ -match '(?<modelName>^.*)\-[^-]*$'} |% {$Matches['modelName']}
        $contents = Get-Content -Path $file.FullName
        $buffer = @()
        foreach ($line in $contents)
        {
            Import-XPO (Join-Path (Join-Path $applicationSourceDir $modelName) $line) $true
            if ($updateAOTObjectsTxt -eq $true)
            {
                $buffer += $line
            }
        }
        if ($updateAOTObjectsTxt -eq $true)
        {
            $buffer | Out-File -FilePath (Join-Path (Split-Path -Path $file.FullName) ('{0}-AOTObjects.txt' -f $modelName)) -Encoding default
        }
    }
    #| Get-Content `
    #|% { foreach ($line in $_) { Import-XPO $line $true; } }
    #{foreach ($line in (Get-Content $_)) { Import-XPO $line; }}
}

function Verify-AOTObjects
{
    $verificationResult = $true
    $importRetryCount = 0
    DO
    {
        #Now we can verify all objects have been imported
        $verificationResult = Verify-AOTObjectsImported
        if ($verificationResult -eq $true)
        {
            Write-Host 'Now, everything is imported' -ForegroundColor Cyan
        }
        elseif ($importRetryCount -eq 0)
        #($secodWaveOfImportPassed -ne $true)
        {
            Write-Host 'Some objects were not imported after combined XPO import' -ForegroundColor Yellow
            Write-Host 'Attempting to import missed objects...' -ForegroundColor Yellow
            Import-MissedObjects
            $importRetryCount++
            #$secodWaveOfImportPassed = $true
        }
        # We actually quit the loop here in case of a negative scenario
        else
        {
            Write-Host 'Still some objects are missing after attempting to reimport' -ForegroundColor Yellow
            break
        }
    } While ($verificationResult -eq $false)
    $verificationResult
}

function Import-AxCode([System.IO.FileSystemInfo]$model)
{
    Delete-Axmodel $model.FullName
    Write-InfoLog ("Import {0} Starting : {1}" -f $model.FullName,(Get-Date)) 
    #Create-AXModel $model.FullName
    #Import the combined XPO into AX
    Get-Model $model
    
    #This line is suspected in locking AX UI
    #Put-BuildNumber $model.FullName
    
    Write-InfoLog ("Import combined xpo for model {0}: {1}" -f $modelName,(Get-Date))
    $aolParm = ''
    if ($aolCode -ne '') {$aolParm = '-aolCode={0}' -f $aolCode}
    
    Write-InfoLog '------------------------------------------------------------------------'
    Write-InfoLog 'Set-NoInstallMode right before importing labels via aldimport startup CMD'
    Write-InfoLog '------------------------------------------------------------------------'
    # This should avoid nasty 'Modelstore has been changed' shitty dialogs that distract build process.
    Set-AXModelStore -NoInstallMode -Server $sqlServer -Database $sqlModelDatabase -Verbose   
    
    try
    {
        Write-InfoLog ("Import {0} Lables : {1}" -f $modelName,(Get-Date))
        $AxModelLabelsFolder = Join-Path $Model.Directory $labelsFolder
        foreach ($file in (Get-ChildItem -Path $AxModelLabelsFolder -Filter "*.ald" -Recurse -ErrorAction SilentlyContinue))
        {
    		Write-InfoLog("Label file to import is {0} into {1}" -f $file.FullName, $ModelName)
            Write-InfoLog('Executing command with parameters: -aol={0} {1} -startupcmd=aldimport_{2} "-model=@{3}" -nocompileonimport -internal=noModalBoxes' -f $axLayer,$aolParm,$file.FullName,$Model.FullName)
            $arguments = '-aol={0} {1} "-startupcmd=aldimport_{2}" "-model=@{3}" -nocompileonimport -internal=noModalBoxes' -f $axLayer,$aolParm,$file.FullName,$Model.FullName
            $axProcess = Start-Process $ax32 -WorkingDirectory $clientBinDir -PassThru -WindowStyle minimized -ArgumentList $arguments -Verbose
            if ($axProcess.WaitForExit(60000*$ImportTimeout) -eq $false)
            {
                $axProcess.Kill()
                Throw ("Error: AX label import did not complete within {0} minutes" -f $ImportTimeout)
            }
        }
    }
    catch
    {
        Write-Infolog ('Import of labels for model {0} failed with error: {1}' -f $modelName, $error[0])
    }
    
    $xpoNamePrefix = ("Combined.{0}" -f $modelName)
    #$xpoName = ("Combined.{0}.xpo" -f $modelName)
    
    # Avoid calling Set-AXModelStore -NoInstallMode too often.
    
    #Write-InfoLog 'Set NoInstallMode right before importing xpos just in case'
    #Set-AXModelStore -NoInstallMode -Server $sqlServer -Database $sqlModelDatabase -Verbose   
    
    # Get the _sysCls.xpo filename using same vicious ps expression
    $sysClsXpoFileName = gci -Path "$currentLogFolder\*" -Include "*_sysCls.xpo" -Name -ErrorAction SilentlyContinue | select -f 1
    if ($sysClsXpoFileName -ne $null -and $sysClsXpoFileName  -ne '')
    {
        #$title = ('---------------Starting to import system classes via Import AOT Startup CMD at {0}---------------------' -f (Get-Date))
        #$barLine = new-object System.String ([char]'-', $title.Length)
        #Write-InfoLog $barLine
        #Write-Infolog $title
        
        Write-InfoLog '------------------------------------------------------------------------------------------------------'
        Write-InfoLog ('---------------Starting to import selected System Classes *_sysCls.xpo at {0}-------------------------' -f (Get-Date))
        
        Import-XPO $sysClsXpoFileName
        
        #$arguments = ('-lazyclassloading -lazytableloading "-StartupCmd=aotimport_{0}" -internal=noModalBoxes' -f (join-path $currentLogFolder $sysClsXpoFileName))
        #$axProcess = Start-Process $ax32 -WorkingDirectory $clientBinDir -PassThru -WindowStyle minimized -ArgumentList $arguments -OutVariable out
        #Write-InfoLog $out
        #if ($axProcess.WaitForExit(60000*$ImportTimeout) -eq $false)
        #{
            #Write-InfoLog("Error: AX AOT import did not complete within {0} minutes" -f $ImportTimeout)
        	#$axProcess.Kill()
        #}
        
        Write-Infolog ('---------------Finished importing of system classes via Import AOT Startup CMD at {0}-----------------' -f (Get-Date))
        #Write-InfoLog $barLine
        Write-InfoLog '------------------------------------------------------------------------------------------------------'
        
        # Copy AOTprco.log file into configured Client log dir
        #Copy-Item -Path (join-path (Split-Path -Parent $MyInvocation.MyCommand.Path) "AOTprco.log") -Destination $clientLogDir -Force -ErrorAction SilentlyContinue 
        Copy-PredefinedAOTprco
        
        # Run compile partial to compile just imported classes required for proper AOT import and exit after partial compilation
        $arguments = '{0} {1} -lazyclassloading -lazytableloading -StartupCmd=compilepartial -novsprojcompileall -internal=noModalBoxes' -f $compileInLayerParm,$aolParm
        Write-host ("Calling CompilePartial API : {0}" -f (Get-Date)) 
        $axProcess = Start-Process $ax32 -WorkingDirectory $clientBinDir -PassThru -WindowStyle minimized -ArgumentList $arguments -OutVariable out
        Write-host $out
        Write-InfoLog (" ")
        Write-InfoLog (" ")
        if ($axProcess.WaitForExit(60000) -eq $false)
        {
            $axProcess.Kill()
            # It's fine to just kill the process here
            #Throw ("Error: AX compile partial did not complete within {0} minutes" -f $CompileAllTimeout)
        }
    }
    
    # Get the _sysTab.xpo filename using vicious expression
    $sysTabXpoFileName = gci -Path "$currentLogFolder\*" -Include "*_sysTab.xpo" -Name -ErrorAction SilentlyContinue | select -f 1
    if ($sysTabXpoFileName -ne $null -and $sysTabXpoFileName -ne '')
    {
        #$title = ('---------------Starting to import system tables via Import AOT Startup CMD at {0}---------------------' -f (Get-Date))
        #$barLine = new-object System.String ([char]'-', $title.Length)
        #Write-InfoLog $barLine
        #Write-Infolog $title
        Write-InfoLog '------------------------------------------------------------------------------------------------------'
        Write-InfoLog ('---------------Starting to import system tables via Import AOT Startup CMD at {0}---------------------' -f (Get-Date))
        
        #Import-XPO $sysTabXpoFileName
        
        $arguments = ('-lazyclassloading -lazytableloading "-StartupCmd=aotimport_{0}" -internal=noModalBoxes' -f (join-path $currentLogFolder $sysTabXpoFileName))
        $axProcess = Start-Process $ax32 -WorkingDirectory $clientBinDir -PassThru -WindowStyle minimized -ArgumentList $arguments -OutVariable out
        Write-InfoLog $out
        if ($axProcess.WaitForExit(60000*$ImportTimeout) -eq $false)
        {
            Write-InfoLog("Error: AX AOT import did not complete within {0} minutes" -f $ImportTimeout)
        	$axProcess.Kill()
        }
        
        Write-Infolog ('---------------Finished importing of system tables via Import AOT Startup CMD at {0}------------------' -f (Get-Date))
        Write-InfoLog $barLine
    }

    foreach ($xpoName in (gci -Path "$currentLogFolder\*" -Include "$xpoNamePrefix*.xpo" -Exclude '*_sys*.xpo' -Name)) # Handle sysTab (System Tables) & sysCls (System Classes) separately
    {
        Import-XPO $xpoName
        if ([System.IO.Path]::GetFileNameWithoutExtension($xpoName) -eq $xpoNamePrefix)
        {
            #Import the second time as table references are not imported from the first time
            Write-InfoLog ('Import {0} the second time as table references are not imported from the first time' -f $xpoName)
            Import-XPO $xpoName
        }
    }
    
    Write-InfoLog ("Done Import combined xpo for model {0}: {1}" -f $modelName,(Get-Date))
    
    # Synchronize SysUserInfo table as it is critical for any startup commands further processing
    #Write-InfoLog '-----------------------------------------------------------------------------'
    #Write-InfoLog '---------------Starting to synchronize SysUserInfo table---------------------'
    #Synchronize-AX 'SysUserInfo'
    #Write-Infolog '---------------Synchronization of table SysUserInfo succeded-----------------'
    #Write-InfoLog '-----------------------------------------------------------------------------'
    
    <#try
    {
        Write-InfoLog ("Import {0} Lables : {1}" -f $modelName,(Get-Date))
        $AxModelLabelsFolder = Join-Path $Model.Directory $labelsFolder
        foreach ($file in (Get-ChildItem -Path $AxModelLabelsFolder -Filter "*.ald" -Recurse -ErrorAction SilentlyContinue))
        {
    		Write-InfoLog("Label file to import is {0} into {1}" -f $file.FullName, $ModelName)
            Write-InfoLog('Executing command with parameters: -aol={0} {1} -startupcmd=aldimport_{2} "-model=@{3}" -nocompileonimport -internal=noModalBoxes' -f $axLayer,$aolParm,$file.FullName,$Model.FullName)
            $arguments = '-aol={0} {1} "-startupcmd=aldimport_{2}" "-model=@{3}" -nocompileonimport -internal=noModalBoxes' -f $axLayer,$aolParm,$file.FullName,$Model.FullName
            $axProcess = Start-Process $ax32 -WorkingDirectory $clientBinDir -PassThru -WindowStyle minimized -ArgumentList $arguments -Verbose
            if ($axProcess.WaitForExit(60000*$ImportTimeout) -eq $false)
            {
                $axProcess.Kill()
                Throw ("Error: AX label import did not complete within {0} minutes" -f $ImportTimeout)
            }
        }
    }
    catch
    {
        Write-Infolog ('Import of labels for model {0} failed with error: {1}' -f $modelName, $error[0])
    }#>
    
    try
    {
        Build-VisualStudioProjects ($model)
    }
    catch
    {
        Write-InfoLog ('Building of VS projects failed with error: {0}' -f $error)
    }
    
    Write-InfoLog ("Import {0} finished : {1}" -f $modelName,(Get-Date)) 
}

function Create-PackagesConfig
{
    $assembliesHashSet = new-object System.Collections.Generic.HashSet[String]
    #$packagesContent = '<?xml version="1.0" encoding="utf-8"?>' + "`n" + '<packages>' + "`n"
    foreach ($refsFileName in (gci -Path "$currentLogFolder\*" -Include "*_refs.xpo" -Name))
    {
        foreach ($line in (Get-Content (join-path $currentLogFolder $refsFileName)))
        { 
            if ($line -match '\b(?<assemblyname>MMS\.Cloud\.Commands\.[a-zA-Z0-9._%+-]+)[ ,]+Version\=(?<version>\d+(?:\.\d+)+)\b')
            {
                $assemblyInfo = ('{0}:{1}' -f $matches['assemblyname'], $matches['version'])
                if ($assembliesHashSet.Contains($assemblyInfo) -ne $true)
                {
                    $assembliesHashSet.Add($assemblyInfo)
                }
                #$packagesContent += (('  <package id="{0}" version="{1}" targetFramework="net45" />' -f $matches['assemblyname'], $matches['version']) + "`n")
            }
        }
    }
    $packagesContent = '<?xml version="1.0" encoding="utf-8"?>' + "`n" + '<packages>' + "`n"
    foreach ($assemblyInfo in $assembliesHashSet)
    {
        $split = $assemblyInfo.Split([char[]]':')
        $packagesContent += (('  <package id="{0}" version="{1}" targetFramework="net45" />' -f $split[0], $split[1]) + "`n")
    }
    #| {$packagesContent += (('  <package id="{0}" version="{1}" targetFramework="net45" />' -f $matches['assemblyname'], $matches['version']) + "`n")}
    <#foreach ($line in $fileContent)
    {
        if ($line -match 'AssemblyDisplayName #MMS.Cloud.Commands')
        {
            #AssemblyDisplayName #MMS.Cloud.Commands.CMI, Version=1.0.4.0, Culture=neutral, 
            $line -match "AssemblyDisplayName #(?<assemblyname>MMS.Cloud.Commands\.[A-Z0-9._%+-]+)\,\bVersion\=(?<version>\d+(?:\.\d+)+)\b" }
            #@{$matches['assemblyname'] = $matches['version']}
        }
    }#>
    $packagesContent += "</packages>"
    $packagesConfigFileName = Join-Path $currentLogFolder packages.config
    $packagesContent | Out-File -filepath $packagesConfigFileName -Encoding UTF8
}

#
function Install-Packages
{
    # Setup NuGet for usage
    $template = 'nuget Sources {0} -Name {1} -Source "{2}" -UserName {3} -Password {4}'
    $verb = 'Remove'
    $name = 'mmm'
    $user = 'mmruser'
    $pwd = 'Qwerty12345'
    $feedSource = 'https://mediamarkt.myget.org/F/models/api/v2/'
    $expr = ($template -f $verb, $name, $feedSource, $user, $pwd)
    Invoke-Expression $expr
    $verb = 'Add'
    $expr = ($template -f $verb, $name, $feedSource, $user, $pwd)
    Invoke-Expression $expr
    $verb = 'Remove'
    $name = 'mmd'
    $feedSource = 'https://mediamarkt.myget.org/F/default/api/v2/'
    $expr = $expr = ($template -f $verb, $name, $feedSource, $user, $pwd)
    Invoke-Expression $expr
    $verb = 'Add'
    $expr = $expr = ($template -f $verb, $name, $feedSource, $user, $pwd)
    Invoke-Expression $expr
    # Ensure packages output directory is created
    New-Item (Join-Path $currentLogFolder 'Packages') -itemtype Directory -Force
    # Build nuget install expression
    $nugetInstallExpr = ('nuget install "{0}" -o "{1}"' -f (Join-Path $currentLogFolder packages.config), (Join-Path $currentLogFolder Packages))
    Invoke-Expression $nugetInstallExpr

    Install-PackagesToGAC ($currentLogFolder)
}

function Copy-Folder([string]$srcFolder, [string]$dstFolder, [int]$timeoutSec = 3600)
{
    #robocopy "$scrFolder" "$dstFolder" /s /z | Out-Null

    Write-Host "Source folder: $srcFolder" -ForegroundColor Green
    Write-Host "Destination folder: $dstFolder" -ForegroundColor Green

    $p = Start-Process robocopy -ArgumentList ('"{0}" "{1}" /s /z' -f $srcFolder, $dstFolder) -OutVariable out -PassThru
    if ($p.WaitForExit($timeoutSec * 1000) -ne $true)
    {
        Write-ErrorLog ('robocopy was unable to complete in {0} seconds' -f $timeoutSec)
        $p.Kill()
    }
    #Write-InfoLog "robocopy output`n: $out"
    return $dstFolder
}

function Copy-Packages([string]$serverPackagesFolder)
{
    if (Is-PathLocal $serverPackagesFolder)
    {
        return $serverPackagesFolder
    }

    $dstPath = join-Path $currentLogFolder Packages

    $ret = $dstPath

    New-Item $dstPath -ItemType Directory | Out-Null

    # Sleep for 1 seconds just to get things settle down after creating a new folder
    Start-Sleep -Seconds 1

    Copy-Folder $serverPackagesFolder $dstPath | Out-Null

    #robocopy "$serverPackagesFolder" "$dstPath" /s /z

    return $ret
}

function Copy-Modelstores([string]$serverPath)
{
    Write-Host "Server path: $serverPath" -ForegroundColor Blue

    #$serverPathCopy = $serverPath

    if (Is-PathLocal $serverPath)
    {
        return $serverPath
    }

    $localPath = Join-Path $currentLogFolder Modelstores
    $returnValue = $localPath
    New-Item $localPath -ItemType Directory | Out-Null

    Write-Host "Modelstore local folder: $localPath" -ForegroundColor Cyan

    if (Test-Path $localPath)
    {
        Write-Host "$localPath exists." -ForegroundColor Green
    }
    else
    {
        Write-Host "$localPath does not exist." -ForegroundColor Red
    }

    Write-Host "Server path again: $serverPath" -ForegroundColor Magenta
    #Write-Host "Server path copy: $serverPathCopy" -ForegroundColor Yellow

    #$serverPathCopy = 'Dummy'

    (Copy-Folder $serverPath $localPath) | Out-Null

    #robocopy "$serverPath" "$localPath" *.axmodelstore /s /z
    return $returnValue
}


function Is-PathLocal([string]$path)
{
    if ($path.StartsWith("\\"))
    {
        return $false
    }
    return $true
}

function Install-PackagesToGAC($packagesFolder)
{
    if (!$gacutilExe)
    {
        $gacutilExe = GetEnvironmentVariable('GacUtilPath')
        #'C:\Program Files (x86)\Microsoft SDKs\Windows\v8.1A\bin\NETFX 4.5.1 Tools\x64\gacutil.exe'
    }

    $localPackagesFolder = Copy-Packages $packagesFolder

    if ($localPackagesFolder -eq $null)
    {
        Write-Host "Local packages folder is null" -ForegroundColor Red
    }
    else
    {
        Write-Host "Local packages folder is not null" -ForegroundColor Green
    }

    Write-Host "Packages are now in the local location: $localPackagesFolder" -ForegroundColor Cyan
    Write-Host "Let's go get them installed now, shall we?" -ForegroundColor Cyan
    Start-Sleep -Seconds 5

    if ($localPackagesFolder -eq $null)
    {
        Write-Host "Local packages folder is null" -ForegroundColor Red
    }
    else
    {
        Write-Host "Local packages folder is not null" -ForegroundColor Green
    }

    <#$p = Test-Path -Path $localPackagesFolder

    if ($p -eq $true)
    {
        Write-Host "$localPackagesFolder exists" -ForegroundColor Green
    }
    else
    {
        Write-Host "$localPackagesFolder does not exist" -ForegroundColor Red
    }#>

    Start-Sleep -Seconds 5

    #$localPackagesFolder = Join-Path $currentLogFolder Packages

    $dlls = gci -Path "$localPackagesFolder" -Include *.dll -File -Recurse # | Select-Object -Property FullName
    ForEach ($dll in $dlls)
    {
        $p = Start-Process $gacutilExe -ArgumentList ('/i "{0}"' -f $dll.FullName) -OutVariable out -PassThru
        if ($p.WaitForExit(5000) -ne $true)
        {
            Write-ErrorLog 'GacUtil was unable to complete in 5 seconds'
            $p.Kill()
        }
        Write-Infolog $out
    }
}

function Copy-PredefinedAOTprco
{
    # Copy AOTprco.log file into configured Client log dir
    #Write-InfoLog ("Script startup dir: {0}" -f $script:startupDir)
    #Write-InfoLog ("Client log dir: {0}" -f $clientLogDir)
    Copy-Item -Path (join-path (Split-Path -Parent $script:startupDir) "AOTprco.log") -Destination $clientLogDir -Force -ErrorAction SilentlyContinue 
}

function Build-VisualStudioProjects([System.IO.FileSystemInfo]$model)
{
    Write-InfoLog ("Begin: Importing Visual Studio Project : {0}" -f (Get-Date)) 
    $manifest = new-object "System.Xml.XmlDocument"
    $manifest.Load($model.FullName)
    [String]$modelName=$manifest.SelectSingleNode("//Name").get_InnerText()
    $publisher=$manifest.SelectSingleNode("//Publisher").get_InnerText()

    $aolParm = ''
    if ($aolCode -ne '') {$aolParm = '/p:axAolCode={0}' -f $aolCode}
    $projPath = (join-path $AxBuildDir 'ImportVSProjects.proj')
    $logFile = join-path $currentLogFolder ('VSImport.{0}.log' -f $modelName)
    $errlogFile = join-path $currentLogFolder ('VSImportError.{0}.err' -f $modelName)
    $wrnlogFile = join-path $currentLogFolder ('VSImportWarning.{0}.wrn' -f $modelName)

    $arguments =  '"{0}" /p:srcFolder="{1}" /p:axLayer={2} {3} /p:ModelName="{4}" /p:Configuration=Release /l:FileLogger,Microsoft.Build.Engine;logfile="{5}" /p:ModelPublisher="{6}" /flp1:errorsonly;logfile="{7}" /flp2:WarningsOnly;logfile="{8}"' -f $projPath, $Model.Directory.FullName,$axLayer,$aolParm,$modelName,$logFile, $publisher,$errlogFile, $wrnlogFile
    $msBuild = "'{0}\msbuild.exe'" -f $msBuildPath
    Write-InfoLog 'Msbuild arguments'
    Write-InfoLog $arguments
    $axProcess = Start-Process "msbuild.exe" -WorkingDirectory $msBuildPath -PassThru -WindowStyle minimized -ArgumentList $arguments -Verbose
    if ($axProcess.WaitForExit(60000*$ImportTimeout) -eq $false)
    {
        $axProcess.Kill()
        Throw ("Error: Visual studio project didn't import in {0} min." -f $ImportTimeout)
    }

    $retError = $true
    if((test-path $logfile) -eq $true)
    {
        $fileContent = Get-Content $logFile -ErrorAction SilentlyContinue
        $lineNum = 0
        foreach ($line in $fileContent)
        {
            $err = $line.Contains('0 Error(s)')
            if($err -eq $true)
            {
                $retError = $false
            }
        }
    }

    if((test-path $errlogFile) -eq $true)
    {
        $fileContent = Get-Content $errlogFile -ErrorAction SilentlyContinue
        if($fileContent -eq $null -or $fileContent.Trim() -eq '')
        {
            $retError = $false        
        }
    }
    
    if($retError -eq $true)
    {
        Write-ErrorLog ('Failed to import VS project for model {0}' -f $modelName)
        #Write-TerminatingErrorLog('Failed to import VS project for model {0}' -f $modelName)
    }
}

function Create-ModelList
{
    Write-InfoLog ("Begin: Create-ModelList: {0}" -f (Get-Date))  

    $modelList = @()
    foreach($m in ($modelLayerMap.GetEnumerator()))
    {
        if($m -ne $null)
        {
            foreach($file in $m.Value)
            {
                $fileInfo = Get-Item -Path $file
                if($fileInfo -ne $null)
                {
                    if($fileInfo.Extension -eq '.axmodel')
                    {
                        $modelList += ($fileInfo.Name) +[char]10
                    }
                    elseif($fileInfo.Name -eq 'Model.xml')
                    {
                        $manifest = new-object "System.Xml.XmlDocument"
                        $manifest.Load($fileInfo.FullName)
                        [String]$modelName=$manifest.SelectSingleNode("//Name").get_InnerText()
                        $modelList += ('{0}.axmodel' -f $modelName) +[char]10
                    }
                }
            }
        }
    }

    $modelList | Out-File (join-path (Join-Path $dropLocation "Application\Appl\") "ModelList.txt") -Encoding Default
    Write-InfoLog $modelList
}

function Install-Model($folder, $file)
{
    Write-InfoLog ("Begin Install-Model: {0}" -f (Get-Date))
    Write-InfoLog ("Model file:")
    Write-InfoLog ($file)
    Write-InfoLog (" ")

    if($file -ne $null -and $folder -ne $null)
    {
        $extraArguments = ''
        if($importOverrideParams -ne $null)
        {
            if($importOverrideParams.Contains($file))
            {
                $extraArguments = $importOverrideParams.Get_Item($file)    
            }        
        }
        $file = join-path $folder $file
        if((test-path $file) -eq $true)   
        { 
            Write-InfoLog ("Calling Install-AXModel: {0}" -f (Get-Date))
            $exp = 'Install-AXModel {0} -File "{1}" -Details -NoPrompt -Server "{2}" -Database "{3}" -OutVariable out -Verbose -createparents' -f $extraArguments, $file, $sqlServer, $sqlModelDatabase
            Write-InfoLog $exp
            Invoke-Expression $exp 
            Write-InfoLog $out
        }
    }
    
    Write-InfoLog ("End Install-Model: {0}" -f (Get-Date))
}

function Export-ModelStore($modelStore)
{
    Write-InfoLog ("Begining AX modlel store export into $modelStore at {0}" -f (Get-Date))
    Write-InfoLog ("Calling Install-AXModelStore at {0}" -f (Get-Date))
    Export-AXModelStore -File $modelStore -Database $sqlModelDatabase -Details -Server $sqlServer -OutVariable out -Verbose
    Write-InfoLog ("End exporting AX model store into $modelStore at {0}" -f (Get-Date))
}

function Install-ModelStore($modelStore)
{
    Write-InfoLog ("Begin installing AX model store $modelStore at {0}" -f (Get-Date))
    
    if ((Test-Path $modelStore) -eq $true)
    {
        Write-InfoLog ("Calling Install-AXModelStore at {0}" -f (Get-Date))
        Import-AXModelStore -Database $sqlModelDatabase -Details -File $modelStore -NoPrompt -IdConflict "Overwrite" -Server $sqlServer -OutVariable out -Verbose
    }
    else
    {
        Write-ErrorLog "Model store file $modelStore does not exist"
    }
    
    Write-InfoLog ("End installing AX model store $modelStore at {0}" -f (Get-Date))
}

function Load-Models($folder, $list)
{
	Write-InfoLog ("Begin: Load-Models : {0}" -f (Get-Date)) 

    $modelList = (Join-Path $folder $list)
    if ((Test-Path $modelList) -ne $false)
    {
        $fileContent = Get-Content $modelList
        foreach ($line in $fileContent)
        {
            if(($line -ne $null) -and ($line.Trim() -ne ''))
            {
                Write-InfoLog('Calling Install-Model {0} {1}' -f $folder, $line.Trim())
                Install-Model $folder $line.Trim()
            }
        }       
    }   
    else
    {
        foreach ($file in (Get-ChildItem -Path $folder -Filter "*.axmodel" -ErrorAction SilentlyContinue))
        {
            Write-InfoLog('Calling Install-Model {0} {1}' -f $folder, $file.Name)
            Install-Model $folder $file.Name
        }
    }
	Write-InfoLog ("End: Load-Models : {0}" -f (Get-Date)) 
}

function Import-VSProjectsForModel($modelListFileName)
{
    $done = $false
    if (($modelListFileName -ne $null) -and (Test-Path $modelListFileName) -eq $true)
    {
        $fileContent = Get-Content $modelListFileName
        foreach ($line in $fileContent)
        {
            if(($line -ne $null) -and ($line.Trim() -ne ''))
            {
                $split = $line.Trim().Split('.')
                Build-VisualStudioProjects (Get-Item -Path (Join-Path (Join-Path $ApplicationSourceDir $split[0]) Model.xml))
                $done = $true
            }
        }
    }

    if ($done -eq $true)
    {
        Write-InfoLog 'Import of VS Projects into AX app succeeded'
    }
}

function Read-ModelList($folder)
{
    $models = @()

    $modelList = (Join-Path $folder ModelList.txt)
    if ((Test-Path $modelList) -ne $false)
    {
        $fileContent = Get-Content $modelList
        foreach ($line in $fileContent)
        {
            if(($line -ne $null) -and ($line.Trim() -ne ''))
            {
                $models += $line.Trim()
            }
        }       
    }   
    else
    {
        foreach ($file in (Get-ChildItem -Path $folder -Filter "*.axmodel" -ErrorAction SilentlyContinue))
        {
            $models += $file.Name
        }
    }

    return $models
}

function Create-ModelMap
{    
    if($dependencyPath -ne $null -and ((Test-path (join-path $dependencyPath 'appl')) -eq $true))
    {
        Set-ModelLayerOrder (join-path $dependencyPath 'appl')
    }
}

function Set-ModelLayerOrder($folder)
{
    Write-InfoLog ("Begin: Set-ModelLayerOrder: {0}" -f (Get-Date)) 

    $models = Read-ModelList ($folder)
    if($models -ne $null)
    {
        foreach($model in $models)
        {
            Write-InfoLog ("Calling Get-AXModelManifest: {0}" -f (Get-Date)) 
            $modelManifest = Get-AXModelManifest -file (join-path $folder $model) -Server $sqlServer -Database $sqlModelDatabase -OutVariable out -Verbose
            Write-InfoLog $out
            if($modelManifest -ne $null)
            {
                Add-LayerOrder (join-path $folder $model) $modelManifest.Layer
            }
        }
    }
    
    Write-InfoLog ("End: Set-ModelLayerOrder: {0}" -f (Get-Date)) 
}

function Get-LayerId([string]$layerName)
{    
    $query = "SELECT ID FROM {0}..Layer where Name = '{1}'" -f $sqlModelDatabase,$layerName
	
    $table = Invoke-Sqlcmd -Query "$query" -ServerInstance "$SQLserver" -Verbose
    foreach($row in $table)  
    {
        $layerId = $row.get_Item('ID')
    }
	
    if ($layerId -ge $higestLayer) 
    {
        $script:higestLayer = $layerId
        $script:compileInLayer = $layerName
    }

    $layerId
}   

function Add-LayerOrder($name, $modelLayer)
{
    $layerId = Get-LayerId($modelLayer)
    if($layerId -ne $null)
    {
        if($modelLayerMap.ContainsKey($layerId))
        {
            $list = $modelLayerMap.Get_Item($layerId)
            $list += $name
            $modelLayerMap.Set_Item($layerId, $list)
        }
        else
        {
            $list = @()
            $list += $name
            $modelLayerMap.Add($layerId, $list) 
        }
    }
}

function Import-BuildModels
{
	Write-InfoLog ("BEGIN: Import-BuildModels: {0}" -f (Get-Date)) 
    if($modelLayerMap -ne $null)
    {        
        foreach($m in ($modelLayerMap.GetEnumerator()))
        {
            if($m -ne $null)
            {
                foreach($file in $m.Value)
                {
                    $fileInfo = Get-Item -Path $file
                    if($fileInfo -ne $null)
                    {
                        if($fileInfo.Extension -eq '.axmodel')
                        {
                            Write-InfoLog('Calling Install-Model {0} {1}' -f $fileInfo.Directory.FullName, $fileInfo.Name)
                            Install-Model $fileInfo.Directory.FullName $fileInfo.Name
                        }
                        elseif($fileInfo.Name -eq 'Model.xml')
                        {
                            Write-InfoLog('Calling Install-AxCode {0}' -f $fileInfo)
                            Import-AxCode $fileInfo
                        }
                    }
                }
            }
        }
    }
    
	Write-InfoLog ("END: Import-BuildModels: {0}" -f (Get-Date)) 
}

function Verify-AOTObjectsImported
{
    $arguments = "-StartupCmd=verifyAOTObjects"
    $axProcess = Start-Process $ax32 -WorkingDirectory $clientBinDir -PassThru -WindowStyle minimized -ArgumentList $arguments -OutVariable out
    Write-host $out
    Write-InfoLog (" ")
    Write-InfoLog (" ")
    if ($axProcess.WaitForExit(60000*5) -eq $false)
    {
        $axProcess.Kill()
        Write-Host ('AX AOT objects verification did not complete within {0} minutes' -f 5) -ForegroundColor Yellow
        #Throw ("Error: AX AOT objects verification did not complete within {0} minutes" -f 5)
    }
    $ok = $true
    foreach ($file in (gci -Path "$clientLogDir\*" -File -Include *-AOTMissingObjects.txt -ErrorAction SilentlyContinue))
    {
        if ((Get-Content -Path $file.FullName |? {[string]::IsNullOrWhiteSpace($_) -eq $false} | Select -First 1) -ne $null)
        {
            $ok = $false
            break
        }
    }
    $ok
}

############################################################################################
#Collect-Build
############################################################################################
function Collect-Build([System.Array]$models)
{
    <#Write-InfoLog (" ") 
    Write-InfoLog ("*****************************************************************") 
    Write-InfoLog ("****************COMPILE AX***************************************") #>
	Write-InfoLog ("Begin: Collect-Build : {0}" -f (Get-Date)) 
    Write-InfoLog (" ") 
    Write-InfoLog (" ") 

    Start-AOS
    Write-InfoLog (" ") 
    Write-InfoLog (" ") 

    Write-InfoLog ("Collecting model files: {0}" -f (Get-Date)) 
    Write-InfoLog (" ") 

    if($models -ne $null)
    {
        foreach ($model in $models)
        {   
            $manifest = new-object "System.Xml.XmlDocument"
            $manifest.Load($model.FullName)
            [String]$modelName=$manifest.SelectSingleNode("//Name").get_InnerText()
            $modelFile = Join-Path (join-Path $dropLocation "Application\Appl\") ('{0}.axmodel' -f $modelName)
            Remove-Item $modelFile -ErrorAction SilentlyContinue
            try
            {
                if($signkey -ne $null)
                {
                    Write-InfoLog ("Calling Export-AXModel: {0}" -f (Get-Date)) 
                    $result = Export-AXModel -Model $modelName -Key $signkey -File $modelFile -Server $sqlServer -Database $sqlModelDatabase -OutVariable out -Verbose
                    Write-InfoLog $out
                }
                else
                {
                    Write-InfoLog ("Calling Export-AXModel: {0}" -f (Get-Date)) 
                    $result = Export-AXModel -Model $modelName -File $modelFile -Server $sqlServer -Database $sqlModelDatabase -OutVariable out -Verbose
                    Write-InfoLog $out
                }
            }
            catch
            {
                Write-ErrorLog ('An error occured during a call to Export-AXModel: {0}' -f $error[0])
            }
        }
    }
    
    if($dependencyPath -ne $null)
    {
        Write-InfoLog ("Collecting dependent model files: {0}" -f (Get-Date)) 
        Write-InfoLog (" ") 

        $Path = Join-Path $dependencyPath "Appl"
        if( (Test-path $Path) -eq $true)
        {
            foreach ($file in (Get-ChildItem -Path $Path -Filter "*.axmodel" -ErrorAction SilentlyContinue))
            {
                Copy-Item -Path (Join-Path $file.directory $file.Name) -Destination (Join-Path $dropLocation "Application\Appl") -Force 
            }
        }
    }       

    if($dependencyPath -ne $null)
    {
        Write-InfoLog ("Collecting binaries: {0}" -f (Get-Date)) 
        Write-InfoLog (" ") 
        $Path = Join-Path $dependencyPath "Bin"
        if( (Test-path $Path) -eq $true)
        {
            foreach ($file in (Get-ChildItem -Path $Path -ErrorAction SilentlyContinue))
            {
                if ($file.PSIsContainer -eq $False)
                {
                    Copy-Item -Path (Join-Path $file.directory $file.Name) -Destination (Join-Path $dropLocation "Application\bin") -Force 
                }   
            }
        }   
    }
    
    # Stop AOS before Exporting Model Store
    Stop-AOS
    
    Write-InfoLog ('Start of Export-AXModelStore at {0}' -f (Get-Date))
    $modelStoreFileName = Join-Path (join-Path $dropLocation "Application\Appl\") ('Build-{0}.axmodelstore' -f $CurrentVersion)
    Write-InfoLog ("Exporting AXModelStore to file: $modelStoreFileName")
    Export-ModelStore $modelStoreFileName
    Write-InfoLog ('End of Export-AXModelStore at {0}' -f (Get-Date))
        
    Write-InfoLog ("Completed: Collect-Build : {0}" -f (Get-Date)) 
}
############################################################################################
#END Collect-Build
############################################################################################

############################################################################################
#Clean-Build
############################################################################################

function Clean-Build
{
	Write-InfoLog ("Begin: Clean-Build : {0}" -f (Get-Date)) 
    
    Write-InfoLog ("Calling Set-AXModelStore: {0}" -f (Get-Date)) 
    Set-AXModelStore -NoInstallMode -Server $sqlServer -Database $sqlModelDatabase -OutVariable out -Verbose
    Write-InfoLog $out
    
    Write-InfoLog '-----------------------------------------'

	Write-InfoLog ("Deleting models : {0}" -f (Get-Date)) 
    if($scriptName -eq 'DEPLOY')
    {
        Clean-Models 
    }
    else
    {
        Clean-BuildModels
    }
    
    Write-InfoLog ("Models deleted : {0}" -f (Get-Date))

    Clean-DependentBinaries
    
    Write-InfoLog ("Calling Set-AXModelStore: {0}" -f (Get-Date)) 
    Set-AXModelStore -NoInstallMode -Server $sqlServer -Database $sqlModelDatabase -OutVariable out -Verbose
    Write-InfoLog $out
    Stop-AOS
    # TODO: set proper .modelstore filename here. Probably this should be extracted to the parameters.txt file.
    Install-ModelStore (join-path $backupModelStoreFolder "CleanAXR3.axmodelstore")
    Write-InfoLog ('---------------------------------------------------------------')
    Write-Infolog 'Clean modelstore has been restored'
    Write-InfoLog ('---------------------------------------------------------------')
    Remove-Item -Path (Join-Path $clientLogDir "*.*") -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $env:LOCALAPPDATA "ax_*.auc") -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $serverApplDir "*.a*") -ErrorAction SilentlyContinue
    
    Write-InfoLog ('------------------------Restoring AX Database------------------')
    Restore-Database $sqlDatabase $CleanBackupFileName
    Write-InfoLog ('--------------------Restoring AX Database Done-----------------')
    Start-AOS
    Synchronize-AX
	Write-InfoLog ("Completed: Clean-Build : {0}" -f (Get-Date)) 
    # Call Set-AXModelStore -NoInstallMode one more time after importing Clean model store and restroring Database backup
    #Write-InfoLog ("Calling Set-AXModelStore: {0}" -f (Get-Date)) 
    #Set-AXModelStore -NoInstallMode -Server $sqlServer -Database $sqlModelDatabase -OutVariable out -Verbose
    #Write-InfoLog $out
}

function Clean-BuildModels
{
	Write-InfoLog ("BEGIN: Clean-BuildModels: {0}" -f (Get-Date)) 
    if($modelLayerMap -ne $null)
    {      
        $modelLayerMap = $modelLayerMap.GetEnumerator() | Sort-Object Name -descending
        if($modelLayerMap -eq $null)
        {
            $modelLayerMap = @{}
        }
        if($modelLayerMap.GetType().Name -eq 'DictionaryEntry')
        {
            $modelLayerMap = @{ $modelLayerMap.Name = $modelLayerMap.Value}
        }
  
        foreach($m in ($modelLayerMap.GetEnumerator()))
        {
            if($m -ne $null)
            {
                foreach($file in $m.Value)
                {
                    $fileInfo = Get-Item -Path $file
                    if($fileInfo -ne $null)
                    {
                        if($fileInfo.Extension -eq '.axmodel')
                        {
                            Delete-ModelByFileName $fileInfo.FullName
                        }
                        elseif($fileInfo.Name -eq 'Model.xml')
                        {
                            Delete-AXModel $fileInfo.FullName
                        }
                    }
                }
            }
        }
    }
    
	Write-InfoLog ("END: Clean-BuildModels: {0}" -f (Get-Date)) 
}

function Clean-Models
{
	Write-InfoLog ("Begin: Clean-Models : {0}" -f (Get-Date)) 
    $folder = (join-Path $dropLocation "Application\Appl\")
    $modelList = (Join-Path $folder 'ModelList.txt')
    if ((Test-Path $modelList) -ne $false)
    {
        Write-InfoLog ("Getting models from modellist.txt: {0}" -f $modelList) 
        $models = @()
        $fileContent = Get-Content $modelList
        foreach ($line in $fileContent)
        {
            if(($line -ne $null) -and ($line.Trim() -ne ''))
            {
                $models += $line.Trim()
            }
        }
        
        for ($idx = $models.Length - 1; $idx -ge 0;$idx--)
        {   
            $modelFile = (join-path $folder $models.Get($idx))
            Delete-ModelByFileName $modelFile
        }                        
    }   
    else
    {
        Write-Warning "Running clean models without sequence might cause issues."
        foreach ($file in (Get-ChildItem -Path $folder -Filter "*.axmodel" -ErrorAction SilentlyContinue))
        {
            Delete-ModelByFileName $file.FullName
        }
    }
	Write-InfoLog ("End: Clean-Models : {0}" -f (Get-Date)) 
}

function Delete-ModelByFileName($model)
{
    Write-InfoLog ("Begin: Delete-ModelByFileName : {0}" -f (Get-Date)) 
    
    Write-InfoLog ("Calling Get-AXModelManifest: {0}" -f (Get-Date)) 
    if((test-path $model) -eq $true)
    {
        $modelManifest = Get-AXModelManifest -file $model -Server $sqlServer -Database $sqlModelDatabase -OutVariable out -Verbose
        Write-InfoLog $out
        if($modelManifest -ne $null)
        {
            try{
            Write-InfoLog ("Calling Uninstall-AXModel: {0}" -f (Get-Date))
            $Result = Uninstall-AXModel -Model $modelManifest.Name -Details -NoPrompt -Server $sqlServer -Database $sqlModelDatabase -OutVariable out -Verbose
            Write-InfoLog $out
            }
            catch
            {
                Write-InfoLog "Uninstall-AXModel Failed."
                Write-InfoLog $Error[0]
            }
        }
    }

    Write-InfoLog ("End: Delete-ModelByFileName : {0}" -f (Get-Date)) 
}

function Delete-AXModel($model)
{
    $manifest = new-object "System.Xml.XmlDocument"
    $manifest.Load($Model)
    [String]$ModelName=$manifest.SelectSingleNode("//Name").get_InnerText()
    Write-InfoLog ("Begin: Delete-AXModel {0} at {1}" -f $ModelName, (Get-Date)) 

    $modelData = Get-AXModel -Model $ModelName -Server $sqlServer -Database $sqlModelDatabase
    if($modelData -ne $null)
    {
        $Result = Uninstall-AXModel -Model $ModelName -NoPrompt -Server $sqlServer -Database $sqlModelDatabase
    }
    
    Write-InfoLog ("Completed: Delete-AXModel {0} at {1}" -f $ModelName, (Get-Date)) 
}

function Clean-DependentBinaries
{
    Stop-AOS
	Write-InfoLog ("Deleting dependent binaries : {0}" -f (Get-Date)) 
    if($dependencyPath -ne $null -and ((test-path $dependencyPath) -eq $true))
    {
        $Path = Join-Path $dependencyPath "Bin"
        if( (Test-path $Path) -eq $true)
        {
            foreach ($file in (Get-ChildItem -Path $Path -ErrorAction SilentlyContinue))
            {
                Remove-item (Join-Path $serverBinDir $file.Name) -Force -ErrorAction SilentlyContinue 
                Remove-item (Join-Path $clientBinDir $file.Name) -Force -ErrorAction SilentlyContinue 
            }
        }     
    }
    Start-AOS
	Write-InfoLog ("Dependent binaries deleted: {0}" -f (Get-Date)) 
}

function Restore-Database($dbName, $backupFileName)
{
    # Load assemblies
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
    [Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
    [Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoEnum") | Out-Null

    $relocateData = @()
    $svr = new-object ('Microsoft.SqlServer.Management.Smo.Server')  $sqlServer
    
    # Create restore object and specify its settings
    $smoRestore = new-object("Microsoft.SqlServer.Management.Smo.Restore")
    $smoRestore.Database = $dbName
    $smoRestore.NoRecovery = $false;
    $smoRestore.ReplaceDatabase = $true;
    $smoRestore.Action = "Database"
    
    # Create location to restore from
    $backupDevice = New-Object ("Microsoft.SqlServer.Management.Smo.BackupDeviceItem") ($backupFileName, "File")
    $smoRestore.Devices.Add($backupDevice)
    
     # Get the file list from backup file
    $dbFileList = $smoRestore.ReadFileList($svr)

    # The logical file names should be the logical filename stored in the backup media
    $DataLogicalFileName = $dbFileList.Select("Type = 'D'")[0].LogicalName
    $LogLogicalFileName = $dbFileList.Select("Type = 'L'")[0].LogicalName
    
    Write-Host "Backup data logical file name: $DataLogicalFileName"
    Write-Host "Backup log logical file name: $LogLogicalFileName"

    foreach ($db in $svr.Databases | Where-Object {$_.Name -eq $dbName})
    {
        foreach ($fg in $db.FileGroups)
        {
            # Traverse data files
            foreach ($fl in $fg.Files)
            {
                $relocateItem = New-Object Microsoft.SqlServer.Management.Smo.RelocateFile
                $relocateItem.PhysicalFileName = $fl.FileName
                $relocateItem.LogicalFileName = $DataLogicalFileName
                Write-Host ('{0} <--> {1}' -f $relocateItem.LogicalFileName, $relocateItem.PhysicalFileName)
                $relocateData += $relocateItem
            }
            # Traverse log files
            foreach ($fl in $db.LogFiles)
            {
                $relocateItem = New-Object Microsoft.SqlServer.Management.Smo.RelocateFile
                $relocateItem.PhysicalFileName = $fl.FileName
                $relocateItem.LogicalFileName = $LogLogicalFileName
                Write-Host ('{0} <--> {1}' -f $relocateItem.LogicalFileName, $relocateItem.PhysicalFileName)
                $relocateData += $relocateItem
            }
        }
    }
    
    Write-host ('Relocation data length == {0}' -f $relocateData.Length)

    $svr.KillAllProcesses($dbName)
    #Write-InfoLog "Restore-SqlDatabase -ServerInstance $sqlServer -Database $dbName -BackupFile $backupFileName -ReplaceDatabase"
    Restore-SqlDatabase -ServerInstance $sqlServer -Database $dbName -BackupFile $backupFileName -RelocateFile $relocateData -ReplaceDatabase
}

############################################################################################
#END Clean-Build
############################################################################################

# New TFS Extensions
function Sync-TFSWorkspace($tfsUrl, $localPath)
{
    $tfs = GET-TFS $tfsUrl
    if ($tfs.HasAuthenticated -ne $true)
    {
        $wc = New-Object System.Net.WebClient
        $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        #Invoke-Command -ComputerName mow04dev014 -ScriptBlock { $tfs.Authenticate() } -credential $cred
        $tfs.Authenticate()
    }
    $workspace = $tfs.VCS.GetWorkspace($localPath)
    if ($workspace -eq $null)
    {
        throw "Workspace mapped to $localPath is not found"
    }
    Write-InfoLog ("Sync files started") 
    $g = $workspace.Get()
    $g # Should we even return a value?
}


############################################################################################
#TFS
############################################################################################
function GET-TFS (
    [string] $serverName = $(Throw 'serverName is required')
)
{
    # load the required dll
    [void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.TeamFoundation.Client")

    $propertiesToAdd = (
        ('VCL', 'Microsoft.TeamFoundation.VersionControl.Client', 'Microsoft.TeamFoundation.VersionControl.Client.VersionControlLabel'),
        ('VCS', 'Microsoft.TeamFoundation.VersionControl.Client', 'Microsoft.TeamFoundation.VersionControl.Client.VersionControlServer')
    )

    #$cred = Get-Credential

    <#$netCred = New-Object System.Net.NetworkCredential($cred.UserNamed, $cred.Password)
    [BasicAuthCredential]$basicCred = New-Object Microsoft.TeamFoundation.Client.BasicAuthCredential($netCred)
    [TfsClientCredentials]$tfsCred = New-Object Microsoft.TeamFoundation.Client.TfsClientCredentials($basicCred)

    [psobject] $tfs = New-Object 'Microsoft.TeamFoundation.Client.TeamFoundationServer' ($serverName, $tfsCred)

    
    #>
    [psobject] $tfs = [Microsoft.TeamFoundation.Client.TeamFoundationServerFactory]::GetServer($serverName)
       foreach ($entry in $propertiesToAdd) {
        $scriptBlock = '
            $asm = [System.Reflection.Assembly]::LoadWithPartialName("{0}")
            Write-Host $asm.ToString()
            $t = $asm.GetType("Microsoft.TeamFoundation.VersionControl.Client.VersionControlServer")
            Write-Host $t.AssemblyQualifiedName -foregroundcolor cyan
            $this.GetService([{1}])
        ' -f $entry[1],$entry[2]
        $tfs | add-member scriptproperty $entry[0] $ExecutionContext.InvokeCommand.NewScriptBlock($scriptBlock)
        }

    # $tfs.EnsureAuthenticated()
        
    # Sleep for 5 secs
    #Write-Host 'Starting to sleep for 5 seconds for the first time'
    #Start-Sleep -s 5

    # Check HasAuthenticated flag
    Write-Host "tfs.HasAuthenticated == $($tfs.HasAuthenticated)"

    if ($tfs.HasAuthenticated -ne $true)
    {
        $wc = New-Object System.Net.WebClient
        $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        #Invoke-Command -ComputerName mow04dev014 -ScriptBlock { $tfs.Authenticate() } -credential $cred
        $tfs.Authenticate()
    }

    # Inspect TFS variable
    Write-Host (Get-Variable -Name tfs)

    # Sleep for 5 secs
    #Write-Host 'Starting to sleep for 5 seconds for the second time'
    #Start-Sleep -s 5

    return $tfs
}

function Apply-Label
{
    try
    {
        Write-InfoLog ("Creating label : {0}" -f (Get-Date)) 

        $tfs = GET-TFS $tfsUrl
        $labelName = ($tfsLabelPrefix -f $currentVersion)
        $comments = ($labelComments -f $currentVersion)
        $label = new-object Microsoft.TeamFoundation.VersionControl.Client.VersionControlLabel  ($tfs.vcs, $labelName, $tfs.VCS.AuthenticatedUser, $null, $comments)
        $itemSpec = new-object Microsoft.TeamFoundation.VersionControl.Client.ItemSpec ($TFSWorkspace, 2)
        $versionSpec = [Microsoft.TeamFoundation.VersionControl.Client.VersionSpec]::Latest
        $labelItemSpec += new-object Microsoft.TeamFoundation.VersionControl.Client.LabelItemSpec ($itemSpec, $versionSpec, $false);

        # construct the label
        $xyz = $tfs.vcs.CreateLabel($label, $labelItemSpec, 1)
        Write-InfoLog ("Label Created")
        Write-InfoLog (" ")
    }
    catch
    {
        Write-InfoLog ('Apply labels failed with error: {0}' -f $error[0])
    }
}

function Sync-FilesToALabel
{    
    Write-InfoLog ("Sync files {0}" -f (get-date)) 
    [void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.TeamFoundation.VersionControl.Client")

    $tfs = GET-TFS $tfsUrl
    $itemSpec = new-object Microsoft.TeamFoundation.VersionControl.Client.ItemSpec ($TFSWorkspace, 2)
    if($tfsLabel -ne $null)
    {
        $labelSpec = new-object Microsoft.TeamFoundation.VersionControl.Client.LabelVersionSpec ($tfslabel)
    }
    else
    {
        $labelSpec = [Microsoft.TeamFoundation.VersionControl.Client.VersionSpec]::Latest
    }

    $script:w = $tfs.VCS.TryGetWorkspace($ApplicationSourceDir)
    if ($w -eq $null)
    {
        Write-Infolog "Local path $ApplicationSourceDir is not associated with a TFS Workspace"
        $guid = [Guid]::NewGuid().ToString()
        $wName = 'AXBuild_' + $guid
        Write-InfoLog ("Creating workspace {0}" -f $wName) 
        $labelName = ($tfsLabelPrefix -f $currentVersion)
        <#$label = new-object Microsoft.TeamFoundation.VersionControl.Client.VersionControlLabel  ($tfs.vcs, $labelName, $tfs.VCS.AuthenticatedUser, $null, $labelComments)
        $itemSpec = new-object Microsoft.TeamFoundation.VersionControl.Client.ItemSpec ($TFSWorkspace, 2)
        $versionSpec = [Microsoft.TeamFoundation.VersionControl.Client.VersionSpec]::Latest#>
    
        #Instrumentation
        Write-InfoLog ("Calling CreateWorkspace with the following arguments: workspaceName = {0}, owner = {1}" -f $wName, $tfs.VCS.AuthenticatedUser)
    
        $script:w = $tfs.VCS.CreateWorkspace($wName, $tfs.VCS.AuthenticatedUser)
        $w.Map($tfsWorkspace, $ApplicationSourceDir)
    }

    #$script:w = $tfs.VCS.GetWorkspace($ApplicationSourceDir)
    
    try
    {
        $exclusionList = Remove-OldSourceControlledFiles $ApplicationSourceDir
        #Write-InfoLog ("Remove old source controlled files from {0}" -f $ApplicationSourceDir)
        #Remove-Item -Path "$ApplicationSourceDir\*" -Exclude "Definition" -Force -Recurse -ErrorAction SilentlyContinue 
        # Try to move this call to workspace creation block upwards
        #$w.Map($tfsWorkspace, $ApplicationSourceDir)
        Write-InfoLog ("Sync files started")
        $g = $w.Get($labelSpec, 1)

        Write-Host "Setting the synched files to be ReadOnly" -ForegroundColor Cyan

        # Set all AOT source controlled files synched to be ReadOnly except one's we've captured in the exclusion list
        gci -Path $ApplicationSourceDir -Exclude $exclusionList -Include *.xpo, *.csproj, *.dynamicsproj -File -Recurse `
        |% {sp $_ IsReadOnly $true}

        Write-Host "Setting synched files to ReadOnly Done. $(Get-Date)" -ForegroundColor Cyan
       
        Write-InfoLog ("Sync files done") 
        Write-InfoLog (" ")
    }
    catch
    {
        Write-TerminatingErrorLog "Exception while synchronizing TFS workspace." $Error[0]
    }
    
    Write-InfoLog ("End Sync files {0}" -f (get-date))     
}

function Build-PendingChangesList([string]$sourcePath)
{
    $exclusionList = @()
    $items = gci -Path "$sourcePath" -File -Recurse -Include *.xpo, *.csproj, *.dynamicsproj -ErrorAction SilentlyContinue `
    |? {$_.IsReadOnly -eq $false}`
    |% {$exclusionList += $_.Name}
    $exclusionList
}

function Remove-OldSourceControlledFiles([string]$sourceDir)
{
    Write-Host "Removing old source controlled files from $sourceDir" -ForegroundColor Cyan
    # First off: build exclusion list of cheked out files (pending changes) by looking ast the readonly property
    $exclusionList = Build-PendingChangesList $sourceDir
    Remove-Item -Path "$sourceDir" -Include *.xpo, *.csproj, *.dynamicsproj -Exclude $exclusionList -Force -Recurse -ErrorAction SilentlyContinue
    $exclusionList
}

function Sync-Files
{    
    Write-InfoLog ("Remove old source controlled filed from {0}" -f $ApplicationSourceDir)

    $exclusionList = Remove-OldSourceControlledFiles $ApplicationSourceDir

    #Remove-Item -Path "$ApplicationSourceDir\*" -Exclude "Definition" -Force -Recurse -ErrorAction SilentlyContinue 
    
    # Sleep for 5 minuetes to provide the user enough time to ensure that the $ApplicationSourceDir folder has been cleared and no old (obsolete) xpos has left.
    #Start-Sleep -s 300

    Write-InfoLog ("Sync files {0}" -f (get-date)) 
    
    Write-InfoLog ("tfsUrl = {0}" -f $tfsUrl)

    $tfs = GET-TFS $tfsUrl

    $guid = [Guid]::NewGuid().ToString()
    $wName = 'AXBuild_' + $guid
    Write-InfoLog ("Creating workspace {0}" -f $wName) 
    $labelName = ($tfsLabelPrefix -f $currentVersion)
    $label = new-object Microsoft.TeamFoundation.VersionControl.Client.VersionControlLabel  ($tfs.vcs, $labelName, $tfs.VCS.AuthenticatedUser, $null, $labelComments)
    $itemSpec = new-object Microsoft.TeamFoundation.VersionControl.Client.ItemSpec ($TFSWorkspace, 2)
    $versionSpec = [Microsoft.TeamFoundation.VersionControl.Client.VersionSpec]::Latest
    
    #Instrumentation
    Write-InfoLog ("Calling CreateWorkspace with the following arguments: workspaceName = {0}, owner = {1}" -f $wName, $tfs.VCS.AuthenticatedUser)
    
    $script:w = $tfs.VCS.CreateWorkspace($wName, $tfs.VCS.AuthenticatedUser)
    try
    {
        $localWorkspaceFolder = Split-Path $ApplicationSourceDir -Parent

        Write-InfoLog('tfsWorkspace: {0}' -f $tfsWorkspace)
        Write-InfoLog('ApplicationSourceDir: {0}' -f $ApplicationSourceDir)
        Write-Infolog('Local TFS workspace folder: {0}' -f $localWorkspaceFolder)

        <#$workspaces = $tfs.VCS.QueryWorkspaces($null, $null, $null, [Microsoft.TeamFoundation.VersionControl.Client.WorkspacePermissions]::Administer)
        if ($workspaces -eq $null)
        {
            Write-Host 'There are no workspaces defined' -ForegroundColor Red -BackgroundColor Black
        }
        else
        {
            Write-Host ('{0} workspaces have been found' -f $workspaces.Length) -ForegroundColor Cyan
            foreach ($wspc in $workspaces)
            {
                [Microsoft.TeamFoundation.VersionControl.Client.WorkingFolder]$wspace = $wspc
                Write-Host "Disambiguated display name: ${$wspc.DisambiguatedDisplayName}" -ForegroundColor Cyan
            }
        }#>

        <#$workspace = $tfs.VCS.GetWorkspace($ApplicationSourceDir)
        if ($workspace -ne $null)
        {
            Write-Host ('Seem like local workspace {0} is mapped to somthing in TFS, trying to delete mapping by TFS workspace' -f $ApplicationSourceDir) -ForegroundColor Cyan
            $tfs.VCS.DeleteMapping($workspace)
        }#>

        <#if ($w.IsLocalPathMapped($localWorkspaceFolder))
        {
            Write-InfoLog('Path {0} is locally mapped in TFS' -f $ApplicationSourceDir)
            Write-Host ('Trying to remove mapping for the local workspace folder: {0}' -f $localWorkspaceFolder) -ForegroundColor Cyan
            $local:workspace = new-object Microsoft.TeamFoundation.VersionControl.Client.WorkingFolder ($tfsWorkspace, $localWorkspaceFolder)
            $w.DeleteMapping($local:workspace)
        }
        else
        {
            Write-InfoLog('Path {0} is not locally mapped in TFS' -f $localWorkspaceFolder)
        }#>

        $w.Map($tfsWorkspace, $ApplicationSourceDir)
        #$w.Map($wName, $ApplicationSourceDir)    
        
        Write-InfoLog ("Sync files started") 
        $g = $w.Get($versionSpec, 1)

        Write-Host "Setting the synched files to be ReadOnly" -ForegroundColor Cyan

        # Set all AOT source controlled files synched to be ReadOnly except one's we've captured in the exclusion list
        gci -Path $ApplicationSourceDir -Exclude $exclusionList -Include *.xpo, *.csproj, *.dynamicsproj -File -Recurse `
        |% {sp $_ IsReadOnly $true}

        Write-Host "Setting synched files to ReadOnly Done. $(Get-Date)" -ForegroundColor Cyan
       
        Write-InfoLog ("Sync files done") 
        Write-InfoLog (" ")
    }
    catch
    {
        Write-TerminatingErrorLog ("Exception while mapping TFS workspace: {0}" -f $Error[0])
    }
    
    Write-InfoLog ("End Sync files {0}" -f (get-date))     
}

function Enable-VCS
{
    Write-InfoLog ("Starting Enable-VCS: {0}" -f (Get-Date)) 
    try
    {
        if($vcsDisabled -eq $true)
        {
            $query = "update {0}..sysversioncontrolparameters set VCSENABLED=0" -f $sqlDatabase
            Invoke-Sqlcmd -Query "$query" -ServerInstance "$SQLserver" -Verbose
        }
    }
    catch{
       Write-TerminatingErrorLog  "Exception while updating version control parameters" $Error[0]
    }    
    
    Write-InfoLog ("Done Enable-VCS: {0}" -f (Get-Date))
}

function Disable-VCS
{
    Write-InfoLog ("Starting Disable-VCS: {0}" -f (Get-Date)) 
    try
    {
        #Compiler settings
        $query = "select VCSENABLED from {0}..sysversioncontrolparameters" -f $sqlDatabase
        $table = Invoke-Sqlcmd -Query "$query" -ServerInstance "$SQLserver" -Verbose
        if($table -ne $null)
        {
            foreach($row in $table)  
            {
                $VCSEnabled = $row.get_Item('VCSENABLED')
            }
            if  ($VCSEnabled -eq 0)
            {
                $query = "update {0}..sysversioncontrolparameters set VCSENABLED=1" -f $sqlDatabase
                Invoke-Sqlcmd -Query "$query" -ServerInstance "$SQLserver" -Verbose
                $script:vcsDisabled = $true
            }
        }
    }
    catch
    {
       Write-TerminatingErrorLog  "Exception while updating version control parameters" $Error[0]
    }    
    
    Write-InfoLog ("Done Disable-VCS: {0}" -f (Get-Date))
}


function Clear-TFSCache
{
    $pathTemplate = "C:\Users\{0}\AppData\Local\Microsoft\Team Foundation\{1}\Cache\*"
    $versions = @("3.0", "5.0")
    foreach ($version in $versions)
    {
        Remove-Item -Path ($pathTemplate -f [Environment]::UserName, $version) -Recurse -Force -ErrorAction SilentlyContinue
    }
}

############################################################################################
#END TFS
############################################################################################

Add-Type -AssemblyName system.ServiceProcess

#New-Alias "??" Coalesce

# SIG # Begin signature block
# MIIatwYJKoZIhvcNAQcCoIIaqDCCGqQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUx1/0pfCKtyvh/ORuubtQAVDe
# 45ugghWCMIIEwzCCA6ugAwIBAgITMwAAADaeewBVssNdLAAAAAAANjANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTMwMzI3MjAwODI4
# WhcNMTQwNjI3MjAwODI4WjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OkJCRUMtMzBDQS0yREJFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvBmYmWSq9tq9
# TdEuQs9m7Ncr2HJUyU3z+i4JBkTQEzAtoukQKnUbP1Zcd7f66bz41enN9MiOmyvw
# wBGa8Ve4bL0GjdbBYY/WMOEmqQom0XbagJXqfzAD3A/A1k2Gq7raHn51pQLb4TCz
# QQedDDDfugtCawe9Q8lyj9UZDl3j9fsx7XFsiK7nO3ro+G4X3cv2B/j+IQjpIDoQ
# 4fNJMWfp0jOWwRFXy4v7KnDPO/G73m61dLk9U70D5NzKsvcWvdmac8I+yUdiQlfF
# CsiYycRYKd4O6/J8GPvEq9cLl7UZpgtJODqwUwSIBg6iirll6g5svVqt0Hue0Xoy
# R/Ie0SNuNQIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFMwfZPc12efmJAP0En8Ep94v
# Gr5hMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAFsHcVX7PnDXFDRFUmUNen+e7t7n+WMlVp3qsYH318h82rXp
# Td6wCRG7bLcMMjUSAOCOn7il2jt68y2GkZ6QRIz3NGE2UOZoj1wNCED4Cw2r1Q9F
# SftgR7r5wENBsu5oIGIWtaaf1lNZx7tQoLR8kElP01X27HxYUR7eEtfbfjv8cEa+
# ZQ6ER/tJWAi7eE2Lx8G2nKhFQiAkwQdyfwhXdZ9SlE8UYzkFzK0xA4EHEHqRfzqK
# 2r871svWmnJj/BHgkVIR5Ul/age2xSK+pVTouRQEZLAuWB9H32XIlA0rJTRinaHQ
# hiO16llZ8Oo61VIvwHLHCIUlQPbc4RXEUNTz0ukwggTsMIID1KADAgECAhMzAAAA
# sBGvCovQO5/dAAEAAACwMA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBMB4XDTEzMDEyNDIyMzMzOVoXDTE0MDQyNDIyMzMzOVowgYMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIx
# HjAcBgNVBAMTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAOivXKIgDfgofLwFe3+t7ut2rChTPzrbQH2zjjPmVz+l
# URU0VKXPtIupP6g34S1Q7TUWTu9NetsTdoiwLPBZXKnr4dcpdeQbhSeb8/gtnkE2
# KwtA+747urlcdZMWUkvKM8U3sPPrfqj1QRVcCGUdITfwLLoiCxCxEJ13IoWEfE+5
# G5Cw9aP+i/QMmk6g9ckKIeKq4wE2R/0vgmqBA/WpNdyUV537S9QOgts4jxL+49Z6
# dIhk4WLEJS4qrp0YHw4etsKvJLQOULzeHJNcSaZ5tbbbzvlweygBhLgqKc+/qQUF
# 4eAPcU39rVwjgynrx8VKyOgnhNN+xkMLlQAFsU9lccUCAwEAAaOCAWAwggFcMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBRZcaZaM03amAeA/4Qevof5cjJB
# 8jBRBgNVHREESjBIpEYwRDENMAsGA1UECxMETU9QUjEzMDEGA1UEBRMqMzE1OTUr
# NGZhZjBiNzEtYWQzNy00YWEzLWE2NzEtNzZiYzA1MjM0NGFkMB8GA1UdIwQYMBaA
# FMsR6MrStBZYAck3LjMWFrlMmgofMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY0NvZFNpZ1BDQV8w
# OC0zMS0yMDEwLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljQ29kU2lnUENBXzA4LTMx
# LTIwMTAuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQAx124qElczgdWdxuv5OtRETQie
# 7l7falu3ec8CnLx2aJ6QoZwLw3+ijPFNupU5+w3g4Zv0XSQPG42IFTp8263Os8ls
# ujksRX0kEVQmMA0N/0fqAwfl5GZdLHudHakQ+hywdPJPaWueqSSE2u2WoN9zpO9q
# GqxLYp7xfMAUf0jNTbJE+fA8k21C2Oh85hegm2hoCSj5ApfvEQO6Z1Ktwemzc6bS
# Y81K4j7k8079/6HguwITO10g3lU/o66QQDE4dSheBKlGbeb1enlAvR/N6EXVruJd
# PvV1x+ZmY2DM1ZqEh40kMPfvNNBjHbFCZ0oOS786Du+2lTqnOOQlkgimiGaCMIIF
# vDCCA6SgAwIBAgIKYTMmGgAAAAAAMTANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZIm
# iZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQD
# EyRNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTAwODMx
# MjIxOTMyWhcNMjAwODMxMjIyOTMyWjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJyWVwZMGS/HZpgICBC
# mXZTbD4b1m/My/Hqa/6XFhDg3zp0gxq3L6Ay7P/ewkJOI9VyANs1VwqJyq4gSfTw
# aKxNS42lvXlLcZtHB9r9Jd+ddYjPqnNEf9eB2/O98jakyVxF3K+tPeAoaJcap6Vy
# c1bxF5Tk/TWUcqDWdl8ed0WDhTgW0HNbBbpnUo2lsmkv2hkL/pJ0KeJ2L1TdFDBZ
# +NKNYv3LyV9GMVC5JxPkQDDPcikQKCLHN049oDI9kM2hOAaFXE5WgigqBTK3S9dP
# Y+fSLWLxRT3nrAgA9kahntFbjCZT6HqqSvJGzzc8OJ60d1ylF56NyxGPVjzBrAlf
# A9MCAwEAAaOCAV4wggFaMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMsR6MrS
# tBZYAck3LjMWFrlMmgofMAsGA1UdDwQEAwIBhjASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBT90TFO0yaKleGYYDuoMW+mPLzYLTAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTAfBgNVHSMEGDAWgBQOrIJgQFYnl+UlE/wq4QpTlVnk
# pDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmwwVAYIKwYBBQUHAQEE
# SDBGMEQGCCsGAQUFBzAChjhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY3Jvc29mdFJvb3RDZXJ0LmNydDANBgkqhkiG9w0BAQUFAAOCAgEAWTk+
# fyZGr+tvQLEytWrrDi9uqEn361917Uw7LddDrQv+y+ktMaMjzHxQmIAhXaw9L0y6
# oqhWnONwu7i0+Hm1SXL3PupBf8rhDBdpy6WcIC36C1DEVs0t40rSvHDnqA2iA6VW
# 4LiKS1fylUKc8fPv7uOGHzQ8uFaa8FMjhSqkghyT4pQHHfLiTviMocroE6WRTsgb
# 0o9ylSpxbZsa+BzwU9ZnzCL/XB3Nooy9J7J5Y1ZEolHN+emjWFbdmwJFRC9f9Nqu
# 1IIybvyklRPk62nnqaIsvsgrEA5ljpnb9aL6EiYJZTiU8XofSrvR4Vbo0HiWGFzJ
# NRZf3ZMdSY4tvq00RBzuEBUaAF3dNVshzpjHCe6FDoxPbQ4TTj18KUicctHzbMrB
# 7HCjV5JXfZSNoBtIA1r3z6NnCnSlNu0tLxfI5nI3EvRvsTxngvlSso0zFmUeDord
# EN5k9G/ORtTTF+l5xAS00/ss3x+KnqwK+xMnQK3k+eGpf0a7B2BHZWBATrBC7E7t
# s3Z52Ao0CW0cgDEf4g5U3eWh++VHEK1kmP9QFi58vwUheuKVQSdpw5OPlcmN2Jsh
# rg1cnPCiroZogwxqLbt2awAdlq3yFnv2FoMkuYjPaqhHMS+a3ONxPdcAfmJH0c6I
# ybgY+g5yjcGjPa8CQGr/aZuW4hCoELQ3UAjWwz0wggYHMIID76ADAgECAgphFmg0
# AAAAAAAcMA0GCSqGSIb3DQEBBQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMx
# MzAzMDlaMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAf
# BgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJ+hbLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn
# 0UytdDAgEesH1VSVFUmUG0KSrphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0
# Zxws/HvniB3q506jocEjU8qN+kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4n
# rIZPVVIM5AMs+2qQkDBuh/NZMJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YR
# JylmqJfk0waBSqL5hKcRRxQJgp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54
# QTF3zJvfO4OToWECtR0Nsfz3m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsG
# A1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJg
# QFYnl+UlE/wq4QpTlVnkpKFjpGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcG
# CgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJ
# MEcwRaBDoEGGP2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL21pY3Jvc29mdHJvb3RjZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYB
# BQUHMAKGOGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0Um9vdENlcnQuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# BQUAA4ICAQAQl4rDXANENt3ptK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1i
# uFcCy04gE1CZ3XpA4le7r1iaHOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+r
# kuTnjWrVgMHmlPIGL4UD6ZEqJCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGct
# xVEO6mJcPxaYiyA/4gcaMvnMMUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/F
# NSteo7/rvH0LQnvUU3Ih7jDKu3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbo
# nXCUbKw5TNT2eb+qGHpiKe+imyk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0
# NbhOxXEjEiZ2CzxSjHFaRkMUvLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPp
# K+m79EjMLNTYMoBMJipIJF9a6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2J
# oXZhtG6hE6a/qkfwEm/9ijJssv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0
# eFQF1EEuUKyUsKV4q7OglnUa2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TGCBJ8wggSb
# AgEBMIGQMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xIzAh
# BgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBAhMzAAAAsBGvCovQO5/d
# AAEAAACwMAkGBSsOAwIaBQCggbgwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMZW
# gNXyS7jG1fqBhQRdwCa3mWyiMFgGCisGAQQBgjcCAQwxSjBIoBaAFABDAG8AbQBt
# AG8AbgAuAHAAcwAxoS6ALGh0dHA6Ly93d3cuTWljcm9zb2Z0LmNvbS9NaWNyb3Nv
# ZnREeW5hbWljcy8gMA0GCSqGSIb3DQEBAQUABIIBAI0CD6MXtOv2NDM1EE/zfsBx
# c9tCyUv6KGxDFkXbFBArvXLyq5qZccWCXAqLDCldGoSHBFHPOrjFdoidgN1VM625
# 7aPngETTOM7kGcLH1JTr4YbNwteZXqPk0XWbzSXYmiDIw3adcXfYOOaqST8KWWc2
# SFf23klzparpvbe9tJuLffs4Kbt95oNZ5QWnu5yjlpkkvu072wsaNzpDPlGgIAVk
# AyyMipOfQio2T783HZkL7Y+Ey+UDGHBTkGV0avi4zmrfOMceaE1fzL8D7k9qtEOj
# gLeFL7fSpbXrFKEOWXCu4J0C7mHxCAj3QJkbBbHmi0d19oAm2WfdgdcdpH69VQyh
# ggIoMIICJAYJKoZIhvcNAQkGMYICFTCCAhECAQEwgY4wdzELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBAhMzAAAANp57AFWyw10sAAAAAAA2MAkGBSsOAwIaBQCgXTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xMzA2MjEyMjE3
# MDFaMCMGCSqGSIb3DQEJBDEWBBTE0SU6DM6FT1oKDusYrqer4InNJzANBgkqhkiG
# 9w0BAQUFAASCAQB4XCi8M5kk2ENxgQkqLHaxHNDbdpQ553uhNEYDS36K3nXzjM+M
# 07Z2v9mKzw2DCzA8o3Y6UEGvzcHBuB2wtkZ6mMIKUboiKFlbnRfrjkounGn1TlG2
# RzsgNhzuuS1BoV3wMSRIgYwQXSB2KRH0ZfJd0/iI/XN5yp+Njsm44fR4Hpx25KuB
# +O3J5rZgyherZSBQcBOFkuhRgHomIBIGaGAuMa7bV5tAuAunBzwdWOidqrU8CNJ2
# 3f73qkvJTvfEeZpMop8w5b9jTNvi2iawUUHYMnD7KE5bsiTA0IhTBZG3frxi5Thj
# eg8xvuVeRpAXrUovzVGvDKtLKNB8qTHhOeLy
# SIG # End signature block
