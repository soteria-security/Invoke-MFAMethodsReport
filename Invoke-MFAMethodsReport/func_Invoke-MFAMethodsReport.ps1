Function Execute-GenerateMFAMethodsReport {
    <#
	    .SYNOPSIS
	    Generates a risk-based report of user mutli-factor authentication registration methods.
	    .DESCRIPTION
	    Returns information about users multi-factor authentication registered methods and assigns a risk rating based upon the strength of the authentication method. Can be run for all users, or targeted members of a given group.
	    .PARAMETER ReportScope
	    Scope of the report. Options are All or Group.
        .PARAMETER ReportType
        Desired Report Format. Options are CSV, XML, JSON, or None.
        .PARAMETER TargetGroup
        Only required when the ReportScope is Group. Takes the group DisplayName property and gathers the multi-factor registration info for all members.
	    .EXAMPLE
	    Execute-GenerateMFAMethodsReport -ReportScope All -reportType CSV
        .EXAMPLE
	    Execute-GenerateMFAMethodsReport -ReportScope Group -reportType JSON
	    .INPUTS
	    System.String values for ReportScope, ReportType, and TargetGroup when required.
	    .OUTPUTS
	    Desired report output in the current users \Documents\MFA_Report folder
	    .LINK
        https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-methods-activity
	#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, 
            HelpMessage = "Choose the scope of the report, all users or a select group. Valid options are 'All' or 'Group'")]
        [ValidateSet('All', 'Group', IgnoreCase = $true)]
        [string]$ReportScope = "All",
        [Parameter(Mandatory = $true,
            HelpMessage = "Report Output Format")]
        [ValidateSet("CSV", "XML", "JSON", "None",
            IgnoreCase = $true)]
        [string] $reportType = "CSV",
        [Parameter(Mandatory = $false,
            HelpMessage = "Filter Output for Specific Risk")]
        [ValidateSet("All", "Critical", "High", "Medium", "Low",
            IgnoreCase = $true)]
        [string[]] $riskLevel
    )

    #Requires -Modules "Microsoft.Graph.Reports"
    #Requires -Modules "Microsoft.Graph.Groups"

    Process {
        If ($reportType -ne 'None') {
            Try {
                $global:path = New-Item -Path "$env:USERPROFILE\Documents\MFA_Report" -ItemType Directory -Force -ErrorAction Stop
                Write-host "Creating report path at $($global:path)" -ForegroundColor Yellow
            }
            Catch {
                Write-Warning "Error message: $($_.Exception.Message)"
            }
        }

        $global:sortedResults = @()

        Function Invoke-ConnectGraph {
            Connect-Graph -Scopes "Reports.Read.All", "Group.Read.All", "GroupMember.Read.All", "User.Read.All" -ContextScope Process
            Select-MgProfile -Name beta
        }

        $ErrorActionPreference = 'Stop'

        Function Generate-Report {
            Try {
                $registeredMFAMethods = Get-MgReportAuthenticationMethodUserRegistrationDetail

                $results = @()
                
                Foreach ($entry in $registeredMFAMethods) {
                    $Risk = ""

                    If (($entry.AdditionalProperties.isAdmin -eq $true) -and (($entry.IsMfaRegistered -eq $false) -or ($entry.IsMfaCapable -eq $false)) -or (($entry.AdditionalProperties.isAdmin -eq $true) -and (($entry.AdditionalProperties.defaultMfaMethod -eq 'email') -or ($entry.AdditionalProperties.defaultMfaMethod -eq 'mobilePhone')))) {
                        $Risk = 'Critical'
                    }
                    ElseIf (($entry.AdditionalProperties.isAdmin -eq $false) -and (($entry.IsMfaRegistered -eq $false) -or ($entry.IsMfaCapable -eq $false)) -or (($entry.AdditionalProperties.isAdmin -eq $false) -and (($entry.AdditionalProperties.defaultMfaMethod -eq 'email') -or ($entry.AdditionalProperties.defaultMfaMethod -eq 'mobilePhone')))) {
                        $Risk = 'High'
                    }
                    ElseIf ($entry.IsSsprRegistered -eq $false) {
                        $Risk = 'Medium'
                    }
                    Else {
                        $Risk = 'Low'
                    }

                    $result = [PSCustomObject]@{
                        Name              = $entry.UserDisplayName
                        UPN               = $entry.userPrincipalName
                        MethodsRegistered = ($entry.MethodsRegistered | Out-String).Trim()
                        DefaultMethod     = $entry.AdditionalProperties.defaultMfaMethod
                        IsAdmin           = $entry.AdditionalProperties.isAdmin
                        MFACapable        = $entry.IsMfaCapable
                        MFARegistered     = $entry.IsMfaRegistered
                        IsSSPRCapable     = $entry.IsSsprCapable
                        IsSSPREnabled     = $entry.IsSsprEnabled
                        IsSsprRegistered  = $entry.IsSsprRegistered
                        Risk              = $Risk
                    }

                    If ($riskLevel -eq 'All') {
                        $results += $result
                    }
                    Else {
                        Foreach ($value in $riskLevel) {
                            $results += ($result | Where-Object { $_.Risk -eq $value })
                        }
                    }
                }
                
                $global:sortedResults += $results | Sort-Object { Switch -Regex ($_.Risk) { 'Critical' { 1 }	'High' { 2 }	'Medium' { 3 }	'Low' { 4 } } }   
            }
            Catch {
                Write-Warning "Error message: $($_.Exception.Message)"
            }
        }

        Function Generate-GroupReport {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true, 
                    HelpMessage = "The display name of the group targted users reside in.")]
                [string]$targetGroup
            )

            Try {
                $registeredMFAMethods = Get-MgReportAuthenticationMethodUserRegistrationDetail

                $group = Get-MgGroup -ConsistencyLevel eventual -Filter "displayName eq '$($targetGroup)'"

                $members = (Get-MgGroupMember -GroupId $group.Id).AdditionalProperties.displayName

                $results = @()
                
                Foreach ($entry in $registeredMFAMethods) {
                    If ($entry.UserDisplayName -in $members) {
                        $Risk = ""

                        If (($entry.AdditionalProperties.isAdmin -eq $true) -and (($entry.IsMfaRegistered -eq $false) -or ($entry.IsMfaCapable -eq $false)) -or (($entry.AdditionalProperties.isAdmin -eq $true) -and (($entry.AdditionalProperties.defaultMfaMethod -eq 'email') -or ($entry.AdditionalProperties.defaultMfaMethod -eq 'mobilePhone')))) {
                            $Risk = 'Critical'
                        }
                        ElseIf (($entry.AdditionalProperties.isAdmin -eq $false) -and (($entry.IsMfaRegistered -eq $false) -or ($entry.IsMfaCapable -eq $false)) -or (($entry.AdditionalProperties.isAdmin -eq $false) -and (($entry.AdditionalProperties.defaultMfaMethod -eq 'email') -or ($entry.AdditionalProperties.defaultMfaMethod -eq 'mobilePhone')))) {
                            $Risk = 'High'
                        }
                        ElseIf ($entry.IsSsprRegistered -eq $false) {
                            $Risk = 'Medium'
                        }
                        Else {
                            $Risk = 'Low'
                        }

                        $result = [PSCustomObject]@{
                            Name              = $entry.UserDisplayName
                            UPN               = $entry.userPrincipalName
                            MethodsRegistered = ($entry.MethodsRegistered | Out-String).Trim()
                            DefaultMethod     = $entry.AdditionalProperties.defaultMfaMethod
                            IsAdmin           = $entry.AdditionalProperties.isAdmin
                            MFACapable        = $entry.IsMfaCapable
                            MFARegistered     = $entry.IsMfaRegistered
                            IsSSPRCapable     = $entry.IsSsprCapable
                            IsSSPREnabled     = $entry.IsSsprEnabled
                            IsSsprRegistered  = $entry.IsSsprRegistered
                            Risk              = $Risk
                        }

                        If ($riskLevel -eq 'All') {
                            $results += $result
                        }
                        Else {
                            Foreach ($value in $riskLevel) {
                                $results += ($result | Where-Object { $_.Risk -eq $value })
                            }
                        }
                    }
                }
                
                $global:sortedResults += $results | Sort-Object { Switch -Regex ($_.Risk) { 'Critical' { 1 }	'High' { 2 }	'Medium' { 3 }	'Low' { 4 } } }   
            }
            Catch {
                Write-Warning "Error message: $($_.Exception.Message)"
            }
        }

        While ($null -eq (Get-MgContext)) {
            Invoke-ConnectGraph
        }

        If ($ReportScope -eq 'Group') {
            Generate-GroupReport

            If ($reportType -eq 'Csv') {
                $reportFile = "$global:path\MFA_Report_$(Get-Date -f yyyy-MM-dd).csv"
                Write-Host "Generating report $($reportFile)"
                Try {
                    $global:sortedResults | Export-Csv -Path $reportFile -NoTypeInformation -ErrorAction Stop
                }
                Catch {
                    Write-Warning "Error message: $($_.Exception.Message)"
                }
                If ((Test-Path $reportFile) -eq $true) {
                    Start-Process $reportFile
                }
            }
            ElseIf ($reportType -eq 'JSON') {
                $reportFile = "$global:path\MFA_Report_$(Get-Date -f yyyy-MM-dd).json"
                Write-Host "Generating report $($reportFile)"
                Try {
                    $global:sortedResults | ConvertTo-Json -Depth 10 | Out-File $reportFile -ErrorAction Stop
                }
                Catch {
                    Write-Warning "Error message: $($_.Exception.Message)"
                }
                If ((Test-Path $reportFile) -eq $true) {
                    Start-Process $reportFile
                }
            }
            ElseIf ($reportType -eq 'XML') {
                $reportFile = "$global:path\MFA_Report_$(Get-Date -f yyyy-MM-dd).xml"
                Write-Host "Generating report $($reportFile)"
                Try {
                    $global:sortedResults | Export-Clixml -Depth 3 -Path $reportFile -ErrorAction Stop
                }
                Catch {
                    Write-Warning "Error message: $($_.Exception.Message)"
                }
                If ((Test-Path $reportFile) -eq $true) {
                    Start-Process $reportFile
                }
            }
            ElseIf ($reportType -eq 'None') {
                $global:sortedResults
            }
        }
        Else {
            Generate-Report
            If ($reportType -eq 'Csv') {
                $reportFile = "$global:path\MFA_Report_$(Get-Date -f yyyy-MM-dd).csv"
                Write-Host "Generating report $($reportFile)"
                Try {
                    $global:sortedResults | Export-Csv -Path $reportFile -NoTypeInformation -ErrorAction Stop
                }
                Catch {
                    Write-Warning "Error message: $($_.Exception.Message)"
                }
                If ((Test-Path $reportFile) -eq $true) {
                    Start-Process $reportFile
                }
            }
            ElseIf ($reportType -eq 'JSON') {
                $reportFile = "$global:path\MFA_Report_$(Get-Date -f yyyy-MM-dd).json"
                Write-Host "Generating report $($reportFile)"
                Try {
                    $global:sortedResults | ConvertTo-Json -Depth 10 | Out-File $reportFile -ErrorAction Stop
                }
                Catch {
                    Write-Warning "Error message: $($_.Exception.Message)"
                }
                If ((Test-Path $reportFile) -eq $true) {
                    Start-Process $reportFile
                }
            }
            ElseIf ($reportType -eq 'XML') {
                $reportFile = "$global:path\MFA_Report_$(Get-Date -f yyyy-MM-dd).xml"
                Write-Host "Generating report $($reportFile)"
                Try {
                    $global:sortedResults | Export-Clixml -Depth 3 -Path $reportFile -ErrorAction Stop
                }
                Catch {
                    Write-Warning "Error message: $($_.Exception.Message)"
                }
                If ((Test-Path $reportFile) -eq $true) {
                    Start-Process $reportFile
                }
            }
            ElseIf ($reportType -eq 'None') {
                $global:sortedResults
            }
        }
    }
}