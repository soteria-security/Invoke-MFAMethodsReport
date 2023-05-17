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
        [ValidateSet("CSV", "XML", "JSON", "HTML", "None",
            IgnoreCase = $true)]
        [string] $reportType = "CSV",
        [Parameter(Mandatory = $false,
            HelpMessage = "Filter Output for Specific Risk")]
        [ValidateSet("Critical", "High", "Medium", "Low")]
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

                    If ($null -eq $riskLevel) {
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

                        If ($null -eq $riskLevel) {
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
            ElseIf ($reportType -eq 'HTML') {
                $reportFile = "$global:path\MFA_Report_$(Get-Date -f yyyy-MM-dd).html"
                Write-Host "Generating report $($reportFile)"

                $criticalCount = 0
                $highCount = 0
                $mediumCount = 0
                $lowCount = 0

                ForEach ($result in $global:sortedResults) {
                    If ($result.Risk -eq 'Critical') {
                        $result.Risk = '<span style="color:Crimson;"><strong>Critical</strong></span>'
                        $criticalCount += 1
                    }
                    If ($result.Risk -eq 'High') {
                        $result.Risk = '<span style="color:DarkOrange;"><strong>High</strong></span>'
                        $highCount += 1
                    }
                    If ($result.Risk -eq 'Medium') {
                        $result.Risk = '<span style="color:DarkGoldenRod;"><strong>Medium</strong></span>'
                        $mediumCount += 1
                    }
                    If ($result.Risk -eq 'Low') {
                        $lowCount += 1
                    }
                }
                
                #$jsonResults = $global:sortedResults | ConvertTo-Json -Depth 10
                $tableRows = $global:sortedResults | ForEach-Object {
                    $rowHtml = @"
                    <tr>
                        <td>$($_.Name)</td>
                        <td>$($_.UPN)</td>
                        <td>$($_.MethodsRegistered)</td>
                        <td>$($_.DefaultMethod)</td>
                        <td>$($_.IsAdmin)</td>
                        <td>$($_.MFACapable)</td>
                        <td>$($_.MFARegistered)</td>
                        <td>$($_.IsSSPRCapable)</td>
                        <td>$($_.IsSSPREnabled)</td>
                        <td>$($_.IsSsprRegistered)</td>
                        <td>$($_.Risk)</td>
                    </tr>
"@
                    $rowHtml
                }

                $htmlReport = @"
                <html>
                <head>
                    <meta content="text/html; charset=UTF-8" http-equiv="content-type">
                    <style type="text/css">
                        @import url(https://themes.googleusercontent.com/fonts/css?kit=toadOcfmlt9b38dHJxOBGL40yRR11Bk043VmwNc2-VdJNKf5lpbTaoq56xx1HhKI-lm9KUox0UUkSgunUYOJKw);
                
                        ul.lst-kix_bakjdvg45s3f-8 {
                            list-style-type: none
                        }
                
                        @import url('https://fonts.googleapis.com/css2?family=Source+Sans+Pro:wght@300;400&display=swap');
                
                        ol {
                            margin: 0;
                            padding: 0
                        }
                
                        table td,
                        table th {
                            padding: 0
                        }
                
                        .c12 {
                            border-right-style: solid;
                            padding: 5pt 5pt 5pt 5pt;
                            border-bottom-color: #000000;
                            border-top-width: 0pt;
                            border-right-width: 0pt;
                            border-left-color: #000000;
                            vertical-align: top;
                            border-right-color: #000000;
                            border-left-width: 0pt;
                            border-top-style: solid;
                            border-left-style: solid;
                            border-bottom-width: 1pt;
                            width: 65.2pt;
                            border-top-color: #000000;
                            border-bottom-style: solid
                        }
                
                        .c33 {
                            border-right-style: solid;
                            padding: 5pt 5pt 5pt 5pt;
                            border-bottom-color: #000000;
                            border-top-width: 0pt;
                            border-right-width: 0pt;
                            border-left-color: #000000;
                            vertical-align: top;
                            border-right-color: #000000;
                            border-left-width: 0pt;
                            border-top-style: solid;
                            border-left-style: solid;
                            border-bottom-width: 1pt;
                            width: 200.2pt;
                            border-top-color: #000000;
                            border-bottom-style: solid
                        }
                
                        .c3 {
                            border-right-style: solid;
                            padding: 5pt 5pt 5pt 5pt;
                            border-bottom-color: #000000;
                            border-top-width: 1pt;
                            border-right-width: 1pt;
                            border-left-color: #000000;
                            vertical-align: middle;
                            border-right-color: #000000;
                            border-left-width: 1pt;
                            border-top-style: solid;
                            border-left-style: solid;
                            border-bottom-width: 1pt;
                            width: 27pt;
                            border-top-color: #000000;
                            border-bottom-style: solid
                        }
                
                        .c15 {
                            border-right-style: solid;
                            padding: 5pt 5pt 5pt 5pt;
                            border-bottom-color: #000000;
                            border-top-width: 1pt;
                            border-right-width: 1pt;
                            border-left-color: #000000;
                            vertical-align: middle;
                            border-right-color: #000000;
                            border-left-width: 1pt;
                            border-top-style: solid;
                            border-left-style: solid;
                            border-bottom-width: 1pt;
                            width: 65.2pt;
                            border-top-color: #000000;
                            border-bottom-style: solid
                        }
                
                        .c11 {
                            border-right-style: solid;
                            padding: 5pt 5pt 5pt 5pt;
                            border-bottom-color: #000000;
                            border-top-width: 1pt;
                            border-right-width: 1pt;
                            border-left-color: #000000;
                            vertical-align: middle;
                            border-right-color: #000000;
                            border-left-width: 1pt;
                            border-top-style: solid;
                            border-left-style: solid;
                            border-bottom-width: 1pt;
                            width: 200.2pt;
                            border-top-color: #000000;
                            border-bottom-style: solid
                        }
                
                        .c30 {
                            border-right-style: solid;
                            padding: 5pt 5pt 5pt 5pt;
                            border-bottom-color: #000000;
                            border-top-width: 0pt;
                            border-right-width: 0pt;
                            border-left-color: #000000;
                            vertical-align: top;
                            border-right-color: #000000;
                            border-left-width: 0pt;
                            border-top-style: solid;
                            border-left-style: solid;
                            border-bottom-width: 1pt;
                            width: 27pt;
                            border-top-color: #000000;
                            border-bottom-style: solid
                        }
                
                        .c4 {
                            border-right-style: solid;
                            padding: 5pt 5pt 5pt 5pt;
                            border-bottom-color: #000000;
                            border-top-width: 1pt;
                            border-right-width: 1pt;
                            border-left-color: #000000;
                            vertical-align: middle;
                            border-right-color: #000000;
                            border-left-width: 1pt;
                            border-top-style: solid;
                            border-left-style: solid;
                            border-bottom-width: 1pt;
                            width: 247.5pt;
                            border-top-color: #000000;
                            border-bottom-style: solid
                        }
                
                        .c18 {
                            border-right-style: solid;
                            padding: 5pt 5pt 5pt 5pt;
                            border-bottom-color: #000000;
                            border-top-width: 0pt;
                            border-right-width: 0pt;
                            border-left-color: #000000;
                            vertical-align: top;
                            border-right-color: #000000;
                            border-left-width: 0pt;
                            border-top-style: solid;
                            border-left-style: solid;
                            border-bottom-width: 1pt;
                            width: 247.5pt;
                            border-top-color: #000000;
                            border-bottom-style: solid
                        }
                
                        .c25 {
                            padding-top: 16pt;
                            padding-bottom: 4pt;
                            line-height: 1.15;
                            page-break-after: avoid;
                            orphans: 2;
                            widows: 2;
                            text-align: left;
                            height: 24pt
                        }
                
                        .c19 {
                            padding-top: 16pt;
                            padding-bottom: 4pt;
                            line-height: 1.15;
                            page-break-after: avoid;
                            orphans: 2;
                            widows: 2;
                            text-align: left
                        }
                
                        .c21 {
                            padding-top: 0pt;
                            padding-bottom: 0pt;
                            line-height: 1.15;
                            page-break-after: avoid;
                            orphans: 2;
                            widows: 2;
                            text-align: left
                        }
                
                        .c5 {
                            color: #000000;
                            text-decoration: none;
                            vertical-align: baseline;
                            font-size: 11pt;
                            font-family: "Source Sans Pro Light", "Source Sans Pro";
                            font-style: normal
                        }
                
                        .c31 {
                            color: #d9d9d9;
                            font-weight: 200;
                            text-decoration: none;
                            vertical-align: baseline;
                            font-size: 11pt;
                            font-family: "Source Sans Pro Light", "Source Sans Pro";
                            font-style: normal
                        }
                
                        .c14 {
                            color: #4290eb;
                            font-weight: 200;
                            text-decoration: none;
                            vertical-align: baseline;
                            font-size: 30pt;
                            font-family: "Source Sans Pro Light", "Source Sans Pro";
                            font-style: normal
                        }
                
                        .c2 {
                            color: #4290eb;
                            font-weight: 400;
                            text-decoration: none;
                            vertical-align: baseline;
                            font-size: 24pt;
                            font-family: "Source Sans Pro";
                            font-style: normal
                        }
                
                        .c1 {
                            padding-top: 0pt;
                            padding-bottom: 0pt;
                            line-height: 1.15;
                            orphans: 2;
                            widows: 2;
                            text-align: justify;
                        }
                
                        .c7 {
                            color: #000000;
                            font-weight: 400;
                            text-decoration: none;
                            vertical-align: baseline;
                            font-size: 11pt;
                            font-family: "Source Sans Pro";
                            font-style: normal
                        }
                
                        .c23 {
                            color: #000000;
                            font-weight: 600;
                            text-decoration: none;
                            vertical-align: baseline;
                            font-size: 11pt;
                            font-family: "Source Sans Pro";
                            font-style: normal
                        }
                
                        .c34 {
                            color: #000000;
                            font-weight: 200;
                            text-decoration: none;
                            vertical-align: baseline;
                            font-size: 6pt;
                            font-family: "Source Sans Pro Light", "Source Sans Pro";
                            font-style: normal
                        }
                
                        .c0 {
                            padding-top: 0pt;
                            padding-bottom: 0pt;
                            line-height: 1.0;
                            orphans: 2;
                            widows: 2;
                            text-align: left;
                        }
                
                        .c8 {
                            padding-top: 0pt;
                            padding-bottom: 0pt;
                            line-height: 1.0;
                            orphans: 2;
                            widows: 2;
                            text-align: center
                        }
                
                        .c20 {
                            padding-top: 0pt;
                            padding-bottom: 0pt;
                            line-height: 1.15;
                            orphans: 2;
                            widows: 2;
                            text-align: justify
                        }
                
                        .c6 {
                            padding-top: 0pt;
                            padding-bottom: 10pt;
                            line-height: 1.15;
                            orphans: 2;
                            widows: 2;
                            text-align: justify
                        }
                
                        .c24 {
                            background-color: #ffffff;
                            max-width: 540pt;
                            padding: 36pt 36pt 36pt 36pt
                        }
                
                        .c10 {
                            color: inherit;
                            text-decoration: inherit
                        }
                
                        .c29 {
                            font-size: 30pt
                        }
                
                        .chart-container {
                            width: 1200px;
                            height: 300px;
                            margin: 0 auto;
                        }
                
                        /* Pie Chart */
                        .piechart-container {
                            width: 800px;
                            height: 400px;
                            position: relative;
                        }
                    </style>
                </head>
                
                <body class="c24">
                    <link href="https://cdn.jsdelivr.net/npm/prismjs@1.24.1/themes/prism.min.css" rel="stylesheet" />
                    <script src="https://cdn.jsdelivr.net/npm/prismjs@1.24.1/prism.min.js"></script>
                    <script src="https://cdn.jsdelivr.net/npm/prismjs@1.24.1/components/prism-powershell.min.js"></script>
                    <p class="c21 title" id="h.jcmsrxce36fv" style="text-align:center;">
                        <span class="c27">
                            <a class="c10" href="">Invoke-MFAMethodsReport</a>
                        </span>
                        <span class="c14"></span>
                    </p>
                    <p class="c21 title" id="h.gan1mgr3c5k5" style="text-align:center;">
                        <span class="c14">Multi-factor Risk Report</span>
                    </p>
                    <p class="c1">
                        <span class="c5"></span>
                    </p>
                    <h1 class="c19" id="h.1pyz3jiilmxm">
                        <span class="c2">About This Report</span>
                    </h1>
                    <!--BEGIN_EXECSUM_TEMPLATE-->
                    <p class="c6">
                        This report was generated by <a
                            href="https://github.com/soteria-security/Invoke-MFAMethodsReport">Invoke-MFAMethodsReport</a>, the
                        open-source Microsoft 365 multi-factor risk assessment tool.
                        <br /><br />
                    </p>
                    <!--END_EXECSUM_TEMPLATE-->
                    <!--BEGIN_CHART_TEMPLATE-->
                    <h1 class="c19" id="h.1pyz3jiilmxm">
                        <span class="c2">Risk Severity</span>
                    </h1>
                    <!-- RISK RATING BAR CHART -->
                    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                    <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-datalabels@2.0.0"></script>
                    <div class="chart-container">
                        <canvas id="riskChart"></canvas>
                    </div>
                    <script>
                        var ctx = document.getElementById('riskChart').getContext('2d');
                        var myChart = new Chart(ctx, {
                            type: 'bar',
                            data: {
                                labels: ['Critical', 'High', 'Medium', 'Low'],
                                datasets: [{
                                    label: 'Risk Severity',
                                    backgroundColor: ['#FC0303', '#FC6D03', '#FCDE03', '#2CFC03', '#C8C8C8'],
                                    data: [$criticalCount, $highCount, $mediumCount, $lowCount]
                                }]
                            },
                            plugins: [ChartDataLabels],
                            options: {
                                legend: {
                                    display: false,
                                },
                                title: {
                                    display: true,
                                    text: 'Risk Ratings'
                                },
                                responsive: true,
                                maintainAspectRatio: false,
                                indexAxis: 'y',
                                scales: {
                                    xAxes: [{
                                        ticks: {
                                            beginAtZero: true
                                        },
                                        gridLines: {
                                            display: false
                                        }
                                    }],
                                    yAxes: [{
                                        gridLines: {
                                            display: false
                                        }
                                    }]
                                },
                                plugins: {
                                    datalabels: {
                                        anchor: 'end',
                                        align: 'end',
                                        font: {
                                            size: 11,
                                            weight: 'bold'
                                        },
                                        formatter: function (value, context) {
                                            var total = context.dataset.data.reduce((a, b) => a + b, 0);
                                            var percentage = Math.round((value / total) * 100);
                                            return percentage + '%';
                                        }
                                    }
                                },
                                tooltips: {
                                    callbacks: {
                                        label: function (tooltipItem, data) {
                                            return data.labels[tooltipItem.index] + ": " + tooltipItem.xLabel;
                                        }
                                    }
                                }
                            }
                        });
                    </script>
                    <!--END_CHART_TEMPLATE-->
                    <!--BEGIN_FINDING_SHORT_REPEATER-->
                    <h1 class="c19" id="h.1pyz3jiilmxm">
                        <span class="c2">Multi-factor Risk Table</span>
                    </h1>
                    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
                    <table class="c26" id="results">
                        <style>
                            table,
                            th,
                            td {
                                border: 1px solid black;
                                padding-left: 10px;
                                padding-right: 10px;
                                text-align: center;
                                vertical-align: middle;
                            }
                        </style>
                        <thead>
                            <tr class="c9">
                                <th>Name</th>
                                <th>UPN</th>
                                <th>MethodsRegistered</th>
                                <th>DefaultMethod</th>
                                <th>IsAdmin</th>
                                <th>MFACapable</th>
                                <th>MFARegistered</th>
                                <th>IsSSPRCapable</th>
                                <th>IsSSPREnabled</th>
                                <th>IsSsprRegistered</th>
                                <th>Risk</th>
                            </tr>
                        </thead>
                        <tbody>
                            $tableRows
                        </tbody>
                    </table>
                    <!--END_FINDING_SHORT_REPEATER-->
                </body>
                </html>
"@
                $htmlReport | Out-File -FilePath $reportFile
            }
            ElseIf ($reportType -eq 'None') {
                $global:sortedResults
            }
        }
    }
}