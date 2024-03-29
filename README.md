# Invoke-MFAMethodsReport
PowerShell module that generates a risk-based report of user multi-factor authentication registration methods.

## Purpose
Invoke-MFAMethodsReport was created to give administrators a quick and easy way to generate risk-based report of user multi-factor authentication registration methods.
The report is sorted by risk, so administrators will be able to easily discern the most at risk users based on their MFA configuration, including if the user is registered, if they hold an administrative role in the tenant, all registered methods, and the user selected default method used to authenticate the user.

## To-Do List
* ~~Allow filtering by risk to only output desired risk ratings~~
* ~~Additional report output formats~~

## Module Help
```pwsh
<#
.SYNOPSIS
    Generates a risk-based report of user multi-factor authentication registration methods.
.DESCRIPTION
    Returns information about users multi-factor authentication registered methods and assigns a risk rating based upon the strength of the authentication method. Can be run for all users, or targeted members of a given group.
.PARAMETER ReportScope
    Scope of the report. Options are All or Group.
.PARAMETER ReportType
    Desired Report Format. Options are CSV, XML, JSON, HTML, or None.
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
```

## Requirements
The Microsoft Graph PowerShell module, and sufficient permissions to run the queries are required.
The first time Microsoft Graph requests the necessary permissions, a Global Administrator must grant the permissions request on behalf of the tenant.

### Required Permissions
```
Reports.Read.All
Group.Read.All
GroupMember.Read.All
User.Read.All
```
### Graph Modules Used
```
Microsoft.Graph.Reports
Microsoft.Graph.Groups
```

## Using the Module
```pwsh
PS C:\> git clone 'https://github.com/soteria-security/Invoke-MFAMethodsReport.git'
PS C:\> Import-Module ".\Invoke-MFAMethodsReport/Invoke-MFAMethodsReport/Invoke-MFAMethodsReport.psd1"
```
## Installing the Module
The module can be installed by copying the Invoke-MFAMethodsReport folder and its contents to `C:\Users\<Your User>\Documents\WindowsPowerShell\Modules`

## Generating the Report
```pwsh
# Return full set of results
PS C:\> Execute-GenerateMFAMethodsReport -ReportScope All -reportType CSV
       # or
PS C:\> Execute-GenerateMFAMethodsReport -ReportScope Group -reportType JSON
       # or
PS C:\> Execute-GenerateMFAMethodsReport -ReportScope Group -reportType HTML

# Return filtered risks only
PS C:\> Execute-GenerateMFAMethodsReport -ReportScope All -reportType None -riskLevel Critical
       # or
PS C:\> Execute-GenerateMFAMethodsReport -ReportScope All -reportType None -riskLevel Critical, High
```
## Output Examples
### Stdout
By selecting the report type 'None', all results will be output to stdout (your terminal)

![image](https://user-images.githubusercontent.com/88730003/234398857-28281412-8550-4e65-9e63-dff7f73b2c52.png)

### JSON
```json
[
  {
          "Name":  "BOBBIE_ARNOLD",
          "UPN":  "BOBBIE_ARNOLD@domain.onmicrosoft.com",
          "MethodsRegistered":  "",
          "DefaultMethod":  "none",
          "IsAdmin":  true,
          "MFACapable":  false,
          "MFARegistered":  false,
          "IsSSPRCapable":  false,
          "IsSSPREnabled":  false,
          "IsSsprRegistered":  false,
          "Risk":  "Critical"
      },
      {
          "Name":  "Lynne Robbins",
          "UPN":  "LynneR@domain.onmicrosoft.com",
          "MethodsRegistered":  "",
          "DefaultMethod":  "none",
          "IsAdmin":  false,
          "MFACapable":  false,
          "MFARegistered":  false,
          "IsSSPRCapable":  false,
          "IsSSPREnabled":  false,
          "IsSsprRegistered":  false,
          "Risk":  "High"
      },
      {
          "Name":  "MABEL_GOODWIN",
          "UPN":  "MABEL_GOODWIN@domain.onmicrosoft.com",
          "MethodsRegistered":  "",
          "DefaultMethod":  "none",
          "IsAdmin":  false,
          "MFACapable":  false,
          "MFARegistered":  false,
          "IsSSPRCapable":  false,
          "IsSSPREnabled":  false,
          "IsSsprRegistered":  false,
          "Risk":  "High"
      },
      {
          "Name":  "MAJOR_FORBES",
          "UPN":  "MAJOR_FORBES@domain.onmicrosoft.com",
          "MethodsRegistered":  "",
          "DefaultMethod":  "none",
          "IsAdmin":  false,
          "MFACapable":  false,
          "MFARegistered":  false,
          "IsSSPRCapable":  false,
          "IsSSPREnabled":  false,
          "IsSsprRegistered":  false,
          "Risk":  "High"
      }
    ]
```
