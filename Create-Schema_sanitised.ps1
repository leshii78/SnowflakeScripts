<#
I have created a PowerShell script which we can use to provision a New schema and the access roles associated with it in snowflake.
You need to have the active directory PowerShell module installed (Add-WindowsFeature -Name "RSAT-AD-PowerShell" –IncludeAllSubFeature) and snowsql (https://sfc-repo.snowflakecomputing.com/snowsql/bootstrap/1.2/windows_x86_64/index.html)

The script accepts either schema name and database name or a csv file as input 

Usage:

Providing a schema name 
Create-Schema.ps1 -SchemaName <schema name> -DatabaseName <database name>
Optional parameters 
-runSnowflake no are you sure prompt for snowflake parts
-runAD no are you sure prompt for Acitve Directory parts

Providing a CSV file as input
Create-Schema.ps1 -UseCSVFile -CSVFilePath <path to csv file> 
Optional parameters 
-runSnowflake no are you sure prompt for snowflake parts
-runAD no are you sure prompt for Acitve Directory parts

If you run with no parameters 
Create-Schema.ps1
It will assume a single schema creation and prompt for <schema name> and <database name>

If you provide only the -UseCSVFile parameter 
Create-Schema.ps1 -UseCSVFile
It will prompt for the path to CSV file
#>


[CmdletBinding(DefaultParameterSetName='one')]
param (
    [Parameter(parametersetname='one',Mandatory=$true)]
    [string]
    $SchemaName,
    [Parameter(parametersetname='one',Mandatory=$true)]
    [string]
    $DatabaseName,
    [Parameter(parametersetname='two')]
    [Switch]
    $useCSVFile,
    [Parameter(parametersetname='two',Mandatory=$true)]
    [string]
    $CSVFilePath,
    [Parameter()]
    [Switch]
    $RunSnowflake,
    [Parameter()]
    [Switch]
    $RunAD
)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 # Force tls1.2
$env:PATH += ";C:\Program Files\Snowflake SnowSQL"

$userName=(get-aduser $([System.Environment]::UserName)).userPrincipalName
Function CreateSchema
{
    # Create schema
    $createSchemaSQL = @"
        USE ROLE SYSADMIN;
        CREATE SCHEMA IF NOT EXISTS $FQSchemaName ;
        USE ROLE SECURITYADMIN;
        CREATE ROLE IF NOT EXISTS $Role_R;
        CREATE ROLE IF NOT EXISTS $ROLE_W;
        CREATE ROLE IF NOT EXISTS $ROLE_FA;
        GRANT SELECT ON FUTURE TABLES IN SCHEMA $FQSchemaName TO ROLE $Role_R;
        GRANT SELECT ON FUTURE VIEWS IN SCHEMA $FQSchemaName TO ROLE $Role_R;
        GRANT INSERT,UPDATE,DELETE,TRUNCATE ON FUTURE TABLES IN SCHEMA $FQSchemaName TO ROLE $Role_W;
        GRANT SELECT ON ALL TABLES IN SCHEMA $FQSchemaName TO ROLE $Role_R;
        GRANT SELECT ON ALL VIEWS IN SCHEMA $FQSchemaName TO ROLE $Role_R;
        GRANT INSERT,UPDATE,DELETE,TRUNCATE ON ALL TABLES IN SCHEMA $FQSchemaName TO ROLE $Role_W;
        GRANT ALL PRIVILEGES ON SCHEMA $FQSchemaName TO ROLE $Role_FA;
        GRANT OWNERSHIP ON FUTURE VIEWS iN SCHEMA $FQSchemaName TO ROLE $Role_FA;
        GRANT OWNERSHIP ON FUTURE TABLES iN SCHEMA $FQSchemaName TO ROLE $Role_FA;
        GRANT ROLE $Role_R TO ROLE $Role_FA;
        GRANT ROLE $Role_W TO ROLE $Role_FA;
        GRANT USAGE ON SCHEMA  $FQSchemaName TO ROLE $Role_R;
        GRANT USAGE ON SCHEMA  $FQSchemaName TO ROLE $Role_W;
        GRANT USAGE ON SCHEMA  $FQSchemaName TO ROLE $Role_FA;
        GRANT USAGE ON DATABASE $DatabaseName TO ROLE $Role_R;
        GRANT USAGE ON DATABASE $DatabaseName TO ROLE $Role_W;
        GRANT USAGE ON DATABASE $DatabaseName TO ROLE $Role_FA;
"@



Write-Host "Creating $FQSchemaName using the following SQL command"
    Write-host "------------------------------------------"
    Write-host $createSchemaSQL
    Write-host "------------------------------------------"
    #write-host "Enter Y to continue or anything else to Abort"
    if ($RunSnowflake)
    {
        $continue = 'y'
        Write-host "-RunSnowflake used No prompt to continue"
        Start-sleep -seconds 2
    }
    else {
        $continue = Read-Host -Prompt "Enter Y to continue or anything else to Abort"     
    }
    if ($continue -eq 'y' -or $continue -eq 'Y'){
        Write-host "Executing"
        if ((get-aduser $([System.Environment]::UserName)).userPrincipalName -eq $userName)
        {
            write-host "run as current user"
            $createSchemaSQL | snowsql.exe -u $userName -a <ACCOUNT> -r <ROLE> -w <WAREHOUSE> --authenticator externalbrowser -o log_level=DEBUG
        }
        else 
        {            
            write-host "run as $SFusername"
            $createSchemaSQL | set-content C:\temp\snowsql.sql
            #Use System.Diagnostics to start the process as UserB
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            #With FileName we're basically telling powershell to run another powershell process
            $ProcessInfo.FileName = "powershell.exe"
            #CreateNoWindow helps avoiding a second window to appear whilst the process runs
            $ProcessInfo.CreateNoWindow = $true
            #Note the line below contains the Working Directory where the script will start from
            $ProcessInfo.WorkingDirectory = $env:USERPROFILE
            $ProcessInfo.RedirectStandardError = $true 
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.RedirectStandardInput = $true
            $ProcessInfo.UseShellExecute = $false
            $processinfo.LoadUserProfile = $true
            #The line below is basically the command you want to run and it's passed as text, as an argument
            #$ProcessInfo.Arguments = "write-host `"run as prompted user`";cmd /c echo %username%"
            $ProcessInfo.Arguments = 'snowsql.exe -u '+$SFuserName+' <ACCOUNT> -r <ROLE> -w <WAREHOUSE> --authenticator externalbrowser -o log_level=DEBUG -o Log_level=WARNING -f c:\temp\snowsql.sql -o friendly=false -o quiet=true -o log_file=C:\temp\snowsql.log > c:\temp\snowsql.out'
            #The next 3 lines are the credential for UserB, as you can see, we can't just pass $Credential
            $ProcessInfo.Username = $SFCredential.GetNetworkCredential().username
            $ProcessInfo.Domain = $SFCredential.GetNetworkCredential().Domain
            $ProcessInfo.Password = $SFCredential.Password
            #Finally start the process and wait for it to finish
            $Process = New-Object System.Diagnostics.Process 
            $Process.StartInfo = $ProcessInfo 
            $Process.Start() | Out-Null 
            while (-not $Process.HasExited ){
                Write-host "." -nonewline
                start-sleep -s 1
            }
            $Process.WaitForExit() 
            #Grab the output
            Write-Host "----------------------------------------------"
            $GetProcessResult = $Process.StandardOutput.ReadToEnd()
            $GetProcessResult = $Process.StandardError.ReadToEnd()
            get-content c:\temp\snowsql.out 
            #Print the Job results
            Write-host $GetProcessResult
        }        
       
    }else {
        Write-Host "Aborted"
    }
}

function CreateAdGroups {
    
    import-module ActiveDirectory
    Write-Host "Creating the following AD Groups to be assosciated with the roles"
    Write-host "-------------------------------------------"
    Write-host $adGroup_R
    Write-host $adGroup_W
    Write-host $adGroup_FA
    Write-host "-------------------------------------------"
    if ($RunAD)
    {
        $continue = 'y'
        Write-host "-RunAD used No prompt to continue"
        Start-sleep -seconds 2
    }
    else {
        $continue = Read-Host -Prompt "Enter Y to continue or anything else to Abort" 
    }
    if ($continue -eq 'y' -or $continue -eq 'Y'){
        Write-host "Executing"
       
        if (get-adgroup -Filter {SamAccountName -eq $adGroup_R} -server gs.adinternal.com) {
            Write-host " AD Group $adGroup_R already exists Skipping"
        }
        Else
        {
            if ($currentuser){
                New-ADGroup -GroupScope Universal -Path $ouIdentity -GroupCategory Security -name $adGroup_R -Description "Access role - No Users" -SamAccountName $adGroup_R -DisplayName $adGroup_R -server <DOMAIN> 
            }else {
                New-ADGroup -GroupScope Universal -Path $ouIdentity -GroupCategory Security -name $adGroup_R -Description "Access role - No Users" -SamAccountName $adGroup_R -DisplayName $adGroup_R -server <DOMAIN> -credential $ADcredential    
            }
            
        }
        if (get-adgroup -Filter {SamAccountName -eq $adGroup_W}  -server <DOMAIN>) {
            Write-host " AD Group $adGroup_w already exists Skipping"
        }
        Else
        {
            if ($currentuser){
                New-ADGroup -GroupScope Universal -Path $ouIdentity -GroupCategory Security -name $adGroup_W -Description "Access role - No Users" -SamAccountName $adGroup_W -DisplayName $adGroup_R -server <DOMAIN> 
            }else {
                New-ADGroup -GroupScope Universal -Path $ouIdentity -GroupCategory Security -name $adGroup_W -Description "Access role - No Users" -SamAccountName $adGroup_W -DisplayName $adGroup_R -server <DOMAIN> -credential $ADcredential
            }
            
            
        }
        if (get-adgroup -Filter {SamAccountName -eq $adGroup_FA}  -server <DOMAIN>) {
            Write-host " AD Group $adGroup_fa already exists Skipping"
        }
        Else
        {
            if ($currentuser){
                New-ADGroup -GroupScope Universal -Path $ouIdentity -GroupCategory Security -name $adGroup_FA -Description "Access role - No Users" -SamAccountName $adGroup_FA -DisplayName $adGroup_R -server <DOMAIN>
            }else {
                New-ADGroup -GroupScope Universal -Path $ouIdentity -GroupCategory Security -name $adGroup_FA -Description "Access role - No Users" -SamAccountName $adGroup_FA -DisplayName $adGroup_R -server <DOMAIN> -credential $ADcredential
            }
            
        }
        if ($currentuser){
            Add-ADGroupMember -Identity $adGroup_R -Members $adGroup_FA  -server <DOMAIN>
        Add-ADGroupMember -Identity $adGroup_W -Members $adGroup_FA -server <DOMAIN>
        }else {
            Add-ADGroupMember -Identity $adGroup_R -Members $adGroup_FA -credential $ADcredential -server <DOMAIN>
        Add-ADGroupMember -Identity $adGroup_W -Members $adGroup_FA -credential $ADcredential -server <DOMAIN>
        }
        
    }else {
        Write-Host "Aborted"
    }
    
}

If ($username -notlike "*<UPNSUFFIX>")
{
    write-host "This script must be run using your Regular sage account that is associated with Snowflake"
    $SFusername = Read-Host  "Enter your snowflake username"
    $SFcredential = Get-Credential -Message "Enter password" -UserName $SFuserName
    #Exit 1
}
else 
{
    Write-Host "This script is being run with $username, this account will be used for connecting to snowflake"
}

If ($username -notlike "<ADMIN ACCOUNT PREFIX>*")
{
    write-host "Not being run with an ADMIN"
    $ADcredential = get-credential -message "Enter ADMIN Account Details"
    $currentuser = $false
    #Exit 1
}
else {
    $currentuser = $true
}


if ($useCSVFile){
    $csvfile = Import-Csv -path $CSVFilePath
    #$csvfile
    Foreach ($row in $csvfile){
        $DatabaseName = $row.database
        $DatabaseName = $DatabaseName.ToUpper()
        $SchemaName = $row.schema
        $SchemaName = $SchemaName.ToUpper()
        Write-host "creating schema $schemaName in database $DatabaseName"
        # Setup Variables
        # AD Groups
        $adGroup_R = "Snowflake-Role-"+$DatabaseName+"_"+$SchemaName+"_R"
        $adGroup_W = "Snowflake-Role-"+$DatabaseName+"_"+$SchemaName+"_W"
        $adGroup_FA = "Snowflake-Role-"+$DatabaseName+"_"+$SchemaName+"_FA"
        # AD OU for group Provisioning
        [String]$ouIdentity='OU=<SNOWFLAKE OU>,OU=DC=<DOMAIN>'
        # Roles
        $Role_R = $DatabaseName+"_"+$SchemaName+"_R"
        $Role_W = $DatabaseName+"_"+$SchemaName+"_W"
        $Role_FA = $DatabaseName+"_"+$SchemaName+"_FA"
        # Schema
        $FQSchemaName = $DatabaseName+"."+$SchemaName
        CreateSchema
        CreateAdGroups

    }

}
else {
    # Setup Variables
    # AD Groups
    $DatabaseName = $DatabaseName.ToUpper()
    $SchemaName = $SchemaName.ToUpper()
    $adGroup_R = "snowflake-role-"+$DatabaseName+"_"+$SchemaName+"_R"
    $adGroup_W = "snowflake-role-"+$DatabaseName+"_"+$SchemaName+"_W"
    $adGroup_FA = "snowflake-role-"+$DatabaseName+"_"+$SchemaName+"_FA"
    # AD OU for group Provisioning
    [String]$ouIdentity='OU=<SNOWFLAKE OU>,OU=DC=<DOMAIN>'
    # Roles
    $Role_R = $DatabaseName+"_"+$SchemaName+"_R"
    $Role_W = $DatabaseName+"_"+$SchemaName+"_W"
    $Role_FA = $DatabaseName+"_"+$SchemaName+"_FA"
    # Schema
    $FQSchemaName = $DatabaseName+"."+$SchemaName
    CreateSchema
    CreateAdGroups
}
