<#
## User Termination ################################
written by Chris Renshaw
Created 3/8/2017

## Outline of script ###############################

* input username
* specify any retention 
* mailbox disabled as needed
* permissions (Groups) logged / revoked
* password changed
* user account disabled
* checks / creates Graveyard OU as needed
* drop user into Graveyard OU as needed
* manager given full acces to email as needed
* append perms revoked to user description

#> ##################################################

#TAGS User,term,disable
#UNIVERSAL

Function UserTerm {


    clear

    #Clear Variables
    $UserAlias = @()
    $Session = @()
    $strUser = @()
    $UserPerms = @()
    $LogFile = @()
    $TermDate = @()
    $ADGroups = @()
    $DeleteDate = @()
    $DivisionDetails = @()
    $DomainName = "YourDomain.local" #eg - "domain.com" or "domain.local" // modification of script would be needed for subdomain, eg - sub.domain.com
    $MailServer = "FQDN of server" #eg - "mail-server.domain.com"
    $LogLocation = "C:\Logs"



    if ($UserCredential -eq $NULL) {
            $UserCredential = Get-Credential
        }


    Write-Host "User Account Deletion for $DomainName" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Please fill out the following questions carefully and be sure to check for" -ForegroundColor Yellow
    Write-Host "any errors including spelling. Be careful with this script." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""

    #Obtain User Alias
    Write-Host "Enter the username to be disabled. (Without $DomainName\, no wildcards, and not blank)" -ForegroundColor Yellow
    $UserAlias = Read-Host "Username"
    Write-Host ""
    if ($UserAlias -eq "$NULL" -or $UserAlias -eq "*" -or $UserAlias -eq "?") {
        #check for * or ? or blank
        Write-Host "Error - You must specify a username. No wildcards or blanks. Please try again." -ForegroundColor Red
        Write-Host ""
        return
    }
    elseif ($UserAlias -eq "stop" -or $UserAlias -eq "quit" -or $UserAlias -eq "q") {
        Write-Host "You requested to quit the Termination Process. Goodbye." -ForegroundColor Red
        Write-Host ""
        return
    }
    else {
        try {
            $UserAcctCheck = Get-ADUser -Identity $UserAlias -ErrorAction Stop
        }
        catch {
            Write-Host "Error - User account specified doesn't exist in AD.  Please try again." -ForegroundColor Red
            Write-Host ""
            return
        }
        If (!($UserAcctCheck.Enabled -eq $True)) { 
            Write-Host "Error - User account not active. Please try again." -ForegroundColor Red 
            Write-Host ""
            return
        }
    }
    #End Obtain User Alias


    #Retention
    $Graveyard = @()
    $UserRetain = @()
    $EmailRetain = @()

    Write-Host ""
    Write-Host "Will this user's account or email need to be retained in the Graveyard OU?" -ForegroundColor Yellow
    $UserRetain = Read-Host "Confirm Y or N"
    Write-Host "" 
    if ($UserRetain -ne "Y" -or $UserRetain -ne "y") {
        Write-Host "You requested not to retain this user's account in the graveyard." -ForegroundColor Red
        Write-Host "If this is incorrect, hit (Ctrl+C) to terminate the script." -ForegroundColor Red
        Write-Host ""
        $Graveyard = "NO"
        $UserRetain = "NO"
        $EmailRetain = "NO"
    }
    else {
        $UserRetain = "YES"
        $Graveyard = "YES"
        Write-Host ""
        Write-Host "Will the email need to be retained and Full-Access given to their manager?" -ForegroundColor Yellow
        $EmailRetain = Read-Host "Confirm Y or N"
        Write-Host ""
        if ($EmailRetain -ne "Y" -or $EmailRetain -ne "y") {
            Write-Host "You requested not to retain this user's email account." -ForegroundColor Red
            Write-Host "If this is incorrect, hit (Ctrl+C) to terminate the script." -ForegroundColor Red
            Write-Host ""
            $EmailRetain = "NO"
        }
        else {
            Write-Host "You confirmed that you'd like to retain the user's email" -ForegroundColor Yellow
            Write-Host "and give the manager Full Access permissions." -ForegroundColor Yellow
            $EmailRetain = "YES"
        }
    }
    #End Retention


    #Verification
    Write-Host ""
    Write-Host "You chose the following user - is this correct?" -ForegroundColor Yellow 
    $UserConfirmCheck = Get-ADUser -Identity $UserAlias
    $UserConfirmCheck.Name
    Write-Host ""
    Write-Host "Account Retained in the Graveyard:" -ForegroundColor Yellow 
    $UserRetain
    Write-Host ""
    Write-Host "Email Retained and manager given access:" -ForegroundColor Yellow 
    $EmailRetain
    Write-Host ""
    Write-Host ""
    $UserConfirm = Read-Host "Confirm (Y or N)"
    if ($UserConfirm -ne "Y" -or $UserConfirm -ne "y") {
        Write-Host "You declined the confirmation. Quitting the User Termination Process. Goodbye." -ForegroundColor Red
        Write-Host ""
        return
    }

    Write-Host ""
    Write-Host "Thank you. Proceeding with termination." -ForegroundColor Green
    Write-Host ""
    Write-Host ""
    #End Verification


    #Mailbox Logic
    if ($EmailRetain -eq "NO") {
        Write-Host "<< Disable Mailbox >>" -ForegroundColor Cyan
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$MailServer/PowerShell/ -Authentication Kerberos -Credential $UserCredential
        Import-PSSession $Session -AllowClobber 
        Disable-Mailbox -Identity "$UserAlias" -Confirm:$false
        Write-Host ""
        Write-Host "Mailbox disabled successfully?" -ForegroundColor Yellow
        $error.clear()
        try { Get-Mailbox -Identity "$UserAlias" -ErrorAction Stop}
        #catch { Write-Host "Mailbox not found!" -ForegroundColor Yellow }
        catch {  }
        If ($error) { Write-Host "Mailbox Successfully Disabled" -ForegroundColor Green }
        Else { Write-Host "Error - please check email server" -ForegroundColor Red }
        Write-Host ""
        Write-Host ""
        Remove-PSSession $Session
    }

    else {
        #assign Full Access to manager
        $managerDetails = Get-ADUser (Get-ADUser $UserAlias -properties manager).manager -properties displayName
        $managerUserName=$managerDetails.SamAccountName
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$MailServer/PowerShell/ -Authentication Kerberos -Credential $UserCredential
        Import-PSSession $Session -AllowClobber
        Add-MailboxPermission -Identity $UserAlias -User $managerUserName -AccessRights FullAccess -InheritanceType All
        Remove-PSSession $Session
    }
    #End Mailbox Logic


    #Log Alias and permissions
    function log($string, $color) {
        if ($Color -eq $null) {$color = "white"}
        write-host $string -foregroundcolor $color   
        $temp = ": " + $string
        $string = Get-Date -format "yyyy.MM.dd hh:mm:ss tt"
        $string += $temp 
        $string | out-file -Filepath $logfile -append
    }
    
    $LogFile = "$LogLocation\$UserAlias $(Get-Date -f yyyy-MM-dd).txt"

    $strUser = Get-ADPrincipalGroupMembership -Identity $UserAlias
    $UserPerms = $strUser.name
    $TermDate = Get-Date -DisplayHint Date
    $DeleteDate = ((Get-Date -DisplayHint Date).AddMonths(3))
    $DivisionDetails = (Get-ADUser $UserAlias -properties Office).Office
    Write-Host "<< Logging Permission Sets >>" -ForegroundColor Cyan
    Write-Host "Permissions prior to termination have been recorded to:" -ForegroundColor Yellow
    Write-Host "$LogFile" -ForegroundColor Green
    Write-Host ""
    Write-Host ""

    log "Termination Date - $TermDate"
    log "Deletion Date - $DeleteDate"
    log "Full Name - $((Get-ADUser $UserAlias).Name)"
    log "User Name - $UserAlias"
    log "Division - $DivisionDetails"
    log "Permissions Revoked - $UserPerms"
    
    #End Log Alias and permissions



    #User Account Retention vs Deletion

    if ($UserRetain -ne "NO") {

        #Revoke Permissions
        Write-Host "<< Revoking Permission Sets >>" -ForegroundColor Cyan
        $ADGroups = Get-ADPrincipalGroupMembership -Identity $UserAlias | where {$_.Name -ne "Domain Users"}
        Remove-ADPrincipalGroupMembership -Identity "$UserAlias" -MemberOf $ADGroups -Confirm:$false
        Write-Host "Permissions successfully revoked?" -ForegroundColor Yellow
        $PermCheck = Get-ADPrincipalGroupMembership -Identity $UserAlias | where {$_.Name -ne "Domain Users"} 
        If ($PermCheck -eq $NULL) { Write-Host "Successful" -ForegroundColor Green }
        Else { Write-Host "Error - please check AD server" -ForegroundColor Red }
        Write-Host ""
        Write-Host ""
        #End Revoke Permissions


        #Change Password
        Write-Host "<< Changing Password >>" -ForegroundColor Cyan
        Set-ADAccountPassword -Identity $UserAlias -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "T3rm3dU5er$" -Force)
        Write-Host "Password for $UserAlias has been changed to T3rm3dU5er$" -ForegroundColor Green
        Write-Host ""
        Write-Host ""
        #End Change Password


        #Append the output to the Description field of the user object
        Write-Host "<< Appending User Description with previous permissions >>" -ForegroundColor Cyan
        Get-ADUser -Identity $UserAlias -Properties Description |
          ForEach-Object {
            Set-ADUser $_ -Description "Disabled $TermDate, Perms Revoked: $UserPerms, Original Description: $($_.Description)"
          }
        Write-Host "The following data has been added to the user account's description field:" -ForegroundColor Yellow
        
        Write-Host "DELETE ON $DeleteDate //" -ForegroundColor Green
        Write-Host "Disabled $TermDate //" -ForegroundColor Green
        Write-Host "Permissions Revoked: $UserPerms" -ForegroundColor Green
        Write-Host ""
        Write-Host ""
        #End Append the output to the Description field of the user object


        #Disable User Account
        Write-Host "<< Disable User Account >>" -ForegroundColor Cyan
        Disable-ADAccount -Identity $UserAlias
        Write-Host "User Account Disabled?" -ForegroundColor Yellow
        $UserAcctCheck = Get-ADUser -Identity $UserAlias
        If ($UserAcctCheck.Enabled -eq $False) { Write-Host "Successful" -ForegroundColor Green }
        Else { Write-Host "Error - please check AD server" -ForegroundColor Red }
        Write-Host ""
        Write-Host ""
        #End Disable User Account


        #Check for and move user account to Graveyard OU
        Write-Host "<< Scanning for Graveyard OU >>" -ForegroundColor Cyan
        Write-Host ""
        #build Path
        $DCpt1 = @()
        $DCpt2 = @()
        $Domain_Split = @()
        $GraveyardPath = @()
        $GraveyardExist = @()

        $Domain_Split = $DomainName.Split(".")       
        $DCpt1 = $Domain_Split[0]
        $DCpt2 = $Domain_Split[1]
        
        $GraveyardPath = "OU=Graveyard,DC=$DCpt1,DC=$DCpt2" 

        $GraveyardExist = [adsi]::Exists("LDAP://$GraveyardPath")
        #if false, create
        If ($GraveyardExist -eq $FALSE) {
            New-ADOrganizationalUnit -Name Graveyard -Path "DC=$DCpt1,DC=$DCpt2"
        }

        Write-Host "<< Move User Account to Graveyard OU >>" -ForegroundColor Cyan
        Get-ADUser -Identity $UserAlias | Move-ADObject -TargetPath $GraveyardPath
        Write-Host "User Account for $UserAlias has been moved to the Graveyard in AD." -ForegroundColor Green
        Write-Host ""
        Write-Host ""
        #End Check for and move user account to Graveyard OU

    }

    else {
    #Delete User Account
    Write-Host "<< Deleting User Account >>" -ForegroundColor Cyan
    Remove-ADUser -Identity $UserAlias -Confirm:$false

    }

    #Complete
    Write-Host ""
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host "User Account $UserAlias has successfully been terminated." -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Green


}
