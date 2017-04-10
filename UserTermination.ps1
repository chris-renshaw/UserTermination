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
    $DomainName = "DomainName.local" #eg - "domain.com" or "domain.local" // modification of script would be needed for subdomain, eg - sub.domain.com
    $MailServer = "MAIL.DomainName.local" #eg - "mail-server.domain.com"
    $LogLocation = "C:\LogFiles"
    $GraveyardOU = "OU=Disabled Users,OU=Graveyard,DC=DomainName,DC=local"
    $TermPW = "T3rm3dU5er$" #Password set for disabled, but retained, user account


    if ($UserCredential -eq $NULL) {
            $UserCredential = Get-Credential
        }


    Write-Host "User Account Deletion" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Please fill out the following questions carefully and be sure to check for" -ForegroundColor Yellow
    Write-Host "any errors including spelling. Be careful with this script." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""

    #Obtain User Alias
    
    # Select username or enter last name
    Write-Host "Would you like to enter the username or the user's last name?" -ForegroundColor Cyan
    Write-Host "=============================================================" -ForegroundColor Cyan 
    Write-Host "1) Enter the username"
    Write-Host "2) Enter the user's last name"
    Write-Host ""
     switch ($SELECTION = Read-Host "Select on option") {

        1{
            Write-Host ""
            $UserAcctCheck = @()
            Write-Host "Enter the username to be disabled. (Without $DomainName\, no wildcards, and not blank)" -ForegroundColor Cyan
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
            $UserNameChosen = $UserAcctCheck.Name
        }

        2{
            Write-Host ""
            Write-Host "Enter the user's last name to be disabled." -ForegroundColor Cyan
            $UserLastName = Read-Host "User's Last Name"
            Write-Host ""
            if ($UserLastName -eq "$NULL" -or $UserLastName -eq "*" -or $UserLastName -eq "?") {
                #check for * or ? or blank
                Write-Host "Error - You must specify a valid entry. No wildcards or blanks. Please try again." -ForegroundColor Red
                Write-Host ""
                return
            }
            elseif ($UserLastName -eq "stop" -or $UserLastName -eq "quit" -or $UserLastName -eq "q") {
                Write-Host "You requested to quit the Termination Process. Goodbye." -ForegroundColor Red
                Write-Host ""
                return
            }
            else {
                try {
                    # Menu selection of usernames found
                    $LastNameChk = $NULL
                    $LastNameChk = (Get-ADUser -Filter{Surname -eq $UserLastName} -ErrorAction Stop).Name

                    if ($LastNameChk -eq $NULL) {
                        Write-Host "No such last name was found. Please check the name and try again." -ForegroundColor Red
                        return
                    }

                    else {
                        if ($LastNameChk.Count -gt "1") {
                            Write-Host "Found the following options. Please choose one:" -ForegroundColor Cyan
                            Write-Host ""
                            $UserNameMenu = @{}
                            for ($i=1;$i -le $LastNameChk.count; $i++) {
                                Write-Host "$i. $($LastNameChk[$i-1])"
                                $UserNameMenu.Add($i,($LastNameChk[$i-1]))
                            }
                            [int]$NameAns = Read-Host "Confirm"
                            Write-Host ""
                            $UserNameChosen = $UserNameMenu.Item($NameAns)
                        }
                        else {
                            $UserNameChosen = $LastNameChk

                        }
                    }

                    $UserAcctCheck = @()
                    $UserAcctCheck = (Get-ADUser -Filter{Name -eq $UserNameChosen} -ErrorAction Stop)
                    $UserAlias = $UserAcctCheck.SamAccountName
                }
                catch {
                    Write-Host "Error - No users found.  Please try again." -ForegroundColor Red
                    Write-Host ""
                    return
                }
                If (!($UserAcctCheck.Enabled -eq $True)) { 
                    Write-Host "Error - User account not active. Please try again." -ForegroundColor Red 
                    Write-Host ""
                    return
                }
            }

        }

    }

    #End Obtain User Alias
    

    # Confirm User Name 
    Write-Host ""
    Write-Host "You entered the following user account - is this correct?" -ForegroundColor Cyan 
    $UserConfirmCheck = Get-ADUser -Identity $UserAlias
    $UserConfirmCheck.Name
    Write-Host "" 
    $UserConfirm = Read-Host "Confirm (Y or N)"
    if ($UserConfirm -ne "Y" -or $UserConfirm -ne "y") {
        Write-Host "You declined the confirmation. Quitting the User Termination Process. Goodbye." -ForegroundColor Red
        Write-Host ""
        return
    } # Stops the script upon incorrect user choice


    # Retention Verification
    $UserRetain = @()
    $EmailRetain = @()
    Write-Host ""
    Write-Host "Will this user's account need to be retained in the Graveyard OU?" -ForegroundColor Cyan
    $UserRetain = Read-Host "Confirm (Y or N)"
    Write-Host "" 
    if ($UserRetain -ne "Y" -or $UserRetain -ne "y") {
        Write-Host "You requested not to retain this user's account in the graveyard." -ForegroundColor Red
        Write-Host ""
        $UserRetain = "NO"
        $EmailRetain = "NO"
    }
    else {
        $UserRetain = "YES"
        Write-Host ""
        Write-Host "You requested to retain this user's AD account." -ForegroundColor Green

            Write-Host "Will the email need to be retained and Full-Access given to their manager?" -ForegroundColor Cyan
        Write-Host ""
        $EmailRetain = Read-Host "Confirm (Y or N)"
        Write-Host ""
        if ($EmailRetain -ne "Y" -or $EmailRetain -ne "y") {
            Write-Host "You requested not to retain this user's email account." -ForegroundColor Red
            Write-Host ""
            $EmailRetain = "NO"
        }
        else {
            Write-Host "You confirmed that you'd like to retain the user's email" -ForegroundColor Green
            Write-Host "and give the manager Full Access permissions." -ForegroundColor Green
            $EmailRetain = "YES"
        }

    }



    #End Retention Verification


    # Summary Verification
    Write-Host "==================" -ForegroundColor Green
    Write-Host "Review of Deletion" -ForegroundColor Green
    Write-Host "==================" -ForegroundColor Green
    Write-Host ""
    Write-Host "You selected the following data. Please review carefully" -ForegroundColor Yellow
    Write-Host "and ensure the data is correct or cancel the script!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "==================" -ForegroundColor Green
    Write-Host ""
    Write-Host "User to be Terminated:" -ForegroundColor Cyan 
    $UserConfirmCheck.Name
    Write-Host ""
    Write-Host "Account to be retained in the Graveyard:" -ForegroundColor Cyan 
    $UserRetain
    Write-Host ""
    Write-Host "Email to be retained and manager given access:" -ForegroundColor Cyan 
    $EmailRetain
    Write-Host ""
    Write-Host "Is the above listed information correct? (Y/N)"  -ForegroundColor Yellow
    Write-Host "Please note that if it is not, this script terminates."  -ForegroundColor Red
    $SelectionConfirmation = @()
    $SelectionConfirmation = Read-Host "Confirm"

    if ($SelectionConfirmation -eq "Y" -or $SelectionConfirmation -eq "Yes") {
        Write-Host ""
        Write-Host "You confirmed the above information is correct - proceeding to terminate AD User." -ForegroundColor Green
        Write-Host ""
    }
    
    else {
        Write-Host ""
        Write-Host "You confirmed the above information is not correct - terminating script." -ForegroundColor Red
        break
    }

    #End Confirm Selection

    # Summary End Verification


    #Mailbox Logic
    if ($EmailRetain -eq "NO") { # These steps will complete if the mailbox is not to be retained
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

    if ($UserRetain -ne "NO") { # These steps will complete if the user is to be retained

        #Revoke Permissions
        Write-Host "<< Revoking Permission Sets >>" -ForegroundColor Yellow
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
        Write-Host "<< Changing Password >>" -ForegroundColor Yellow
        Set-ADAccountPassword -Identity $UserAlias -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "T3rm3dU5er$" -Force)
        Write-Host "Password for $UserAlias has been changed to $TermPW" -ForegroundColor Green
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
        Write-Host "Disabled $TermDate" -ForegroundColor Green
        Write-Host "Permissions Revoked: $UserPerms" -ForegroundColor Green
        Write-Host ""
        Write-Host ""
        #End Append the output to the Description field of the user object


        #Disable User Account
        Write-Host "<< Disable User Account >>" -ForegroundColor Yellow
        Disable-ADAccount -Identity $UserAlias
        Write-Host "User Account Disabled?" -ForegroundColor Yellow
        $UserAcctCheck = Get-ADUser -Identity $UserAlias
        If ($UserAcctCheck.Enabled -eq $False) { Write-Host "Successful" -ForegroundColor Green }
        Else { Write-Host "Error - please check AD server" -ForegroundColor Red }
        Write-Host ""
        Write-Host ""
        #End Disable User Account


        #Move user account to Graveyard OU
        Write-Host "<< Move User Account to Graveyard OU >>" -ForegroundColor Yellow
        Get-ADUser -Identity $UserAlias | Move-ADObject -TargetPath $GraveyardOU
        Write-Host "User Account for $UserAlias has been moved to the Graveyard in AD." -ForegroundColor Green
        Write-Host ""
        Write-Host ""
        #Move user account to Graveyard OU

    } # These steps will complete if the user is to be retained

    else { # These steps will complete if the user is not to be retained
    #Delete User Account
    Write-Host "<< Deleting User Account >>" -ForegroundColor Yellow
    Remove-ADUser -Identity $UserAlias -Confirm:$false

    } # These steps will complete if the user is not to be retained

    #Complete
    Write-Host ""
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "User Account for $UserNameChosen has successfully been terminated." -ForegroundColor Green
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Green


}
