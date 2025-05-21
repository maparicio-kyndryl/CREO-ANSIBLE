#version 1.0.1 - updated script for domain users group acception
#version 1.0.2 - linter changes fixed
#version 1.0.3 - Implemented conditional checks to validate the data before processing it further, skipping any irrelevant data
#version 1.0.4 - Fixed as per EAA sugestions
[cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('CN','__Server','Computer','IPAddress')]
        [string[]]$Computername = $env:COMPUTERNAME,
        [parameter()]
        [string]$Group = "Administrators",
        [parameter()]
        [int]$Depth = ([int]::MaxValue),
        [parameter()]
        [Alias("MaxJobs")]
        [int]$Throttle = 10
    )
    Begin {
        $PSBoundParameters.GetEnumerator() | ForEach-object {
            Write-Verbose $_ -Verbose
        }
        #region Extra Configurations
        Write-Verbose ("Depth: {0}" -f $Depth) -Verbose
        #endregion Extra Configurations
        #Define hash table for Get-RunspaceData function
        $runspacehash = @{}
        #Function to perform runspace job cleanup
        Function Get-RunspaceData {
            [cmdletbinding()]
            param(
                [switch]$Wait
            )
            Do {
                $more = $false
                Foreach($runspace in $runspaces) {
                    If ($runspace.Runspace.isCompleted) {
                        $runspace.powershell.EndInvoke($runspace.Runspace)
                        $runspace.powershell.dispose()
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                    } ElseIf ($Null -ne $runspace.Runspace) {
                        $more = $true
                    }
                }
                If ($more -AND $PSBoundParameters['Wait']) {
                    Start-Sleep -Milliseconds 100
                }
                #Clean out unused runspace jobs
                $temphash = $runspaces.clone()
                $temphash | Where-object {
                    $Null -eq $_.runspace
                } | ForEach-object {
                    Write-Verbose ("Removing {0}" -f $_.computer) -Verbose
                    $Runspaces.remove($_)
                }
            } while ($more -AND $PSBoundParameters['Wait'])
        }

        #region ScriptBlock
            $scriptBlock = {
            Param ($Computer,$Group,$Depth,$NetBIOSDomain,$ObjNT,$Translate)
            $Script:Depth = $Depth
            $Script:ObjNT = $ObjNT
            $Script:Translate = $Translate
            $Script:NetBIOSDomain = $NetBIOSDomain
            Function Get-LocalMyGroupMember {
                [cmdletbinding()]
                Param (
                    [parameter()]
                    [System.DirectoryServices.DirectoryEntry]$LocalGroup
                )
                # Invoke the Members method and convert to an array of member objects.
                $Members= @($LocalGroup.psbase.Invoke("Members")) | foreach-object{([System.DirectoryServices.DirectoryEntry]$_)}
				$Counter++
                ForEach ($Member In $Members) {
                    Try {
						#Change3
                        #$Name = $Member.GetType().InvokeMember("Name", 'GetProperty', $Null, $Member, $Null)
                        #$Path = $Member.GetType().InvokeMember("ADsPath", 'GetProperty', $Null, $Member, $Null)
                        $Name = $Member.InvokeGet("Name")
						$Path = $Member.InvokeGet("AdsPath")
                        write-verbose "USer local Adspath-->$path" -Verbose
                        $DomainName=$Path
						# Check if this member is a group.
                        $isGroup = ($Member.InvokeGet("Class") -eq "group")



						#region Change1 by Kensel
						#Remove the domain from the computername to fix the type comparison when supplied with FQDN
						IF ($Computer.Contains('.')){

							$Computer = $computer.Substring(0,$computer.IndexOf('.'))
						}
						#endregion Change1 by Kensel

						If (($Path -like "*/$Computer/*")) {
                            $Type = 'Local'
                        } Else {$Type = 'Domain'}
						#Change2 by Kensel - Add the Group to the output

                       if ($Type -eq 'Domain'){
                        New-Object PSObject -Property @{
                            Computername = $Computer
                            UserName = $Name
                            Type = $Type
                            ParentGroup = $LocalGroup.Name[0]
                            isGroup = $isGroup
                            Depth = $Counter
							PrivGroup = $Group
                            Domainname=$DomainName
                        }

                        }
                        If ($isGroup) {
                            # Check if this group is local or domain.
                            If ($Counter -lt $Depth) {
                                If ($Type -eq 'Local') {
                                    If ($Groups[$Name] -notcontains 'Local') {
                                       # $host.ui.WriteVerboseLine(("{0}: Getting local group members" -f $Name))
                                        #$Groups[$Name] += ,'Local'
                                        # Enumerate members of local group.
                                        Get-LocalMyGroupMember $Member
                                    }
                                } Else {
                                    If ($Groups[$Name] -notcontains 'Domain') {
                                        $host.ui.WriteVerboseLine(("{0}: Getting domain group members" -f $Name))
                                        $Groups[$Name] += ,'Domain'
					###############################
					#new code to get disntinguished name
                    $domain = $DomainName
                    $domain = $domain -replace('WinNT://','')
                    $domain = $domain -split "/"
                    $domain = $domain[0]
                    $domain
                    write-verbose "dom check : $domain" -Verbose
                    $groupName = $Name

                    # Create a directory searcher object
                       $searcher = New-Object System.DirectoryServices.DirectorySearcher
                       $searcher.Filter = "(&(objectClass=group)(cn=$groupName))"
                        $searcher.SearchRoot = "LDAP://$domain"

                        # Perform the search
                    $result = $searcher.FindOne()
                    $distinguishedName = $result.Properties["distinguishedName"][0]
                    $Member = $distinguishedName
					####################################
                                        # Enumerate members of domain group.
                                        #Get-DomainGroupMember $Member $Name $True
					Get-DomainGroupMember -DomainGroup $Member -NTName $Name -blnNT $True
                                    }
                                }
                            }
                        }
                    } Catch {
                        $host.ui.WriteWarningLine(("GLGM{0}" -f $_.Exception.Message))
                    }
                }
            }
            #############################################################
            # Function to recursively get group members using ADSI
function Get-NestedGroupMembersADSI {
    param (
        [string]$groupName,
        [string]$ParentName,
        [string]$PrivGrp
    )

    # Get the group using ADSI
    write-verbose "checking the group name in nestgroup:$groupName" -Verbose

    $group = [adsi]"LDAP://$groupName"

    write-verbose "checking for grp val: $group" -Verbose

    # Iterate through each member
    foreach ($memberDN in $group.member) {

    write-verbose "checking memberdn:$memberDN" -Verbose

       $user = [adsi]"LDAP://$memberDN"
            if ($user.objectClass -eq "group") {write-verbose "Found the group" -Verbose} else {write-verbose "not Found the group" -Verbose}
        # Check if the member is a group
        if ($user.objectClass -eq "group") {
            # If it's a group, recursively call the function

            write-verbose "Found the group iterating again : $user.cn" -Verbose
            Get-NestedGroupMembersADSI -groupName $user.cn
        } else {
            # If it's a user, display the user information
            write-verbose "User: $($user.sAMAccountName)" -Verbose
            $userval= $user.sAMAccountName
            $userval= $userval.replace("{","")
            $userval= $userval.replace("}","")
            New-Object PSObject -Property @{
                            Computername = $Computer
                            UserName = $userval
                            ParentGroup = $ParentName
                            Type = 'Domain'
                            isGroup = "False"
                            Depth = $Counter
							PrivGroup = $PrivGrp
                            Domainname=$DomainName
                        }
        }
    }
}

            ##################################################
            Function Get-DomainGroupMember {
                [cmdletbinding()]
                Param (
                    [parameter()]
                    $DomainGroup,
                    [parameter()]
                    [string]$NTName,
                    [parameter()]
                    [string]$blnNT
                )
                Try {

                    If ($blnNT -eq $True) {
                        # Convert NetBIOS domain name of group to Distinguished Name.
                        #$objNT.InvokeMember("Set", "InvokeMethod", $Null, $Translate, (3, ("{0}{1}" -f $NetBIOSDomain.Trim(),$NTName)))
                        #$DN = $objNT.InvokeMember("Get", "InvokeMethod", $Null, $Translate, 1)
                        $DN = $DomainGroup
			#if making any issue with data try commenting the below condition
			if($DN -match "System.DirectoryServices.DirectoryEntry"){
			continue}

                        $ADGroup = [ADSI]"LDAP://$DN"
                         write-verbose "domain group details-->LDAP://$DN" -Verbose
                    } Else {
                        $DN = $DomainGroup.distinguishedName
                        $ADGroup = $DomainGroup
                         Write-Verbose "else condition" -Verbose
                    }

                    $Counter++
                    ForEach ($MemberDN In $ADGroup.Member) {
                    $test=$MemberDN -replace '/','\/'
                    write-verbose "replace-->$test" -Verbose
                        $MemberGroup = [ADSI]("LDAP://{0}" -f ($MemberDN -replace '/','\/'))

                        #Change2 by Kensel - Add the Group to the output
                       # write-verbose "Name-->$MemberDN"
                         $DomainName=$MemberDN
                        $DomainName=($DomainName -split ","| where-object {$_ -match "DC="}) -replace "DC="
                          $Username=$MemberGroup.name[0]
                          write-verbose "Checking the username : $Username" -Verbose
                          if($isGroup){
                        # Call the function with the initial group name
                        write-verbose "Calling the groupname : $test" -Verbose
                        Get-NestedGroupMembersADSI -groupName $test $Username $Group } else {write-verbose "not  a group" -Verbose}

                          #,Name,GivenName,Sn,Title,Description,WhenCreated,WhenChanged
                        $Members= @($LocalGroup.psbase.Invoke("Members")) | ForEach-Object{($MemberGroup)}
                         ForEach ($Member In $Members) {

						#Change3
                        #$Name = $Member.GetType().InvokeMember("Name", 'GetProperty', $Null, $Member, $Null)
                        #$Path = $Member.GetType().InvokeMember("ADsPath", 'GetProperty', $Null, $Member, $Null)
                        #$Name = $Member.InvokeGet("Name")
                     						$Path = $Member.InvokeGet("AdsPath")

                         $Username=$Member.InvokeGet("sAMAccountName")
                         write-verbose "Username-->$Path" -Verbose
                         break

                        }



						New-Object PSObject -Property @{
                            Computername = $Computer
                            UserName = $Username
                            Type = 'Domain'
                            ParentGroup = $NTName
                            isGroup = ($MemberGroup.Class -eq "group")
                            Depth = $Counter
							PrivGroup = $Group
                            Domainname=$DomainName
                        }

                        # Check if this member is a group.
                        If ($MemberGroup.Class -eq "group") {
                            If ($Counter -lt $Depth) {
                                If ($Groups[$MemberGroup.name[0]] -notcontains 'Domain') {
                                    Write-Verbose ("{0}: Getting domain group members" -f $MemberGroup.name[0]) -Verbose
                                    $Groups[$MemberGroup.name[0]] += ,'Domain'
                                    # Enumerate members of domain group.
                                    Write-Verbose ("Membergroup val-->$MemberGroup") -Verbose
                                    #Get-DomainGroupMember $MemberGroup $MemberGroup.Name[0] $True
					Get-DomainGroupMember -DomainGroup $MemberGroup -NTName $MemberGroup.Name[0] -blnNT $True
                                }
                            }
                        }
                    }
                } Catch {
                    $host.ui.WriteWarningLine(("GDGM{0}" -f $_.Exception.Message))
                }
            }
            #region Get Local Group Members
            $Script:Groups = @{}
            $Script:Counter=0
            # Bind to the group object with the WinNT provider.
            $ADSIGroup = [ADSI]"WinNT://$Computer/$Group,group"
            Write-Verbose ("Checking {0} membership for {1}" -f $Group,$Computer) -Verbose
            $Groups[$Group] += ,'Local'
            Get-LocalMyGroupMember -LocalGroup $ADSIGroup
            #endregion Get Local Group Members
        }
        #endregion ScriptBlock
        Write-Verbose ("Checking to see if connected to a domain") -Verbose
        Try {
            $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $Root = $Domain.GetDirectoryEntry()
            $Base = ($Root.distinguishedName)

            # Use the NameTranslate object.
            $Script:Translate = New-Object -comObject "NameTranslate"
            $Script:objNT = $Translate.GetType()

            # Initialize NameTranslate by locating the Global Catalog.
            $objNT.InvokeMember("Init", "InvokeMethod", $Null, $Translate, (3, $Null))

            # Retrieve NetBIOS name of the current domain.
            $objNT.InvokeMember("Set", "InvokeMethod", $Null, $Translate, (1, "$Base"))
            [string]$Script:NetBIOSDomain =$objNT.InvokeMember("Get", "InvokeMethod", $Null, $Translate, 3)
        } Catch {Write-Warning ("{0}" -f $_.Exception.Message)}

        #region Runspace Creation
        Write-Verbose ("Creating runspace pool and session states") -Verbose
        $sessionstate = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
        $runspacepool.Open()

        Write-Verbose ("Creating empty collection to hold runspace jobs") -Verbose
        $Script:runspaces = New-Object System.Collections.ArrayList
        #endregion Runspace Creation
    }

    Process {
        ForEach ($Computer in $Computername) {
            #Create the powershell instance and supply the scriptblock with the other parameters
            $powershell = [powershell]::Create().AddScript($scriptBlock).AddArgument($computer).AddArgument($Group).AddArgument($Depth).AddArgument($NetBIOSDomain).AddArgument($ObjNT).AddArgument($Translate)

            #Add the runspace into the powershell instance
            $powershell.RunspacePool = $runspacepool

            #Create a temporary collection for each runspace
            $temp = "" | Select-Object PowerShell,Runspace,Computer
            $Temp.Computer = $Computer
            $temp.PowerShell = $powershell

            #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
            $temp.Runspace = $powershell.BeginInvoke()
            Write-Verbose ("Adding {0} collection" -f $temp.Computer) -Verbose
            $runspaces.Add($temp) | Out-Null

            Write-Verbose ("Checking status of runspace jobs") -Verbose
            Get-RunspaceData @runspacehash
        }
    }
    End {
        #Write-Verbose ("Finish processing the remaining runspace jobs: {0}" -f (@(($runspaces | Where-object {$_.Runspace -ne $Null}).Count))) -Verbose
        Write-Verbose "finish processing the remaining jobs"
	$runspacehash.Wait = $true
        Get-RunspaceData @runspacehash

        #region Cleanup Runspace
        Write-Verbose ("Closing the runspace pool") -Verbose
        $runspacepool.close()
        $runspacepool.Dispose()
        #endregion Cleanup Runspace
    }