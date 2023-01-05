<#
Example Use:
.\nsxv2t-premigration-nsxv-apply-ipsets.ps1
#>

param($VcIP, $VcUser, $VcPass, $NSXvIP, $NSXvUser, $NSXvPass)

Import-Module -Name powernsx

if (-not $VcPass) {
    $VcPass = Read-Host 'VC Password' -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($VcPass)
    $VcPassValue = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    Connect-VIServer $VcIP -User $VcUser -Password $VcPassValue
    Connect-NsxServer -vCenterServer $VcIP -ValidateCertificate:$false -Username $VcUser -Password $VcPassValue
} else {
    Connect-VIServer $VcIP -User $VcUser -Password $VcPass
    Connect-NsxServer -vCenterServer $VcIP -ValidateCertificate:$false -Username $VcUser -Password $VcPass
    
}

$firewallRules = Get-NsxFirewallRule
$ruleMemberArray = @()

$securityGroups = Get-NsxSecurityGroup
$secuityGroupsArray = @()

$ipSets = Get-NsxIpSet

$VMs = Get-VM

$vmNoIpFoundArray = @()

foreach ($rule in $firewallRules) {
    foreach ($destination in ($rule.destinations.destination | where type -eq "VirtualMachine")) {
        $vm = Get-VM -Name $destination.name
        if ($vm.Guest.IPAddress.where{($_ -match ".")}.count -eq 0){
            $vmNoIpFoundObject = [PSCustomObject]@{
                vm_name = $vm.name
                vm_state = $vm.PowerState
            }
            $vmNoIpFoundArray += $vmNoIpFoundObject
        }
        foreach ($ip in $vm.guest.IPAddress) {
            if ($ip.contains(".") -AND -not ($rule.destinations.destination.value).contains($ip)) {
                $ruleMemberObject = [PSCustomObject]@{
                    rule_name = $rule.name
                    rule_id = $rule.id
                    direction = "destination"
                    vm_name = $vm.name
                    member = $ip
                }
                $ruleMemberArray += $ruleMemberObject
            }
        }     
    }
    foreach ($source in $rule.sources.source | where type -eq "VirtualMachine") {
        $vm = Get-VM -Name $source.name
        if ($vm.Guest.IPAddress.where{($_ -match ".")}.count -eq 0){
            $vmNoIpFoundObject = [PSCustomObject]@{
                vm_name = $vm.name
                vm_state = $vm.PowerState
            }
            $vmNoIpFoundArray += $vmNoIpFoundObject
        }        
        foreach ($ip in $vm.guest.IPAddress) {
            if ($ip.contains(".") -AND -not ($rule.sources.source.value).contains($ip)) {
                $ruleMemberObject = [PSCustomObject]@{
                    rule_name = $rule.name
                    rule_id = $rule.id
                    direction = "source"
                    vm_name = $vm.name
                    member = $ip
                }
                $ruleMemberArray += $ruleMemberObject
            }
        }     
    }    
}

foreach ($ruleMember in $ruleMemberArray) {
    try {
        Get-NsxFirewallRule -RuleId $ruleMember.rule_id  | Add-NsxFirewallRuleMember -MemberType $ruleMember.direction -Member $ruleMember.member | Out-Null
        Write-Host -ForegroundColor Green 'SUCCESS: Added '$ruleMember.vm_name ' - ' $ruleMember.member ' to rule ' $ruleMember.rule_id ' - ' $ruleMember.rule_name ' - ' $ruleMember.direction
    } catch {
        Write-Host -ForegroundColor Red 'ERROR: Failed to add ' $ruleMember.vm_name ' - ' $ruleMember.member ' to rule ' $ruleMember.rule_id ' - ' $ruleMember.rule_name ' - ' $ruleMember.direction
        Write-Output ("FAILED")
        $ruleMember.name
        $ruleMember.rule_id
        $ruleMember.direction
        $ruleMember.member
        Write-Output ("")
    }
}

foreach ($securityGroup in $securityGroups){
    $effectiveIpAddresses = Get-NsxSecurityGroupEffectiveIpAddress -SecurityGroup $securityGroup
    
    $ipv4name = "ipsv4-" + $securityGroup.name

    if($ipSets.where{($_.name -eq $ipv4name)}.count -eq 0) {
        $ipSetv4 = New-NsxIpSet -name $ipv4name
    } else {
        $ipSetv4 = Get-NsxIpSet -name $ipv4name
    }

    foreach ($ip in $EffectiveipAddresses.IpAddress) {
        if ($ip -match "/" -OR $ip -match "-") {
            #Skip IPSet Ipaddresses
            continue
        }
        $checkifip = [IPAddress] $ip
        if ($checkifip.AddressFamily.ToString() -eq "InterNetwork") {
            Get-NsxIpSet -objectId $ipSetv4.objectId | Add-NsxIpSetMember -IPAddress ($ip.ToString() + "/32")
        }
    }

    Get-NsxSecurityGroup -objectId $securityGroup.objectID |  Add-NsxSecurityGroupMember -Member $ipSetv4
}

foreach ($vm in $VMs) {
    if ($vm.Guest.IPAddress.where{($_ -match ".")}.count -eq 0){
        $vmNoIpFoundObject = [PSCustomObject]@{
            vm_name = $vm.name
            vm_state = $vm.PowerState
        }
        $vmNoIpFoundArray += $vmNoIpFoundObject
    }
}

if ($vmNoIpFoundArray.count -gt 0) {
    Write-Output ("")
    Write-Host -ForegroundColor Red "ERROR: No IPs can be found for the following VMs:"
    $vmNoIpFoundArray | Format-Table
}