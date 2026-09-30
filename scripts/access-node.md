Commands to test firewall

`Test-WSMan` will try to connect to the local machine

`netsh advfirewall show currentprofile` will show the current profile in the first string of output,
for example "Private Profile Settings:"

`Get-NetFirewallRule -DisplayGroup "Windows Remote Management" | Select-Object DisplayName, Enabled, Direction, Action, Profile`

Will show WinRM firewall rule status. You'll need to check HTTPS-In in the Display name and Profile
which is matching the current one. Rule should be Allowed and Enabled

`Get-NetTCPConnection -LocalPort 5986 -State Listen` Checks posrt listening status

`winrm enumerate winrm/config/listener` Displays listener status from winrm
