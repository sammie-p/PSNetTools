# PSNetTools
A collection of networking tools for PowerShell

The purpose of this repository is to collect various functions and other tools I have written in PowerShell for the purposes of network administration.

# NtpTools.ps1
This implements a basic NTP client in PowerShell for the purpose of profiling NTP servers in a one-time method. It is not capable of tracking NTP servers and calculaing things like jitter, but it is useful for chosing reliable NTP servers when run in a script on a client, or chosing a reliable source of the current date and time.

Execute and run 
Get-NtpTime -ComputerName "au.pool.ntp.org","ntp.myhome.com" -ExpandHosts

The ComputerName parameter can also be taken from the pipeline.
@("au.pool.ntp.org","ntp.myhome.com") | Get-NtpTime -ExpandHosts -ResolveNames

ExpandHosts will use all the IP addresses resolved from a DNS query of each host name. ResolveNames will attempt to perform a PTR lookup of IP addresses for both the peer IP and the RefID.

