#Directory of my versioned scripts and functions

$psdir="~\OneDrive\Documents\WindowsPowerShell\Include"


#load all scripts

Get-ChildItem $psdir -include *.ps1 -recurse | %{.$_}

Write-Host "Custom Powershell Environemnt Loaded"