function Get-ServerEngInfo ($csvImport)
{
    pushd -Path .\Ephemeral  # my temp directory

    if (!($csvImport)) 
    {
        # Read the Name Column from the CSV file
        $csvImport = Import-Csv .\Test.csv
    }
 
    # For Each Computer Name perform Ping Test
    $results = foreach ($computer in $csvImport)
    {
        $computerName = $computer.Name
        if (Test-Connection $computerName -Count 1)
        { 
            $address = (Test-Connection $computerName -Count 1 -ErrorAction SilentlyContinue).IPV4Address.ipaddresstostring
        }
        else
        {
            $address = "Offline"
        }
        [PSCustomObject]@{
        Computer = $computerName
        Address = $address}
    }
# Sample outputs - pick one or more, your choice
$results
$results | Format-Table -AutoSize
$results | Out-GridView
$results | Export-Csv -Path .\foo.csv -NoTypeInformation -Encoding ASCII
$results | Out-File -FilePath .\foo.txt -Encoding ASCI
$results | Export-Clixml -Path .\foo.xml -Encoding ASCII
}
