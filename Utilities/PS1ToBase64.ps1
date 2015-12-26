#########################################
# Convert a PS1 File to a Base64 String #
# By Cn33liz 2015                       #
#########################################

param (
   [string]$inputFile  = $(throw "-inputFile is required."),
   [string]$outputFile = $(throw "-outputFile is required.")
)

Write-Host ""
Write-Host "Reading input file: " -NoNewline 
Write-Host $inputFile 
Write-Host ""
$content = Get-Content -LiteralPath ($inputFile) -Encoding UTF8 -ErrorAction SilentlyContinue
if( $content -eq $null ) {
	Write-Host "No data found. May be read error or file protected."
	exit -2
}
$scriptInp = [string]::Join("`r`n", $content)
$script = [System.Convert]::ToBase64String(([System.Text.Encoding]::UTF8.GetBytes($scriptInp)))

Write-Host "Writing Base64 string to: " -NoNewline 
Write-Host $outputFile 
Write-Host ""
$script | out-file $outputFile