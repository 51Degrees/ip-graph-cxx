param($Name, $Configuration, $Arch, $BuildMethod)
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true
./internal-common-dotnet/ip-graph/ci/run-unit-tests.ps1 -RepoName internal-common-dotnet/ip-graph -Name $Name -Configuration $Configuration -Arch $Arch
./ip-intelligence-cxx/ci/run-unit-tests.ps1 -RepoName ip-intelligence-cxx -Name $Name -Configuration $Configuration -Arch $Arch -BuildMethod $BuildMethod
