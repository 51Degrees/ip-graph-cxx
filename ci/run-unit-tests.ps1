param($Name, $Configuration, $Arch, $BuildMethod)
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true
./ip-graph-dotnet/ci/run-unit-tests.ps1 -RepoName ip-graph-dotnet -Name $Name -Configuration $Configuration -Arch $Arch
./ip-intelligence-cxx/ci/run-unit-tests.ps1 -RepoName ip-intelligence-cxx -Name $Name -Configuration $Configuration -Arch $Arch -BuildMethod $BuildMethod
