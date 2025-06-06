param($Name, $Configuration, $Arch, $BuildMethod)
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true
./ip-graph-dotnet/ci/build-project.ps1 -RepoName ip-graph-dotnet -Name $Name -Configuration $Configuration -Arch $Arch
./ip-intelligence-cxx/ci/build-project.ps1 -RepoName ip-intelligence-cxx -Name $Name -Configuration $Configuration -Arch $Arch -BuildMethod $BuildMethod
