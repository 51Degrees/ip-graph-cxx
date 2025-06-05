param($OrgName, $GitHubUser)
$ErrorActionPreference = "Stop"
./ip-graph-dotnet/ci/setup-environment.ps1 -OrgName $OrgName -GitHubUser $GitHubUser
./ip-intelligence-cxx/ci/setup-environment.ps1
