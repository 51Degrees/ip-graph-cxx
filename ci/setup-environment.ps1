param($OrgName, $GitHubUser)
$ErrorActionPreference = "Stop"
./internal-common-dotnet/ip-graph/ci/setup-environment.ps1 -OrgName $OrgName -GitHubUser $GitHubUser
./ip-intelligence-cxx/ci/setup-environment.ps1
