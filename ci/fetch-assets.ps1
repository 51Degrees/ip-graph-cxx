param(
    [string]$OrgName = "51Degrees"
)
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

# This has to be done here, since this is the first script called by nightly-pull-requests.build-and-test.ps1
Write-Host "Setting up ip-graph-dotnet..."
git clone --depth 1 --recurse-submodules --shallow-submodules https://github.com/$OrgName/ip-graph-dotnet.git
git -C ip-graph-dotnet submodule set-url Ip.Graph.C/graph $PWD/ip-graph-cxx
git -C ip-graph-dotnet -c protocol.file.allow=always submodule update --remote Ip.Graph.C/graph

Write-Host "No assets to fetch"
