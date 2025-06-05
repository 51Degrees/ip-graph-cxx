param(
    $DeviceDetection,
    $DeviceDetectionUrl,
    [string]$OrgName = "51Degrees"
)
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

# This has to be done here, since this is the first script called by nightly-pull-requests.build-and-test.ps1
$commit = git -C ip-graph-cxx rev-parse HEAD

Write-Host "Setting up ip-graph-dotnet..."
git clone --depth 1 --recurse-submodules --shallow-submodules https://github.com/$OrgName/ip-graph-dotnet.git
Remove-Item -Recurse -Force ip-graph-dotnet/Ip.Graph.C/graph
Copy-Item -Recurse ip-graph-cxx ip-graph-dotnet/Ip.Graph.C/graph # C preprocessor doesn't like symlinks here for some reason, so we copy
git -C ip-graph-dotnet/Ip.Graph.C/graph log -1

Write-Host "Setting up ip-intelligence-cxx..."
git clone --depth 1 --recurse-submodules --shallow-submodules https://github.com/$OrgName/ip-intelligence-cxx.git
Remove-Item -Recurse -Force ip-intelligence-cxx/src/ip-graph-cxx
Copy-Item -Recurse ip-graph-cxx ip-intelligence-cxx/src/ip-graph-cxx # C preprocessor doesn't like symlinks here for some reason, so we copy
git -C ip-intelligence-cxx/src/ip-graph-cxx log -1

# Actual fetch assets
./ip-intelligence-cxx/ci/fetch-assets.ps1 -RepoName ip-intelligence-cxx -DeviceDetection $DeviceDetection -DeviceDetectionUrl $DeviceDetectionUrl
