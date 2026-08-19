param(
    $DeviceDetection,
    $DeviceDetectionUrl,
    [string]$OrgName = "51Degrees"
)
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

# This has to be done here, since this is the first script called by nightly-pull-requests.build-and-test.ps1
$commit = git -C ip-graph-cxx rev-parse HEAD

Write-Host "Setting up internal-common-dotnet..."
# Not a recursive clone: only the common-cxx submodule is needed, the graph
# submodule is replaced with the local working copy below.
git clone --depth 1 https://github.com/$OrgName/internal-common-dotnet.git
git -C internal-common-dotnet submodule update --init --depth 1 ip-graph/Ip.Graph.C/common-cxx
Remove-Item -Recurse -Force internal-common-dotnet/ip-graph/Ip.Graph.C/graph
Copy-Item -Recurse ip-graph-cxx internal-common-dotnet/ip-graph/Ip.Graph.C/graph # C preprocessor doesn't like symlinks here for some reason, so we copy
git -C internal-common-dotnet/ip-graph/Ip.Graph.C/graph log -1

Write-Host "Setting up ip-intelligence-cxx..."
git clone --depth 1 --recurse-submodules --shallow-submodules https://github.com/$OrgName/ip-intelligence-cxx.git
Remove-Item -Recurse -Force ip-intelligence-cxx/src/ip-graph-cxx
Copy-Item -Recurse ip-graph-cxx ip-intelligence-cxx/src/ip-graph-cxx # C preprocessor doesn't like symlinks here for some reason, so we copy
git -C ip-intelligence-cxx/src/ip-graph-cxx log -1

# Actual fetch assets
./ip-intelligence-cxx/ci/fetch-assets.ps1 -RepoName ip-intelligence-cxx -DeviceDetection $DeviceDetection -DeviceDetectionUrl $DeviceDetectionUrl
