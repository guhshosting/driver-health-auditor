# Run in a native x64 Visual Studio developer shell. Validation scripts are not runtime dependencies.
param([string]$ClangTidy = 'C:/Program Files/LLVM/bin/clang-tidy.exe',
      [string]$Cppcheck = 'C:/Program Files/Cppcheck/cppcheck.exe')
$ErrorActionPreference = 'Stop'
if (-not (Get-Command cl -ErrorAction SilentlyContinue)) { throw 'Run from a Visual Studio native developer shell.' }
New-Item -ItemType Directory -Path artifacts -Force | Out-Null
function Run([string]$log, [scriptblock]$command) {
    $global:LASTEXITCODE = 0
    & $command 2>&1 | Tee-Object "artifacts/$log"
    if ($LASTEXITCODE -ne 0) { throw "$log failed with exit $LASTEXITCODE" }
}
Run 'configure.txt' { cmake -S . -B build-native -G 'Ninja Multi-Config' -DCMAKE_EXPORT_COMPILE_COMMANDS=ON }
foreach ($configuration in @('Debug', 'Release')) {
    Run "build-$configuration.txt" { cmake --build build-native --config $configuration }
    Run "ctest-$configuration.txt" { ctest --test-dir build-native -C $configuration --output-on-failure }
}
Run 'independent-configure.txt' { cmake -S . -B build-independent -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON }
Run 'independent-build.txt' { cmake --build build-independent --clean-first }
Run 'ctest-independent.txt' { ctest --test-dir build-independent --output-on-failure }
Run 'analyze-configure.txt' { cmake -S . -B build-analyze -G Ninja -DCMAKE_BUILD_TYPE=Release -DDHA_ANALYZE=ON }
Run 'analyze.txt' { cmake --build build-analyze }
Run 'asan-configure.txt' { cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DDHA_ASAN=ON }
Run 'asan-build.txt' { cmake --build build-asan }
Run 'ctest-asan.txt' { ctest --test-dir build-asan --output-on-failure --timeout 30 }
$sources = @(rg --files src tests -g '*.cpp')
Run 'clang-tidy.txt' { & $ClangTidy -p build-independent --quiet '--checks=-*,clang-analyzer-*,bugprone-*,performance-*,portability-*' '--warnings-as-errors=*' $sources }
Run 'cppcheck.txt' { & $Cppcheck --enable=warning,style,performance,portability --error-exitcode=1 --std=c++17 --platform=win64 --inline-suppr -I include -DUNICODE -D_UNICODE -D_WIN32 -D_WIN32_WINNT=0x0A00 src tests }
& "$PSScriptRoot/integration.ps1"
& "$PSScriptRoot/integration.ps1" -Executable build-asan/driver-health-auditor.exe -Tests build-asan/dha_tests.exe -Output artifacts/asan-integration
Run 'install.txt' { cmake --install build-native --config Release --prefix install }
Run 'installed-version.txt' { & ./install/bin/driver-health-auditor.exe --version }
Run 'imports.txt' { dumpbin /imports ./build-native/Release/driver-health-auditor.exe }
Run 'manifest.txt' { mt '-inputresource:build-native/Release/driver-health-auditor.exe;#1' -out:artifacts/embedded.manifest }
& "$PSScriptRoot/safety-audit.ps1"
