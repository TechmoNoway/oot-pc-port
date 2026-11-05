param([string]$Compiler = 'C:\msys64\ucrt64\bin\gcc.exe')

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputDirectory = Join-Path $projectRoot 'build'
$executable = Join-Path $outputDirectory 'oot-pc-port.exe'

if (!(Test-Path -LiteralPath $Compiler -PathType Leaf)) {
    throw "C compiler not found: $Compiler. Pass -Compiler with the path to a Windows GCC compiler."
}
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$compilerArguments = @(
    '-std=c17', '-O2', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
    '-DWIN32_LEAN_AND_MEAN', '-DNOMINMAX', '-D_WIN32_WINNT=0x0A00',
    (Join-Path $projectRoot 'src/main.c'),
    (Join-Path $projectRoot 'src/host_win32.c'),
    (Join-Path $projectRoot 'src/guest_memory.c'),
    (Join-Path $projectRoot 'src/runtime_image.c'),
    '-D_CRT_SECURE_NO_WARNINGS', '-lbcrypt',
    '-o', $executable
)
& $Compiler @compilerArguments
if ($LASTEXITCODE -ne 0) { throw "Compilation failed with exit code $LASTEXITCODE." }
& $executable --self-test
if ($LASTEXITCODE -ne 0) { throw "Host self-test failed with exit code $LASTEXITCODE." }
Write-Output "Built $executable"
