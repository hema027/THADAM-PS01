param (
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet("setup", "test", "seed", "pipeline", "app", "corpus", "fetch", "bench", "shots")]
    [string]$Command
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

$PythonExe = Join-Path $RepoRoot "venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

switch ($Command) {
    "setup" {
        & $PythonExe -m pip install -r requirements.txt
        & $PythonExe -m playwright install chromium
    }
    "test" {
        & $PythonExe -m pytest -q
    }
    "seed" {
        & $PythonExe scripts/make_seed.py
    }
    "pipeline" {
        & $PythonExe -m pipeline
    }
    "app" {
        & $PythonExe -m streamlit run app/streamlit_app.py
    }
    "corpus" {
        & $PythonExe -m corpus.build_corpus
    }
    "fetch" {
        & $PythonExe -m detect.fetcher --all
    }
    "bench" {
        & $PythonExe -m detect.fetcher --bench
    }
    "shots" {
        & $PythonExe -m detect.fetcher --shots
    }
}
