@echo off
setlocal
set "SCRIPT=%~dp0hyperv_provision.ps1"
if not exist "%SCRIPT%" (
  echo Script nao encontrado: "%SCRIPT%"
  pause
  exit /b 2
)
echo RE_Megazord - provisionamento inicial Hyper-V (VM fica desligada)
echo O Windows exibira o prompt UAC padrao. Nenhum bypass de elevacao sera usado.
echo O VHD fonte sera preservado; se necessario, uma copia Fixed create-only sera criada em E:.
powershell.exe -NoLogo -NoProfile -Command "$scriptPath = $env:SCRIPT; $argumentLine = '-NoLogo -NoProfile -File ' + [char]34 + $scriptPath + [char]34; $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Normal -ArgumentList $argumentLine -Wait -PassThru; exit $p.ExitCode"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" echo Provisionamento bloqueado ou incompleto. Consulte o relatorio emitido pelo script.
pause
exit /b %RC%

