; Ashgate installer. Needs Inno Setup 6.3 or newer.
; Build it with build-installer.ps1: it builds ashgate-src\dist first and
; passes the version from internal\version\version.go.

#ifndef AppVersion
  #error Pass the version: ISCC /DAppVersion=0.7.3 installer.iss (build-installer.ps1 does this)
#endif

#define AppName "Ashgate"
#define AppPublisher "jdmboy228"
#define AppURL "https://github.com/jdmboy228/Ashgatev2"
#define AppExe "ashgate.exe"
#define Src "ashgate-src"

[Setup]
; AppId identifies the installation for upgrades and uninstall. Never change it.
AppId={{1F695E51-8E7F-4B83-8E84-13113971A2C5}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Setup
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
; Program Files: Ashgate runs as administrator, so its files must not be
; writable by programs that run without administrator rights.
PrivilegesRequired=admin
DefaultDirName={autopf}\{#AppName}
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
LicenseFile={#Src}\LICENSE
SetupIconFile={#Src}\winres\ashgate.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
OutputDir={#Src}\dist
OutputBaseFilename=Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; A running Ashgate is closed by PrepareToInstall (ashgate quit), which stops
; capture cleanly. The Restart Manager would only hide it to the tray.
CloseApplications=no

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
ru.StillRunning=Ashgate не закрылся. Закройте его из трея («Выход») и нажмите «Далее» снова.
en.StillRunning=Ashgate is still running. Close it from the tray (Exit) and click Next again.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#Src}\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Src}\dist\WinDivert.dll"; DestDir: "{app}"
; The driver file can still be loaded right after Ashgate exits.
Source: "{#Src}\dist\WinDivert64.sys"; DestDir: "{app}"; Flags: restartreplace uninsrestartdelete
Source: "{#Src}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Src}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Src}\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Close the window, remove the kill switch's firewall rules and the
; autostart task. Settings in %ProgramData%\Ashgate are kept.
Filename: "{app}\{#AppExe}"; Parameters: "cleanup"; RunOnceId: "AshgateCleanup"; Flags: runhidden waituntilterminated

[Code]
// Close a running Ashgate the way «Выход» does, wherever it was started
// from. The new exe sends the signal, so an old copy in another folder is
// closed too. Codes: 0 closed, 2 not running (see gui.Quit).
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Result := '';
  ExtractTemporaryFile('{#AppExe}');
  if Exec(ExpandConstant('{tmp}\{#AppExe}'), 'quit', '', SW_HIDE, ewWaitUntilTerminated, Code) then
    if (Code <> 0) and (Code <> 2) then
      Result := CustomMessage('StillRunning');
end;
