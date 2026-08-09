; wrustic Windows installer: installs wrustic.exe, the wintun driver
; (wintun-amd64.dll), and a pinned restic.exe side by side in one directory.
; wrustic loads the driver from next to its executable (src/smb/tun.rs) and
; prefers the sibling restic over PATH (src/restic.rs), so the install
; directory is the whole runtime contract.
;
; Built by .github/workflows/release.yml with Inno Setup 6:
;   ISCC.exe /DAppVersion=<version> /DStageDir=<dir> /DOutDir=<dir> ci\windows\installer.iss
; StageDir must contain wrustic.exe, wintun-amd64.dll, and restic.exe.
; StageDir and OutDir must be absolute: relative paths here resolve against
; this file's directory, not the invoker's working directory.

#ifndef AppVersion
  #error AppVersion must be defined (/DAppVersion=x.y.z)
#endif
#ifndef StageDir
  #error StageDir must be defined (/DStageDir=path)
#endif
#ifndef OutDir
  #error OutDir must be defined (/DOutDir=path)
#endif

[Setup]
AppId={{7C0A19D4-3B84-4E1E-9E36-BB0C6E7D8A11}
AppName=wrustic
AppVersion={#AppVersion}
AppPublisher=andrewtheguy
AppPublisherURL=https://github.com/andrewtheguy/wrustic
; Per-user install, no elevation: same location install.ps1 used before.
; (--smb-tun still needs an elevated *runtime*; installing does not.)
DefaultDirName={localappdata}\Programs\wrustic
PrivilegesRequired=lowest
DisableProgramGroupPage=yes
DisableReadyPage=yes
OutputDir={#OutDir}
OutputBaseFilename=wrustic-windows-amd64-setup
; x64os, not x64compatible: the payload includes the amd64 wintun kernel
; driver, which an Arm64 Windows running wrustic under x64 emulation could
; never load — this stays AMD64-only, matching the documented release
; support. (x64os is Inno Setup 6.3's name for what was previously `x64`.)
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
ChangesEnvironment=yes
Compression=lzma2
SolidCompression=yes
Uninstallable=yes

[Files]
Source: "{#StageDir}\wrustic.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\wintun-amd64.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\restic.exe"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
; Append the install directory to the user PATH so `wrustic` works from any
; terminal. Left in place on uninstall, matching what install.ps1 did.
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath

[Code]
// Whole-entry comparison, not substring: a sibling like
// ...\Programs\wrustic-old must not count as this directory being present.
function NeedsAddPath: Boolean;
var
  Path, App, Entry: string;
  Rest: string;
  P: Integer;
begin
  Result := True;
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', Path) then
    exit;
  App := Lowercase(RemoveBackslash(ExpandConstant('{app}')));
  Rest := Path;
  while Rest <> '' do
  begin
    P := Pos(';', Rest);
    if P = 0 then
    begin
      Entry := Rest;
      Rest := '';
    end
    else
    begin
      Entry := Copy(Rest, 1, P - 1);
      Rest := Copy(Rest, P + 1, Length(Rest));
    end;
    if Lowercase(RemoveBackslash(Trim(Entry))) = App then
    begin
      Result := False;
      exit;
    end;
  end;
end;
