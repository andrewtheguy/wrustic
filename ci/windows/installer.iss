; wrustic Windows installer: installs wrustic.exe and the wintun driver
; (wintun-amd64.dll) into the install directory, and a pinned restic.exe
; into its restic\ subdirectory. wrustic loads the driver from next to its
; executable (src/smb/tun.rs) and runs that bundled restic\restic.exe and
; no other — a missing one is an error rather than a fall back to PATH
; (src/restic.rs). The subdirectory matters: the install
; directory itself is appended to the system PATH so `wrustic` is typeable
; in a terminal, and restic must not ride along onto PATH with it.
;
; The install is machine-wide (Program Files, elevated) — only the program
; files. Config, state, and the restic cache stay per-user: wrustic derives
; them from the running user's profile at runtime and the installer never
; touches them.
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
; Machine-wide install: {autopf} is C:\Program Files here (64-bit mode).
DefaultDirName={autopf}\wrustic
PrivilegesRequired=admin
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
Source: "{#StageDir}\restic.exe"; DestDir: "{app}\restic"; Flags: ignoreversion

[Registry]
; Append the install directory to the system PATH so `wrustic` works from
; any terminal, for every user. Left in place on uninstall.
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath

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
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Path) then
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
