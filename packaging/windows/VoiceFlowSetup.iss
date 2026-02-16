#ifndef AppVersion
  #define AppVersion "3.0.0"
#endif

#ifndef RepoRoot
  #define RepoRoot "..\.."
#endif

#ifndef SourceDir
  #define SourceDir "..\..\dist\VoiceFlow"
#endif

[Setup]
AppId={{8F87ED35-3E8D-4A8F-A8B1-3C01B431A7DD}
AppName=VoiceFlow
AppVersion={#AppVersion}
AppPublisher=VoiceFlow
AppPublisherURL=https://github.com/yourusername/voiceflow
AppSupportURL=https://github.com/yourusername/voiceflow/issues
DefaultDirName={autopf}\VoiceFlow
DefaultGroupName=VoiceFlow
DisableProgramGroupPage=yes
OutputDir={#RepoRoot}\dist\installer
OutputBaseFilename=VoiceFlow-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
UninstallDisplayIcon={app}\VoiceFlow.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#RepoRoot}\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\VoiceFlow"; Filename: "{app}\VoiceFlow.exe"
Name: "{autodesktop}\VoiceFlow"; Filename: "{app}\VoiceFlow.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\VoiceFlow.exe"; Description: "Launch VoiceFlow now"; Flags: nowait postinstall skipifsilent
