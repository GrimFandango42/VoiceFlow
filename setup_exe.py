"""
VoiceFlow Windows Executable Builder
Creates standalone .exe installer using PyInstaller and Inno Setup
"""

import os
import sys
import subprocess
from pathlib import Path

def check_requirements():
    """Check if required tools are installed"""
    required_tools = {
        'pyinstaller': 'pip install pyinstaller',
        'pillow': 'pip install pillow',
        'inno-setup': 'Download from https://jrsoftware.org/isdl.php'
    }
    
    missing = []
    
    # Check PyInstaller
    try:
        import PyInstaller
        print("✅ PyInstaller found")
    except ImportError:
        missing.append('pyinstaller')
    
    # Check Pillow
    try:
        import PIL
        print("✅ Pillow found")
    except ImportError:
        missing.append('pillow')
    
    # Check Inno Setup (Windows only)
    if os.name == 'nt':
        inno_paths = [
            r"C:\Program Files (x86)\Inno Setup 6\iscc.exe",
            r"C:\Program Files\Inno Setup 6\iscc.exe"
        ]
        
        inno_found = any(os.path.exists(path) for path in inno_paths)
        if inno_found:
            print("✅ Inno Setup found")
        else:
            missing.append('inno-setup')
    
    if missing:
        print("❌ Missing required tools:")
        for tool in missing:
            print(f"   {tool}: {required_tools[tool]}")
        return False
    
    return True

def create_spec_file():
    """Create PyInstaller spec file for VoiceFlow"""
    spec_content = '''
# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['voiceflow_windows.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('voiceflow_personal.py', '.'),
        ('core', 'core'),
        ('utils', 'utils'),
        ('requirements_windows.txt', '.'),
    ],
    hiddenimports=[
        'pystray._win32',
        'PIL._tkinter_finder',
        'pyautogui',
        'keyboard',
        'RealtimeSTT',
        'requests',
        'asyncio',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='VoiceFlow',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Hide console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico'  # Add icon if available
)
'''
    
    with open('voiceflow.spec', 'w') as f:
        f.write(spec_content.strip())
    
    print("✅ Created voiceflow.spec")

def create_inno_setup_script():
    """Create Inno Setup script for installer"""
    iss_content = '''
#define MyAppName "VoiceFlow"
#define MyAppVersion "3.0.0"
#define MyAppPublisher "VoiceFlow"
#define MyAppURL "https://github.com/GrimFandango42/voiceflow"
#define MyAppExeName "VoiceFlow.exe"

[Setup]
AppId={{8A9B1C2D-3E4F-5A6B-7C8D-9E0F1A2B3C4D}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=LICENSE
InfoAfterFile=README.md
OutputDir=dist
OutputBaseFilename=VoiceFlow-Setup-{#MyAppVersion}
SetupIconFile=icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 6.1

[Files]
Source: "dist\\VoiceFlow.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "requirements_windows.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"
Name: "{group}\\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userappdata}\\Microsoft\\Internet Explorer\\Quick Launch\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"; Tasks: quicklaunchicon

[Run]
Filename: "{app}\\{#MyAppExeName}"; Parameters: "--tray"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
function GetPythonPath: String;
var
  PythonPath: String;
begin
  if RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\\Python\\PythonCore\\3.9\\InstallPath', '', PythonPath) or
     RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\\Python\\PythonCore\\3.10\\InstallPath', '', PythonPath) or
     RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\\Python\\PythonCore\\3.11\\InstallPath', '', PythonPath) or
     RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\\Python\\PythonCore\\3.12\\InstallPath', '', PythonPath) then
  begin
    Result := PythonPath;
  end
  else
  begin
    Result := '';
  end;
end;

function InitializeSetup(): Boolean;
var
  PythonPath: String;
begin
  PythonPath := GetPythonPath;
  if PythonPath = '' then
  begin
    if MsgBox('Python 3.8+ is required but not found. Would you like to download it?', mbConfirmation, MB_YESNO) = IDYES then
    begin
      ShellExecAsOriginalUser('open', 'https://www.python.org/downloads/', '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode);
    end;
    Result := False;
  end
  else
  begin
    Result := True;
  end;
end;
'''
    
    with open('voiceflow_installer.iss', 'w') as f:
        f.write(iss_content.strip())
    
    print("✅ Created voiceflow_installer.iss")

def create_simple_icon():
    """Create a simple icon file if none exists"""
    if os.path.exists('icon.ico'):
        return
    
    try:
        from PIL import Image, ImageDraw
        
        # Create a simple microphone icon
        size = (64, 64)
        image = Image.new('RGBA', size, color=(0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        
        # Draw microphone
        draw.ellipse([16, 8, 48, 40], fill='blue', outline='darkblue', width=2)
        draw.rectangle([28, 40, 36, 50], fill='blue')
        draw.line([20, 56, 44, 56], fill='blue', width=3)
        
        # Save as ICO
        image.save('icon.ico', format='ICO', sizes=[(64, 64), (32, 32), (16, 16)])
        print("✅ Created icon.ico")
        
    except ImportError:
        print("⚠️  Pillow not available, skipping icon creation")

def build_executable():
    """Build the executable using PyInstaller"""
    print("🔨 Building executable with PyInstaller...")
    
    try:
        result = subprocess.run([
            'pyinstaller',
            '--clean',
            '--noconfirm',
            'voiceflow.spec'
        ], check=True, capture_output=True, text=True)
        
        print("✅ Executable built successfully")
        print(f"📁 Output: {os.path.abspath('dist/VoiceFlow.exe')}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ PyInstaller failed: {e}")
        print("Error output:", e.stderr)
        return False

def build_installer():
    """Build installer using Inno Setup"""
    if os.name != 'nt':
        print("⚠️  Inno Setup only available on Windows, skipping installer")
        return True
    
    print("📦 Building installer with Inno Setup...")
    
    # Find Inno Setup
    inno_paths = [
        r"C:\Program Files (x86)\Inno Setup 6\iscc.exe",
        r"C:\Program Files\Inno Setup 6\iscc.exe"
    ]
    
    iscc_path = None
    for path in inno_paths:
        if os.path.exists(path):
            iscc_path = path
            break
    
    if not iscc_path:
        print("❌ Inno Setup not found")
        return False
    
    try:
        result = subprocess.run([
            iscc_path,
            'voiceflow_installer.iss'
        ], check=True, capture_output=True, text=True)
        
        print("✅ Installer built successfully")
        installer_files = list(Path('dist').glob('VoiceFlow-Setup-*.exe'))
        if installer_files:
            print(f"📁 Installer: {installer_files[0].absolute()}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Inno Setup failed: {e}")
        return False

def main():
    """Main build process"""
    print("🚀 VoiceFlow Windows Executable Builder")
    print("=" * 40)
    
    # Check requirements
    if not check_requirements():
        return 1
    
    # Create necessary files
    create_simple_icon()
    create_spec_file()
    create_inno_setup_script()
    
    # Build executable
    if not build_executable():
        return 1
    
    # Build installer
    if not build_installer():
        print("⚠️  Installer build failed, but executable is available")
    
    print("\n✅ Build complete!")
    print("\nFiles created:")
    print("  📄 dist/VoiceFlow.exe - Standalone executable")
    if os.path.exists('dist'):
        installer_files = list(Path('dist').glob('VoiceFlow-Setup-*.exe'))
        if installer_files:
            print(f"  📦 {installer_files[0]} - Windows installer")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())