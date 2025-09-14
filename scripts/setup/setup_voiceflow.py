#!/usr/bin/env python3
"""
VoiceFlow Smart Installer & Environment Setup
==============================================
Automatic dependency checking, installation, and environment validation
"""

import sys
import os
import subprocess
import platform
import shutil
import time
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import importlib.util

@dataclass
class DependencyCheck:
    """Dependency validation result"""
    name: str
    required: bool
    installed: bool
    version: str = ""
    install_command: str = ""
    error_message: str = ""

@dataclass
class SystemRequirement:
    """System requirement definition"""
    name: str
    check_function: str
    required: bool = True
    fix_command: str = ""
    description: str = ""

class VoiceFlowInstaller:
    """Smart installer with comprehensive environment validation"""

    def __init__(self):
        self.project_root = Path(__file__).parent
        self.requirements_file = self.project_root / "requirements_windows.txt"
        self.config_file = self.project_root / "installer_config.json"

        # Installation results tracking
        self.dependency_results: List[DependencyCheck] = []
        self.system_results: List[Tuple[str, bool, str]] = []
        self.issues_found: List[str] = []
        self.fixes_applied: List[str] = []

    def check_python_version(self) -> Tuple[bool, str]:
        """Check Python version compatibility"""
        version = sys.version_info
        min_version = (3, 9)

        if version >= min_version:
            return True, f"Python {version.major}.{version.minor}.{version.micro} (OK)"
        else:
            return False, f"Python {version.major}.{version.minor} is too old (need 3.9+)"

    def check_pip_available(self) -> Tuple[bool, str]:
        """Check if pip is available and working"""
        try:
            import pip
            result = subprocess.run([sys.executable, "-m", "pip", "--version"],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return True, f"pip available: {result.stdout.strip()}"
            else:
                return False, f"pip error: {result.stderr.strip()}"
        except Exception as e:
            return False, f"pip not available: {str(e)}"

    def check_virtual_environment(self) -> Tuple[bool, str]:
        """Check if running in virtual environment (recommended)"""
        in_venv = hasattr(sys, 'real_prefix') or (
            hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
        )

        if in_venv:
            return True, f"Virtual environment: {sys.prefix}"
        else:
            return False, "Not in virtual environment (recommended for isolation)"

    def check_windows_specific(self) -> Tuple[bool, str]:
        """Check Windows-specific requirements"""
        if platform.system() != "Windows":
            return True, "Not Windows (Windows checks skipped)"

        # Check for Windows-specific packages
        issues = []

        # Check pywin32
        try:
            import win32api
        except ImportError:
            issues.append("pywin32 not installed")

        # Check audio devices
        try:
            import sounddevice as sd
            devices = sd.query_devices()
            if len(devices) == 0:
                issues.append("No audio devices found")
        except:
            # Sounddevice not required for core functionality
            pass

        if issues:
            return False, f"Windows issues: {', '.join(issues)}"
        else:
            return True, "Windows environment OK"

    def check_gpu_availability(self) -> Tuple[bool, str]:
        """Check GPU availability for potential acceleration"""
        try:
            # Check NVIDIA GPU
            result = subprocess.run(["nvidia-smi"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                gpu_line = [line for line in lines if 'NVIDIA' in line and 'Driver Version' in line]
                if gpu_line:
                    return True, f"NVIDIA GPU available: {gpu_line[0].split('|')[1].strip()}"
        except:
            pass

        # Check for other indicators
        try:
            import torch
            if torch.cuda.is_available():
                return True, f"CUDA available: {torch.cuda.get_device_name(0)}"
        except:
            pass

        return False, "No GPU acceleration detected (CPU mode will be used)"

    def check_audio_system(self) -> Tuple[bool, str]:
        """Check audio system functionality"""
        try:
            # Try basic audio imports
            import sounddevice as sd
            import numpy as np

            # Get default input device
            default_device = sd.default.device[0]
            if default_device is None:
                return False, "No default audio input device"

            # Get device info
            device_info = sd.query_devices(default_device)
            max_channels = device_info.get('max_input_channels', 0)

            if max_channels == 0:
                return False, f"Default device '{device_info['name']}' has no input channels"

            return True, f"Audio OK: {device_info['name']} ({max_channels} ch, {device_info['default_samplerate']}Hz)"

        except Exception as e:
            return False, f"Audio system error: {str(e)[:100]}"

    def parse_requirements_file(self) -> List[str]:
        """Parse requirements.txt file"""
        if not self.requirements_file.exists():
            print(f"Warning: {self.requirements_file} not found")
            return []

        requirements = []
        with open(self.requirements_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Handle conditional requirements like pywin32>=306; sys_platform == "win32"
                    if ';' in line:
                        package, condition = line.split(';', 1)
                        package = package.strip()
                        condition = condition.strip()
                        # Simple condition evaluation for Windows
                        if 'sys_platform == "win32"' in condition and platform.system() == "Windows":
                            requirements.append(package)
                        elif 'sys_platform == "win32"' not in condition:
                            requirements.append(package)
                    else:
                        requirements.append(line)

        return requirements

    def check_dependency(self, requirement: str) -> DependencyCheck:
        """Check if a single dependency is installed"""
        # Parse package name from requirement (handle version specifiers)
        package_name = requirement.split('>=')[0].split('==')[0].split('<=')[0].split('>')[0].split('<')[0]

        try:
            # Try to import the package
            if package_name == 'RealtimeSTT':
                # Special case for RealtimeSTT
                import RealtimeSTT
                version = getattr(RealtimeSTT, '__version__', 'unknown')
            elif package_name == 'PIL':
                # Pillow is imported as PIL
                from PIL import Image
                version = getattr(Image, 'VERSION', 'unknown')
            elif package_name == 'pywin32':
                import win32api
                version = "installed"
            else:
                # Generic import
                module = importlib.import_module(package_name)
                version = getattr(module, '__version__', 'unknown')

            return DependencyCheck(
                name=package_name,
                required=True,
                installed=True,
                version=version
            )

        except ImportError as e:
            return DependencyCheck(
                name=package_name,
                required=True,
                installed=False,
                install_command=f"pip install {requirement}",
                error_message=str(e)
            )
        except Exception as e:
            return DependencyCheck(
                name=package_name,
                required=True,
                installed=False,
                install_command=f"pip install {requirement}",
                error_message=f"Import error: {str(e)}"
            )

    def install_missing_dependencies(self) -> bool:
        """Install all missing dependencies"""
        missing_deps = [dep for dep in self.dependency_results if not dep.installed]

        if not missing_deps:
            print("All dependencies are already installed.")
            return True

        print(f"\nInstalling {len(missing_deps)} missing dependencies...")

        for dep in missing_deps:
            print(f"  Installing {dep.name}...")

            try:
                # Use pip to install
                result = subprocess.run([
                    sys.executable, "-m", "pip", "install", dep.install_command.replace("pip install ", "")
                ], capture_output=True, text=True, timeout=60)

                if result.returncode == 0:
                    print(f"    [OK] {dep.name} installed successfully")
                    self.fixes_applied.append(f"Installed {dep.name}")
                    dep.installed = True
                else:
                    print(f"    [FAIL] Failed to install {dep.name}: {result.stderr.strip()}")
                    self.issues_found.append(f"Failed to install {dep.name}")

            except subprocess.TimeoutExpired:
                print(f"    [TIMEOUT] Installation of {dep.name} timed out")
                self.issues_found.append(f"Installation timeout: {dep.name}")
            except Exception as e:
                print(f"    [ERROR] Error installing {dep.name}: {str(e)}")
                self.issues_found.append(f"Installation error: {dep.name}")

        # Re-check dependencies after installation
        print("\nRe-validating installed dependencies...")
        requirements = self.parse_requirements_file()
        self.dependency_results = []

        for req in requirements:
            check_result = self.check_dependency(req)
            self.dependency_results.append(check_result)

        still_missing = [dep for dep in self.dependency_results if not dep.installed]

        if still_missing:
            print(f"Warning: {len(still_missing)} dependencies still missing after installation.")
            return False
        else:
            print("All dependencies successfully installed!")
            return True

    def run_system_checks(self) -> bool:
        """Run comprehensive system environment checks"""
        print("Running system environment checks...")

        checks = [
            ("Python Version", self.check_python_version),
            ("Pip Available", self.check_pip_available),
            ("Virtual Environment", self.check_virtual_environment),
            ("Windows Specific", self.check_windows_specific),
            ("GPU Availability", self.check_gpu_availability),
            ("Audio System", self.check_audio_system)
        ]

        all_critical_passed = True

        for check_name, check_func in checks:
            try:
                passed, message = check_func()
                self.system_results.append((check_name, passed, message))

                status = "[OK]" if passed else "[FAIL]"
                print(f"  {status} {check_name:<20}: {message}")

                # Critical checks that must pass
                if check_name in ["Python Version", "Pip Available"] and not passed:
                    all_critical_passed = False
                    self.issues_found.append(f"Critical: {check_name} failed")

                if not passed and check_name not in ["Virtual Environment", "GPU Availability"]:
                    self.issues_found.append(f"{check_name}: {message}")

            except Exception as e:
                print(f"  [FAIL] {check_name:<20}: Check failed - {str(e)}")
                self.system_results.append((check_name, False, f"Check failed: {str(e)}"))
                self.issues_found.append(f"{check_name}: Check failed")

        return all_critical_passed

    def run_dependency_checks(self) -> bool:
        """Check all required dependencies"""
        print("\nChecking dependencies...")

        requirements = self.parse_requirements_file()
        if not requirements:
            print("No requirements found to check.")
            return True

        print(f"Found {len(requirements)} dependencies to check:")

        for req in requirements:
            check_result = self.check_dependency(req)
            self.dependency_results.append(check_result)

            status = "[OK]" if check_result.installed else "[MISSING]"
            version_info = f"({check_result.version})" if check_result.version and check_result.installed else ""
            print(f"  {status} {check_result.name:<20} {version_info}")

            if not check_result.installed:
                print(f"      Missing: {check_result.error_message}")

        missing_count = len([dep for dep in self.dependency_results if not dep.installed])

        if missing_count == 0:
            print(f"\n[OK] All {len(requirements)} dependencies are installed!")
            return True
        else:
            print(f"\n[MISSING] {missing_count} dependencies need to be installed.")
            return False

    def run_post_install_validation(self) -> bool:
        """Run validation tests after installation"""
        print("\nRunning post-installation validation...")

        validation_tests = [
            ("Import Test", self.validate_core_imports),
            ("Configuration", self.validate_config_loading),
            ("Audio Pipeline", self.validate_audio_pipeline)
        ]

        all_passed = True

        for test_name, test_func in validation_tests:
            try:
                passed, message = test_func()
                status = "[OK]" if passed else "[FAIL]"
                print(f"  {status} {test_name:<15}: {message}")

                if not passed:
                    all_passed = False
                    self.issues_found.append(f"Validation failed: {test_name}")

            except Exception as e:
                print(f"  [ERROR] {test_name:<15}: Exception - {str(e)}")
                all_passed = False
                self.issues_found.append(f"Validation error: {test_name}")

        return all_passed

    def validate_core_imports(self) -> Tuple[bool, str]:
        """Validate core VoiceFlow imports work"""
        try:
            from localflow.config import Config
            from localflow.audio_enhanced import EnhancedAudioRecorder
            from localflow.asr_buffer_safe import BufferSafeWhisperASR
            return True, "Core modules import successfully"
        except ImportError as e:
            return False, f"Import failed: {str(e)[:50]}"
        except Exception as e:
            return False, f"Unexpected error: {str(e)[:50]}"

    def validate_config_loading(self) -> Tuple[bool, str]:
        """Validate configuration system works"""
        try:
            from localflow.config import Config
            cfg = Config()
            if cfg.sample_rate > 0 and cfg.channels > 0:
                return True, f"Config loaded: {cfg.sample_rate}Hz, {cfg.channels}ch"
            else:
                return False, "Invalid configuration values"
        except Exception as e:
            return False, f"Config error: {str(e)[:50]}"

    def validate_audio_pipeline(self) -> Tuple[bool, str]:
        """Validate audio pipeline can be initialized"""
        try:
            from localflow.config import Config
            from localflow.audio_enhanced import EnhancedAudioRecorder

            cfg = Config()
            # Quick initialization test (no actual recording)
            recorder = EnhancedAudioRecorder(cfg)

            return True, "Audio pipeline initialized successfully"
        except Exception as e:
            return False, f"Audio pipeline error: {str(e)[:50]}"

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive installation report"""
        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "system": {
                "platform": platform.platform(),
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "working_directory": str(self.project_root)
            },
            "system_checks": [
                {"name": name, "passed": passed, "message": message}
                for name, passed, message in self.system_results
            ],
            "dependencies": [
                {
                    "name": dep.name,
                    "installed": dep.installed,
                    "version": dep.version,
                    "error": dep.error_message
                }
                for dep in self.dependency_results
            ],
            "issues_found": self.issues_found,
            "fixes_applied": self.fixes_applied,
            "summary": {
                "total_dependencies": len(self.dependency_results),
                "installed_dependencies": len([d for d in self.dependency_results if d.installed]),
                "issues_count": len(self.issues_found),
                "fixes_count": len(self.fixes_applied)
            }
        }

    def run_complete_setup(self, auto_install: bool = True) -> bool:
        """Run complete VoiceFlow setup and installation"""
        print("=" * 80)
        print("VoiceFlow Smart Installer & Environment Setup")
        print("=" * 80)
        print(f"Project: {self.project_root}")
        print(f"Python: {sys.executable}")
        print(f"Platform: {platform.platform()}")
        print()

        # Step 1: System environment checks
        if not self.run_system_checks():
            print("\n[CRITICAL] System checks failed. Cannot continue.")
            return False

        # Step 2: Dependency checks
        deps_ok = self.run_dependency_checks()

        # Step 3: Install missing dependencies if requested
        if not deps_ok and auto_install:
            if not self.install_missing_dependencies():
                print("\n[ERROR] Dependency installation failed.")
                return False

        # Step 4: Post-installation validation
        if not self.run_post_install_validation():
            print("\n[WARNING] Post-installation validation had issues.")

        # Step 5: Generate and save report
        report = self.generate_report()

        report_file = self.project_root / "installation_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        # Final summary
        print("\n" + "=" * 80)
        print("INSTALLATION SUMMARY")
        print("=" * 80)

        summary = report['summary']
        print(f"Dependencies: {summary['installed_dependencies']}/{summary['total_dependencies']} installed")
        print(f"Issues Found: {summary['issues_count']}")
        print(f"Fixes Applied: {summary['fixes_count']}")

        if summary['issues_count'] == 0:
            print("\n[SUCCESS] VoiceFlow is ready to use!")
            print("\nNext steps:")
            print("  - Run: python quick_smoke_test.py")
            print("  - Launch: LAUNCH_TRAY.bat")
        else:
            print(f"\n[ISSUES] {summary['issues_count']} problems found")
            print("\nIssues:")
            for issue in self.issues_found[:5]:  # Show first 5 issues
                print(f"  - {issue}")
            if len(self.issues_found) > 5:
                print(f"  ... and {len(self.issues_found) - 5} more")

        print(f"\nDetailed report saved to: {report_file}")
        print("=" * 80)

        return summary['issues_count'] == 0

def main():
    """Entry point for VoiceFlow installer"""
    import argparse

    parser = argparse.ArgumentParser(description="VoiceFlow Smart Installer")
    parser.add_argument("--no-install", action="store_true",
                       help="Check only, don't install missing packages")
    parser.add_argument("--report", help="Save detailed report to custom location")

    args = parser.parse_args()

    installer = VoiceFlowInstaller()
    success = installer.run_complete_setup(auto_install=not args.no_install)

    # Save custom report if requested
    if args.report:
        report = installer.generate_report()
        with open(args.report, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to: {args.report}")

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()