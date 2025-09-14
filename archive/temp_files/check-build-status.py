#!/usr/bin/env python3
"""Continuous build monitor for VoiceFlow GitHub Actions"""

import time
import json
import urllib.request
import urllib.error
from datetime import datetime

REPO = "GrimFandango42/VoiceFlow"
CHECK_INTERVAL = 30  # seconds
MAX_ATTEMPTS = 120  # 1 hour max

def check_github_actions():
    """Check GitHub Actions status via API"""
    api_url = f"https://api.github.com/repos/{REPO}/actions/runs?per_page=5"
    
    try:
        with urllib.request.urlopen(api_url) as response:
            data = json.loads(response.read())
            
        if not data.get('workflow_runs'):
            return None, None, None, None
            
        latest_run = data['workflow_runs'][0]
        
        return (
            latest_run.get('name', 'Unknown'),
            latest_run.get('status', 'Unknown'),
            latest_run.get('conclusion', None),
            latest_run.get('id')
        )
    except Exception as e:
        print(f"⚠️  API Error: {e}")
        return None, None, None, None

def check_artifacts(run_id):
    """Check for build artifacts"""
    if not run_id:
        return []
        
    api_url = f"https://api.github.com/repos/{REPO}/actions/runs/{run_id}/artifacts"
    
    try:
        with urllib.request.urlopen(api_url) as response:
            data = json.loads(response.read())
            
        artifacts = []
        for artifact in data.get('artifacts', []):
            name = artifact.get('name', 'Unknown')
            size = artifact.get('size_in_bytes', 0)
            artifacts.append(f"  📁 {name} ({size:,} bytes)")
            
        return artifacts
    except:
        return []

def monitor_build():
    """Main monitoring loop"""
    print("🚀 Starting continuous build monitoring for VoiceFlow...")
    print(f"📊 Will check every {CHECK_INTERVAL} seconds until build succeeds")
    print("")
    
    attempt = 0
    build_success = False
    
    while attempt < MAX_ATTEMPTS and not build_success:
        attempt += 1
        print(f"=== Check #{attempt} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
        
        name, status, conclusion, run_id = check_github_actions()
        
        if name:
            print(f"📋 Latest workflow: {name}")
            print(f"📊 Status: {status}")
            if conclusion:
                print(f"🎯 Conclusion: {conclusion}")
            
            # Check build status
            if status == "completed" and conclusion == "success":
                print("✅ BUILD SUCCESSFUL!")
                build_success = True
                
                # Check artifacts
                print("\n📦 Checking for artifacts...")
                artifacts = check_artifacts(run_id)
                
                if artifacts:
                    for artifact in artifacts:
                        print(artifact)
                else:
                    print("  No artifacts found yet...")
                
                print("\n🎉 Executables are ready!")
                print(f"📥 Download from: https://github.com/{REPO}/releases")
                print(f"🔗 Or visit: https://github.com/{REPO}/actions/runs/{run_id}")
                
            elif status in ["in_progress", "queued"]:
                print("⏳ Build is still running...")
                
            elif status == "completed" and conclusion == "failure":
                print("❌ Build failed! Checking errors...")
                print(f"📋 Check logs at: https://github.com/{REPO}/actions/runs/{run_id}")
                print("\n🔧 Common fixes:")
                print("  - Check missing dependencies in requirements files")
                print("  - Verify all source files exist")
                print("  - Check for syntax errors in Python files")
                print("  - Ensure GitHub Actions workflow is valid")
                
                # Continue monitoring in case a new build is triggered
                print("\n⏰ Will continue monitoring for new builds...")
        else:
            print("⚠️  Could not fetch build status, will retry...")
        
        print("")
        
        if not build_success:
            print(f"⏰ Waiting {CHECK_INTERVAL} seconds before next check...")
            time.sleep(CHECK_INTERVAL)
    
    if build_success:
        print("\n🎊 BUILD MONITORING COMPLETE - SUCCESS!")
        print("📦 VoiceFlow executables are ready for download")
        print("\nNext steps:")
        print(f"1. Visit: https://github.com/{REPO}/releases")
        print("2. Download the latest release assets")
        print("3. Windows: VoiceFlow.exe or VoiceFlow-Setup-*.exe")
        print("4. Unix: voiceflow-unix.tar.gz")
    else:
        print(f"\n⏱️ Monitoring timeout reached after {attempt} attempts")
        print(f"Please check manually: https://github.com/{REPO}/actions")

if __name__ == "__main__":
    monitor_build()