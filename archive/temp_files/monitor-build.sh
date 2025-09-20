#!/bin/bash
# Continuous build monitor for VoiceFlow

REPO="GrimFandango42/VoiceFlow"
CHECK_INTERVAL=30
MAX_ATTEMPTS=120  # 1 hour max

echo "🚀 Starting continuous build monitoring for VoiceFlow..."
echo "📊 Will check every $CHECK_INTERVAL seconds until build succeeds"
echo ""

attempt=0
build_success=false

while [ $attempt -lt $MAX_ATTEMPTS ] && [ "$build_success" = false ]; do
    attempt=$((attempt + 1))
    echo "=== Check #$attempt at $(date) ==="
    
    # Check if we can access GitHub
    if ! command -v curl &> /dev/null; then
        echo "❌ curl not available, trying alternative method..."
    fi
    
    # Try to get workflow status
    echo "🔍 Checking GitHub Actions status..."
    
    # Method 1: Try GitHub API
    API_RESPONSE=$(curl -s -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/$REPO/actions/runs?per_page=5" 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$API_RESPONSE" ]; then
        # Parse latest run
        LATEST_STATUS=$(echo "$API_RESPONSE" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
        LATEST_CONCLUSION=$(echo "$API_RESPONSE" | grep -o '"conclusion":"[^"]*"' | head -1 | cut -d'"' -f4)
        LATEST_NAME=$(echo "$API_RESPONSE" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)
        
        echo "📋 Latest workflow: $LATEST_NAME"
        echo "📊 Status: $LATEST_STATUS"
        echo "🎯 Conclusion: $LATEST_CONCLUSION"
        
        # Check if build completed successfully
        if [ "$LATEST_STATUS" = "completed" ] && [ "$LATEST_CONCLUSION" = "success" ]; then
            echo "✅ BUILD SUCCESSFUL!"
            build_success=true
            
            # Try to get artifact info
            echo ""
            echo "📦 Checking for artifacts..."
            RUN_ID=$(echo "$API_RESPONSE" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)
            
            if [ -n "$RUN_ID" ]; then
                ARTIFACTS=$(curl -s -H "Accept: application/vnd.github.v3+json" \
                    "https://api.github.com/repos/$REPO/actions/runs/$RUN_ID/artifacts" 2>/dev/null)
                
                if [ $? -eq 0 ]; then
                    echo "$ARTIFACTS" | grep -o '"name":"[^"]*"' | cut -d'"' -f4 | while read artifact; do
                        echo "  📁 $artifact"
                    done
                fi
                
                echo ""
                echo "🎉 Executables are ready!"
                echo "📥 Download from: https://github.com/$REPO/releases"
                echo "🔗 Or visit: https://github.com/$REPO/actions/runs/$RUN_ID"
            fi
            
        elif [ "$LATEST_STATUS" = "in_progress" ] || [ "$LATEST_STATUS" = "queued" ]; then
            echo "⏳ Build is still running..."
        elif [ "$LATEST_STATUS" = "completed" ] && [ "$LATEST_CONCLUSION" = "failure" ]; then
            echo "❌ Build failed! Checking errors..."
            
            # Get run ID for logs
            RUN_ID=$(echo "$API_RESPONSE" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)
            echo "📋 Check logs at: https://github.com/$REPO/actions/runs/$RUN_ID"
            echo ""
            echo "🔧 Common fixes:"
            echo "  - Check missing dependencies in requirements files"
            echo "  - Verify all source files exist"
            echo "  - Check for syntax errors in Python files"
        fi
    else
        echo "⚠️  Could not fetch API data, trying web scraping..."
        
        # Fallback: Try to scrape the Actions page
        WEB_CONTENT=$(curl -s "https://github.com/$REPO/actions" 2>/dev/null)
        
        if echo "$WEB_CONTENT" | grep -q "v3.1.1"; then
            echo "📌 Found v3.1.1 build in Actions"
            
            if echo "$WEB_CONTENT" | grep -q "success"; then
                echo "✅ Build appears successful!"
                build_success=true
            elif echo "$WEB_CONTENT" | grep -q "failure"; then
                echo "❌ Build appears to have failed"
            else
                echo "⏳ Build status unclear, still checking..."
            fi
        fi
    fi
    
    echo ""
    
    # If not successful, wait and try again
    if [ "$build_success" = false ]; then
        echo "⏰ Waiting $CHECK_INTERVAL seconds before next check..."
        sleep $CHECK_INTERVAL
    fi
done

if [ "$build_success" = true ]; then
    echo ""
    echo "🎊 BUILD MONITORING COMPLETE - SUCCESS!"
    echo "📦 VoiceFlow executables are ready for download"
    echo ""
    echo "Next steps:"
    echo "1. Visit: https://github.com/$REPO/releases"
    echo "2. Download the latest release assets"
    echo "3. Windows: VoiceFlow.exe or VoiceFlow-Setup-*.exe"
    echo "4. Unix: voiceflow-unix.tar.gz"
else
    echo ""
    echo "⏱️ Monitoring timeout reached after $attempt attempts"
    echo "Please check manually: https://github.com/$REPO/actions"
fi