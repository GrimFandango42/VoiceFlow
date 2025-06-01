// Frontend test suite for VoiceFlow
const fs = require('fs');
const path = require('path');

class FrontendTester {
    constructor() {
        this.results = {
            tests_passed: 0,
            tests_failed: 0,
            details: []
        };
    }

    log(testName, passed, details = '') {
        if (passed) {
            this.results.tests_passed++;
            console.log(`[PASS] ${testName}`);
        } else {
            this.results.tests_failed++;
            console.log(`[FAIL] ${testName}: ${details}`);
        }
        
        this.results.details.push({
            test: testName,
            passed: passed,
            details: details,
            timestamp: Date.now()
        });
    }

    testBuildOutput() {
        // Check if frontend build exists
        const distPath = path.join(__dirname, 'dist');
        if (fs.existsSync(distPath)) {
            const files = fs.readdirSync(distPath);
            const hasIndex = files.includes('index.html');
            const hasAssets = files.includes('assets');
            
            if (hasIndex && hasAssets) {
                this.log('Frontend build output', true, `Found ${files.length} files`);
                return true;
            } else {
                this.log('Frontend build output', false, 'Missing index.html or assets');
                return false;
            }
        } else {
            this.log('Frontend build output', false, 'dist directory not found');
            return false;
        }
    }

    testPackageJson() {
        try {
            const packagePath = path.join(__dirname, 'package.json');
            const packageData = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
            
            const requiredDeps = ['@tauri-apps/api', 'react', 'react-dom'];
            const missingDeps = requiredDeps.filter(dep => 
                !packageData.dependencies || !packageData.dependencies[dep]
            );
            
            if (missingDeps.length === 0) {
                this.log('Package dependencies', true);
                return true;
            } else {
                this.log('Package dependencies', false, `Missing: ${missingDeps.join(', ')}`);
                return false;
            }
        } catch (error) {
            this.log('Package dependencies', false, error.message);
            return false;
        }
    }

    testSourceFiles() {
        const srcPath = path.join(__dirname, 'src');
        const requiredFiles = [
            'App.jsx',
            'App.css',
            'main.jsx',
            'index.css',
            'components/RecordingIndicator.jsx',
            'components/TranscriptionHistory.jsx',
            'components/Statistics.jsx',
            'components/Settings.jsx'
        ];
        
        const missingFiles = requiredFiles.filter(file => 
            !fs.existsSync(path.join(srcPath, file))
        );
        
        if (missingFiles.length === 0) {
            this.log('Source files', true, `All ${requiredFiles.length} files present`);
            return true;
        } else {
            this.log('Source files', false, `Missing: ${missingFiles.join(', ')}`);
            return false;
        }
    }

    testTauriConfig() {
        try {
            const configPath = path.join(__dirname, 'src-tauri', 'tauri.conf.json');
            const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
            
            const checks = {
                'has app name': config.productName === 'VoiceFlow',
                'has window config': config.app && config.app.windows,
                'has build config': config.build,
                'has bundle config': config.bundle
            };
            
            const failedChecks = Object.entries(checks)
                .filter(([_, passed]) => !passed)
                .map(([check, _]) => check);
            
            if (failedChecks.length === 0) {
                this.log('Tauri configuration', true);
                return true;
            } else {
                this.log('Tauri configuration', false, `Failed checks: ${failedChecks.join(', ')}`);
                return false;
            }
        } catch (error) {
            this.log('Tauri configuration', false, error.message);
            return false;
        }
    }

    testElectronSetup() {
        const electronPath = path.join(__dirname, 'electron');
        
        if (!fs.existsSync(electronPath)) {
            this.log('Electron setup', false, 'Electron directory not found');
            return false;
        }
        
        const hasMainJs = fs.existsSync(path.join(electronPath, 'main.js'));
        const hasPackageJson = fs.existsSync(path.join(electronPath, 'package.json'));
        const hasNodeModules = fs.existsSync(path.join(electronPath, 'node_modules'));
        
        if (hasMainJs && hasPackageJson && hasNodeModules) {
            this.log('Electron setup', true);
            return true;
        } else {
            const missing = [];
            if (!hasMainJs) missing.push('main.js');
            if (!hasPackageJson) missing.push('package.json');
            if (!hasNodeModules) missing.push('node_modules');
            
            this.log('Electron setup', false, `Missing: ${missing.join(', ')}`);
            return false;
        }
    }

    testBuildScripts() {
        const scripts = [
            'BUILD_FIX.bat',
            'BUILD_SIMPLE.bat',
            'BUILD_SOLUTIONS.bat',
            'CREATE_ELECTRON_APP.bat',
            'DIAGNOSE.bat',
            'START_ELECTRON.bat',
            'START_VOICEFLOW.bat'
        ];
        
        const missingScripts = scripts.filter(script => 
            !fs.existsSync(path.join(__dirname, script))
        );
        
        if (missingScripts.length === 0) {
            this.log('Build scripts', true, `All ${scripts.length} scripts present`);
            return true;
        } else {
            this.log('Build scripts', false, `Missing: ${missingScripts.join(', ')}`);
            return false;
        }
    }

    runAllTests() {
        console.log('==================================================');
        console.log('VoiceFlow Frontend Test Suite');
        console.log('==================================================');
        console.log();
        
        this.testBuildOutput();
        this.testPackageJson();
        this.testSourceFiles();
        this.testTauriConfig();
        this.testElectronSetup();
        this.testBuildScripts();
        
        console.log();
        console.log('==================================================');
        console.log(`Tests Passed: ${this.results.tests_passed}`);
        console.log(`Tests Failed: ${this.results.tests_failed}`);
        console.log('==================================================');
        
        // Save results
        fs.writeFileSync(
            path.join(__dirname, 'frontend_test_results.json'),
            JSON.stringify(this.results, null, 2)
        );
        console.log('\nDetailed results saved to: frontend_test_results.json');
        
        return this.results.tests_failed === 0;
    }
}

// Run tests
const tester = new FrontendTester();
const success = tester.runAllTests();
process.exit(success ? 0 : 1);
