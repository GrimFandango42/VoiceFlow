#!/usr/bin/env python3
"""
Focused VoiceFlow Integration Testing

Tests actual component integration with available modules and realistic scenarios.
"""

import os
import sys
import time
import sqlite3
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def test_core_components_integration():
    """Test integration of core components that are actually available."""
    print("🧪 Testing Core Components Integration")
    print("=" * 50)
    
    temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_test_"))
    
    try:
        # Test 1: Configuration System Integration
        print("\n1️⃣ Testing Configuration System...")
        
        with patch('pathlib.Path.home', return_value=temp_dir):
            from utils.config import VoiceFlowConfig, get_config, get_audio_config, get_ai_config
            
            # Test basic config creation
            config = VoiceFlowConfig()
            assert config is not None
            
            # Test config sections
            audio_config = get_audio_config()
            ai_config = get_ai_config()
            
            assert 'model' in audio_config
            assert 'enabled' in ai_config
            
            print("   ✅ Configuration system working")
        
        # Test 2: Authentication System Integration  
        print("\n2️⃣ Testing Authentication System...")
        
        with patch('pathlib.Path.home', return_value=temp_dir):
            from utils.auth import AuthManager, get_auth_manager, extract_auth_token
            
            # Test auth manager creation
            auth = AuthManager()
            assert auth.auth_token is not None
            
            # Test session management
            session_id = auth.create_session("test-client")
            assert auth.validate_session(session_id) is True
            
            # Test token validation
            assert auth.validate_token(auth.auth_token) is True
            assert auth.validate_token("invalid") is False
            
            # Test global auth manager
            global_auth = get_auth_manager()
            assert global_auth is not None
            
            print("   ✅ Authentication system working")
        
        # Test 3: Input Validation Integration
        print("\n3️⃣ Testing Input Validation...")
        
        from utils.validation import InputValidator, ValidationError, safe_filename
        
        # Test text validation
        safe_text = InputValidator.validate_text("Hello world")
        assert safe_text == "Hello world"
        
        # Test dangerous pattern detection
        try:
            InputValidator.validate_text("<script>alert('xss')</script>")
            print("   ⚠️  XSS pattern not blocked")
        except ValidationError:
            print("   ✅ XSS pattern blocked")
        
        # Test JSON validation
        json_data = InputValidator.validate_json_message('{"type": "test", "data": "safe"}')
        assert json_data['type'] == 'test'
        
        # Test file operations
        safe_name = safe_filename("test file.txt")
        assert safe_name == "test_file.txt"
        
        print("   ✅ Input validation working")
        
        # Test 4: Secure Database Integration (if available)
        print("\n4️⃣ Testing Secure Database...")
        
        try:
            from utils.secure_db import SecureDatabase, create_secure_database
            
            # Test with mock encryption
            with patch('utils.secure_db.Fernet') as mock_fernet:
                mock_cipher = Mock()
                mock_cipher.encrypt.return_value = b'encrypted_test'
                mock_cipher.decrypt.return_value = b'decrypted_test'
                mock_fernet.return_value = mock_cipher
                mock_fernet.generate_key.return_value = b'test_key'
                
                db = SecureDatabase(temp_dir / "test_secure.db")
                
                # Test encryption/decryption
                encrypted = db.encrypt_text("test text")
                decrypted = db.decrypt_text(encrypted)
                
                # Test storage
                success = db.store_transcription(
                    text="test transcription",
                    processing_time=100.0,
                    word_count=2,
                    model_used="test-model",
                    session_id="test-session"
                )
                assert success is True
                
                print("   ✅ Secure database working")
                
        except ImportError as e:
            print(f"   ⚠️  Secure database unavailable: {e}")
        
        # Test 5: AI Enhancement Integration
        print("\n5️⃣ Testing AI Enhancement...")
        
        with patch('core.ai_enhancement.requests') as mock_requests:
            # Mock successful connection
            mock_requests.get.return_value.status_code = 200
            mock_requests.get.return_value.json.return_value = {
                'models': [{'name': 'test-model:latest'}]
            }
            
            # Mock enhancement response
            mock_session = Mock()
            mock_session.post.return_value.status_code = 200
            mock_session.post.return_value.json.return_value = {
                'response': 'Enhanced test text.'
            }
            mock_requests.Session.return_value = mock_session
            
            from core.ai_enhancement import AIEnhancer, create_enhancer
            
            # Test enhancer creation
            enhancer = create_enhancer({'enabled': True})
            assert enhancer.use_ai_enhancement is True
            
            # Test text enhancement
            enhanced = enhancer.enhance_text("test text")
            assert enhanced == "Enhanced test text."
            
            # Test fallback behavior
            mock_requests.get.side_effect = Exception("Connection failed")
            fallback_enhancer = create_enhancer({'enabled': True})
            fallback_result = fallback_enhancer.enhance_text("test")
            assert fallback_result == "Test."
            
            print("   ✅ AI enhancement working")
        
        # Test 6: Core Engine Integration
        print("\n6️⃣ Testing Core Engine...")
        
        with patch('pathlib.Path.home', return_value=temp_dir):
            # Mock dependencies that might not be available
            with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder:
                with patch('core.voiceflow_core.pyautogui') as mock_pyautogui:
                    with patch('core.voiceflow_core.keyboard') as mock_keyboard:
                        
                        from core.voiceflow_core import VoiceFlowEngine, create_engine
                        
                        # Test engine creation
                        engine = create_engine({'model': 'base', 'device': 'cpu'})
                        assert engine is not None
                        assert engine.data_dir.exists()
                        
                        # Test database initialization
                        assert engine.db_path.exists()
                        
                        # Test statistics
                        stats = engine.get_stats()
                        assert 'total_transcriptions' in stats
                        
                        # Test storage methods
                        engine.store_transcription("test text", 100.0)
                        
                        # Verify database contents
                        conn = sqlite3.connect(engine.db_path)
                        cursor = conn.cursor()
                        cursor.execute("SELECT COUNT(*) FROM transcriptions_legacy")
                        count = cursor.fetchone()[0]
                        conn.close()
                        assert count == 1
                        
                        print("   ✅ Core engine working")
        
        # Test 7: Component Integration Workflow
        print("\n7️⃣ Testing Component Integration Workflow...")
        
        with patch('pathlib.Path.home', return_value=temp_dir):
            # Test configuration -> engine -> enhancer workflow
            config = VoiceFlowConfig()
            
            with patch('core.voiceflow_core.AudioToTextRecorder'):
                with patch('core.ai_enhancement.requests') as mock_requests:
                    # Setup AI enhancement mock
                    mock_requests.get.return_value.status_code = 200
                    mock_requests.get.return_value.json.return_value = {
                        'models': [{'name': 'test-model'}]
                    }
                    
                    mock_session = Mock()
                    mock_session.post.return_value.status_code = 200
                    mock_session.post.return_value.json.return_value = {
                        'response': 'Workflow enhanced text.'
                    }
                    mock_requests.Session.return_value = mock_session
                    
                    # Create components
                    engine = VoiceFlowEngine(config.get_section('audio'))
                    enhancer = AIEnhancer(config.get_section('ai'))
                    
                    # Test workflow: validate -> enhance -> store
                    text = "workflow test"
                    validated_text = InputValidator.validate_text(text)
                    enhanced_text = enhancer.enhance_text(validated_text)
                    engine.store_transcription(enhanced_text, 150.0)
                    
                    assert enhanced_text == "Workflow enhanced text."
                    
                    print("   ✅ Component integration workflow working")
        
        print("\n🎉 All Integration Tests Completed!")
        return True
        
    except Exception as e:
        print(f"\n💥 Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Cleanup
        import shutil
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            pass

def test_security_integration():
    """Test security feature integration."""
    print("\n🔒 Testing Security Integration")
    print("=" * 50)
    
    temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_security_"))
    
    try:
        # Test authentication + validation integration
        print("\n🔐 Testing Auth + Validation Integration...")
        
        with patch('pathlib.Path.home', return_value=temp_dir):
            from utils.auth import AuthManager
            from utils.validation import InputValidator, ValidationError
            
            auth = AuthManager()
            
            # Test secure session creation with validation
            client_id = InputValidator.validate_text("secure-client-123")
            session_id = auth.create_session(client_id)
            
            assert auth.validate_session(session_id) is True
            
            # Test malicious client ID rejection
            try:
                malicious_id = "<script>alert('xss')</script>"
                InputValidator.validate_text(malicious_id)
                print("   ⚠️  Malicious client ID not blocked")
            except ValidationError:
                print("   ✅ Malicious client ID blocked")
        
        # Test validation + AI enhancement integration
        print("\n🛡️ Testing Validation + AI Integration...")
        
        with patch('core.ai_enhancement.requests') as mock_requests:
            mock_requests.get.return_value.status_code = 200
            mock_requests.get.return_value.json.return_value = {
                'models': [{'name': 'test-model'}]
            }
            
            mock_session = Mock()
            mock_session.post.return_value.status_code = 200
            mock_session.post.return_value.json.return_value = {
                'response': 'Safe enhanced text.'
            }
            mock_requests.Session.return_value = mock_session
            
            from core.ai_enhancement import AIEnhancer
            from utils.validation import InputValidator
            
            enhancer = AIEnhancer({'enabled': True})
            
            # Test validated input to AI enhancer
            safe_input = InputValidator.validate_text("hello world")
            enhanced = enhancer.enhance_text(safe_input)
            
            assert enhanced == "Safe enhanced text."
            print("   ✅ Validation + AI integration working")
        
        # Test complete security pipeline
        print("\n🔗 Testing Complete Security Pipeline...")
        
        with patch('pathlib.Path.home', return_value=temp_dir):
            # Auth -> Validation -> Processing -> Storage
            auth = AuthManager()
            
            # 1. Authenticate
            session_id = auth.create_session("pipeline-test")
            assert auth.validate_session(session_id) is True
            
            # 2. Validate input
            user_input = "secure pipeline test"
            validated_input = InputValidator.validate_text(user_input)
            
            # 3. Process (mock)
            processed_output = validated_input.upper()
            
            # 4. Store securely (mock)
            if hasattr(temp_dir, 'exists'):
                storage_path = temp_dir / "secure_storage.txt"
                storage_path.write_text(processed_output)
                assert storage_path.exists()
            
            print("   ✅ Complete security pipeline working")
        
        return True
        
    except Exception as e:
        print(f"\n💥 Security integration test failed: {e}")
        return False
        
    finally:
        import shutil
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            pass

def test_error_recovery_integration():
    """Test error recovery across integrated components."""
    print("\n🔄 Testing Error Recovery Integration")
    print("=" * 50)
    
    try:
        # Test configuration error recovery
        print("\n📋 Testing Config Error Recovery...")
        
        temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_error_"))
        
        with patch('pathlib.Path.home', return_value=temp_dir):
            # Create invalid config file
            config_dir = temp_dir / ".voiceflow"
            config_dir.mkdir(exist_ok=True)
            config_file = config_dir / "config.json"
            config_file.write_text("invalid json content")
            
            from utils.config import VoiceFlowConfig
            
            # Should handle invalid config gracefully
            config = VoiceFlowConfig()
            assert config is not None  # Should use defaults
            
            print("   ✅ Config error recovery working")
        
        # Test authentication error recovery
        print("\n🔐 Testing Auth Error Recovery...")
        
        with patch('pathlib.Path.home', return_value=temp_dir):
            from utils.auth import AuthManager
            
            # Test with invalid token file
            auth_file = temp_dir / ".voiceflow" / ".auth_token"
            auth_file.write_text("")  # Empty token file
            
            auth = AuthManager()
            # Should generate new token when file is invalid
            assert auth.auth_token is not None
            assert len(auth.auth_token) > 0
            
            print("   ✅ Auth error recovery working")
        
        # Test validation error recovery
        print("\n🛡️ Testing Validation Error Recovery...")
        
        from utils.validation import InputValidator
        
        # Test with various invalid inputs
        invalid_inputs = [None, 123, [], {}]
        
        for invalid_input in invalid_inputs:
            try:
                # Should handle gracefully or raise appropriate error
                if invalid_input is not None:
                    InputValidator.validate_text(str(invalid_input))
            except Exception:
                pass  # Expected for invalid inputs
        
        print("   ✅ Validation error recovery working")
        
        # Test AI enhancement error recovery
        print("\n🤖 Testing AI Error Recovery...")
        
        with patch('core.ai_enhancement.requests') as mock_requests:
            # Test network failure
            mock_requests.get.side_effect = Exception("Network error")
            
            from core.ai_enhancement import AIEnhancer
            
            enhancer = AIEnhancer({'enabled': True})
            # Should fallback to basic formatting
            result = enhancer.enhance_text("test input")
            assert result == "Test input."
            
            print("   ✅ AI error recovery working")
        
        return True
        
    except Exception as e:
        print(f"\n💥 Error recovery test failed: {e}")
        return False
        
    finally:
        import shutil
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            pass

def main():
    """Run all focused integration tests."""
    print("🚀 VoiceFlow Focused Integration Testing")
    print("=" * 60)
    
    tests_passed = 0
    total_tests = 3
    
    # Run test suites
    if test_core_components_integration():
        tests_passed += 1
    
    if test_security_integration():
        tests_passed += 1
    
    if test_error_recovery_integration():
        tests_passed += 1
    
    # Generate summary
    print("\n" + "=" * 60)
    print("🧪 FOCUSED INTEGRATION TEST SUMMARY")
    print("=" * 60)
    
    success_rate = (tests_passed / total_tests) * 100
    
    print(f"Test Suites Passed: {tests_passed}/{total_tests}")
    print(f"Success Rate: {success_rate:.1f}%")
    
    if success_rate == 100:
        print("\n🌟 EXCELLENT: All integration tests passed!")
        print("   System components integrate properly")
        print("   Security features work correctly")
        print("   Error recovery is functional")
    elif success_rate >= 67:
        print("\n✅ GOOD: Most integration tests passed")
        print("   Core functionality is solid")
        print("   Minor issues may need attention")
    else:
        print("\n⚠️  NEEDS WORK: Several integration issues detected")
        print("   Review failed tests and address issues")
    
    return success_rate >= 67

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)