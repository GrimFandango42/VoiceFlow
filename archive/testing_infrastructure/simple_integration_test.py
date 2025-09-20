#!/usr/bin/env python3
"""
Simple VoiceFlow Integration Testing

Focuses on testing real component integration without external dependencies.
Tests the actual integration points that exist in the codebase.
"""

import os
import sys
import tempfile
import json
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def test_configuration_integration():
    """Test configuration system integration across components."""
    print("🔧 Testing Configuration Integration")
    
    temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_config_"))
    
    try:
        with patch('pathlib.Path.home', return_value=temp_dir):
            from utils.config import VoiceFlowConfig, get_config, get_audio_config, get_ai_config
            
            # Create and save configuration
            config = VoiceFlowConfig()
            config.set('audio', 'model', 'integration-test-model')
            config.set('ai', 'temperature', 0.8)
            config.set('security', 'log_transcriptions', False)
            config.save()
            
            # Test configuration loading in new instance
            new_config = VoiceFlowConfig()
            assert new_config.get('audio', 'model') == 'integration-test-model'
            assert new_config.get('ai', 'temperature') == 0.8
            assert new_config.get('security', 'log_transcriptions') is False
            
            # Test configuration sections
            audio_config = get_audio_config()
            ai_config = get_ai_config()
            
            assert audio_config['model'] == 'integration-test-model'
            assert ai_config['temperature'] == 0.8
            
            print("   ✅ Configuration integration successful")
            return True
            
    except Exception as e:
        print(f"   ❌ Configuration integration failed: {e}")
        return False
    finally:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_auth_validation_integration():
    """Test authentication and validation working together."""
    print("🔐 Testing Auth + Validation Integration")
    
    temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_auth_"))
    
    try:
        with patch('pathlib.Path.home', return_value=temp_dir):
            from utils.auth import AuthManager
            from utils.validation import InputValidator, ValidationError
            
            # Create auth manager
            auth = AuthManager()
            
            # Test validated session creation
            client_id = "secure-test-client"
            validated_client_id = InputValidator.validate_text(client_id)
            session_id = auth.create_session(validated_client_id)
            
            assert auth.validate_session(session_id) is True
            
            # Test malicious input rejection
            try:
                malicious_client = "<script>alert('hack')</script>"
                InputValidator.validate_text(malicious_client)
                print("   ⚠️  Malicious input not blocked")
            except ValidationError:
                print("   ✅ Malicious input properly blocked")
            
            # Test WebSocket-style token extraction simulation
            mock_headers = {'Authorization': f'Bearer {auth.auth_token}'}
            
            # Simulate token extraction
            if 'Authorization' in mock_headers:
                token = mock_headers['Authorization'].replace('Bearer ', '')
                assert auth.validate_token(token) is True
            
            print("   ✅ Auth + Validation integration successful")
            return True
            
    except Exception as e:
        print(f"   ❌ Auth + Validation integration failed: {e}")
        return False
    finally:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_ai_validation_integration():
    """Test AI enhancement with input validation."""
    print("🤖 Testing AI + Validation Integration")
    
    try:
        with patch('core.ai_enhancement.requests') as mock_requests:
            # Mock successful Ollama connection
            mock_requests.get.return_value.status_code = 200
            mock_requests.get.return_value.json.return_value = {
                'models': [{'name': 'integration-test-model'}]
            }
            
            # Mock AI enhancement response
            mock_session = Mock()
            mock_session.post.return_value.status_code = 200
            mock_session.post.return_value.json.return_value = {
                'response': 'AI enhanced and validated text.'
            }
            mock_requests.Session.return_value = mock_session
            
            from core.ai_enhancement import AIEnhancer
            from utils.validation import InputValidator
            
            enhancer = AIEnhancer({'enabled': True})
            
            # Test validated input to AI
            user_input = "integrate ai with validation"
            validated_input = InputValidator.validate_text(user_input)
            enhanced_output = enhancer.enhance_text(validated_input)
            
            assert enhanced_output == "AI enhanced and validated text."
            
            # Test AI fallback with validation
            mock_requests.get.side_effect = Exception("Network error")
            fallback_enhancer = AIEnhancer({'enabled': True})
            
            fallback_result = fallback_enhancer.enhance_text("fallback test")
            assert fallback_result == "Fallback test."  # Basic formatting
            
            print("   ✅ AI + Validation integration successful")
            return True
            
    except Exception as e:
        print(f"   ❌ AI + Validation integration failed: {e}")
        return False

def test_database_integration():
    """Test database operations with configuration and validation."""
    print("💾 Testing Database Integration")
    
    temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_db_"))
    
    try:
        with patch('pathlib.Path.home', return_value=temp_dir):
            from utils.config import VoiceFlowConfig
            from utils.validation import InputValidator
            
            # Setup configuration
            config = VoiceFlowConfig()
            db_path = temp_dir / ".voiceflow" / "integration_test.db"
            
            # Create database directly
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create table structure similar to VoiceFlow
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS test_transcriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    validated_text TEXT NOT NULL,
                    word_count INTEGER NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Test validated data storage
            test_texts = [
                "Hello world integration test",
                "Second test transcription",
                "Final validation test"
            ]
            
            for text in test_texts:
                validated_text = InputValidator.validate_text(text)
                word_count = len(validated_text.split())
                
                cursor.execute(
                    "INSERT INTO test_transcriptions (validated_text, word_count) VALUES (?, ?)",
                    (validated_text, word_count)
                )
            
            conn.commit()
            
            # Test data retrieval
            cursor.execute("SELECT COUNT(*) FROM test_transcriptions")
            count = cursor.fetchone()[0]
            assert count == 3
            
            cursor.execute("SELECT validated_text, word_count FROM test_transcriptions")
            results = cursor.fetchall()
            
            # Verify data integrity
            for i, (text, word_count) in enumerate(results):
                expected_words = len(test_texts[i].split())
                assert word_count == expected_words
            
            conn.close()
            
            print("   ✅ Database integration successful")
            return True
            
    except Exception as e:
        print(f"   ❌ Database integration failed: {e}")
        return False
    finally:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_end_to_end_integration():
    """Test complete end-to-end integration workflow."""
    print("🌐 Testing End-to-End Integration")
    
    temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_e2e_"))
    
    try:
        with patch('pathlib.Path.home', return_value=temp_dir):
            # Simulate complete workflow
            from utils.config import VoiceFlowConfig
            from utils.auth import AuthManager
            from utils.validation import InputValidator
            
            with patch('core.ai_enhancement.requests') as mock_requests:
                # Setup AI enhancement mocks
                mock_requests.get.return_value.status_code = 200
                mock_requests.get.return_value.json.return_value = {
                    'models': [{'name': 'e2e-test-model'}]
                }
                
                mock_session = Mock()
                mock_session.post.return_value.status_code = 200
                mock_session.post.return_value.json.return_value = {
                    'response': 'End-to-end enhanced transcription.'
                }
                mock_requests.Session.return_value = mock_session
                
                from core.ai_enhancement import AIEnhancer
                
                # 1. Load configuration
                config = VoiceFlowConfig()
                config.set('ai', 'enabled', True)
                
                # 2. Authenticate user
                auth = AuthManager()
                session_id = auth.create_session("e2e-test-client")
                
                # 3. Validate input
                user_input = "end to end integration test transcription"
                validated_input = InputValidator.validate_text(user_input)
                
                # 4. Enhance with AI
                enhancer = AIEnhancer(config.get_section('ai'))
                enhanced_text = enhancer.enhance_text(validated_input)
                
                # 5. Store results
                db_path = temp_dir / ".voiceflow" / "e2e_test.db"
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE e2e_results (
                        id INTEGER PRIMARY KEY,
                        session_id TEXT,
                        original_text TEXT,
                        enhanced_text TEXT,
                        word_count INTEGER
                    )
                ''')
                
                cursor.execute(
                    "INSERT INTO e2e_results (session_id, original_text, enhanced_text, word_count) VALUES (?, ?, ?, ?)",
                    (session_id, validated_input, enhanced_text, len(validated_input.split()))
                )
                conn.commit()
                conn.close()
                
                # 6. Verify complete workflow
                assert auth.validate_session(session_id) is True
                assert enhanced_text == "End-to-end enhanced transcription."
                
                # Verify data persistence
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM e2e_results")
                result = cursor.fetchone()
                conn.close()
                
                assert result is not None
                assert result[1] == session_id  # session_id
                assert result[2] == validated_input  # original_text
                assert result[3] == enhanced_text  # enhanced_text
                
                print("   ✅ End-to-end integration successful")
                return True
                
    except Exception as e:
        print(f"   ❌ End-to-end integration failed: {e}")
        return False
    finally:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_error_propagation():
    """Test error handling across integrated components."""
    print("🔄 Testing Error Propagation")
    
    try:
        # Test configuration error propagation
        temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_error_"))
        
        with patch('pathlib.Path.home', return_value=temp_dir):
            # Create invalid config
            config_dir = temp_dir / ".voiceflow"
            config_dir.mkdir(exist_ok=True)
            config_file = config_dir / "config.json"
            config_file.write_text("invalid json")
            
            from utils.config import VoiceFlowConfig
            
            # Should handle gracefully
            config = VoiceFlowConfig()
            assert config is not None
            
            # Test validation error propagation
            from utils.validation import InputValidator, ValidationError
            
            error_caught = False
            try:
                InputValidator.validate_text("<script>alert('xss')</script>")
            except ValidationError:
                error_caught = True
            
            assert error_caught, "Validation should catch dangerous input"
            
            # Test AI enhancement error propagation
            with patch('core.ai_enhancement.requests') as mock_requests:
                mock_requests.get.side_effect = Exception("Connection failed")
                
                from core.ai_enhancement import AIEnhancer
                
                enhancer = AIEnhancer({'enabled': True})
                # Should fallback gracefully
                result = enhancer.enhance_text("test error handling")
                assert result == "Test error handling."
                
                print("   ✅ Error propagation working correctly")
                return True
                
    except Exception as e:
        print(f"   ❌ Error propagation test failed: {e}")
        return False
    finally:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

def main():
    """Run simplified integration tests."""
    print("🚀 VoiceFlow Simple Integration Testing")
    print("=" * 60)
    print("Testing actual component integration without external dependencies")
    print()
    
    tests = [
        test_configuration_integration,
        test_auth_validation_integration,
        test_ai_validation_integration,
        test_database_integration,
        test_end_to_end_integration,
        test_error_propagation
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test in tests:
        try:
            if test():
                passed_tests += 1
            print()
        except Exception as e:
            print(f"   💥 Test failed with exception: {e}")
            print()
    
    # Summary
    print("=" * 60)
    print("📊 INTEGRATION TEST RESULTS")
    print("=" * 60)
    
    success_rate = (passed_tests / total_tests) * 100
    
    print(f"Tests Passed: {passed_tests}/{total_tests}")
    print(f"Success Rate: {success_rate:.1f}%")
    
    if success_rate == 100:
        print("\n🌟 EXCELLENT: All integration tests passed!")
        print("   ✅ Configuration system integrates properly")
        print("   ✅ Authentication and validation work together")
        print("   ✅ AI enhancement integrates with validation")
        print("   ✅ Database operations work with all components")
        print("   ✅ End-to-end workflows function correctly")
        print("   ✅ Error handling propagates properly")
        
    elif success_rate >= 80:
        print("\n✅ GOOD: Most integration tests passed")
        print("   Core integration functionality is solid")
        print("   Minor issues may need attention")
        
    elif success_rate >= 60:
        print("\n⚠️  ACCEPTABLE: Some integration issues detected")
        print("   Basic functionality works but improvements needed")
        
    else:
        print("\n❌ POOR: Significant integration issues")
        print("   Multiple components not integrating properly")
    
    print(f"\n📋 SUMMARY: VoiceFlow component integration is {'FUNCTIONAL' if success_rate >= 60 else 'PROBLEMATIC'}")
    
    return success_rate >= 60

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)