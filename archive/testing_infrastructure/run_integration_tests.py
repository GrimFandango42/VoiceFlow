#!/usr/bin/env python3
"""
VoiceFlow Comprehensive Integration Testing Suite

This script performs comprehensive integration testing of VoiceFlow components,
focusing on security integration, data flow validation, and real-world scenarios.
"""

import os
import sys
import time
import sqlite3
import tempfile
import threading
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List, Tuple

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def create_test_environment():
    """Create isolated test environment."""
    temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_integration_"))
    print(f"[SETUP] Created test environment: {temp_dir}")
    return temp_dir

def cleanup_test_environment(temp_dir: Path):
    """Clean up test environment."""
    import shutil
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
        print(f"[CLEANUP] Removed test environment: {temp_dir}")
    except Exception as e:
        print(f"[WARNING] Failed to cleanup {temp_dir}: {e}")

class IntegrationTestSuite:
    """Comprehensive integration test suite for VoiceFlow."""
    
    def __init__(self):
        self.test_results = []
        self.temp_dir = None
        
    def log_result(self, test_name: str, status: str, details: str = ""):
        """Log test result."""
        result = {
            'test': test_name,
            'status': status,
            'details': details,
            'timestamp': time.time()
        }
        self.test_results.append(result)
        status_icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
        print(f"[{status_icon}] {test_name}: {status}")
        if details:
            print(f"    {details}")
    
    def setup(self):
        """Setup test environment."""
        self.temp_dir = create_test_environment()
        
    def teardown(self):
        """Teardown test environment."""
        if self.temp_dir:
            cleanup_test_environment(self.temp_dir)
    
    def test_core_engine_initialization(self):
        """Test core engine initialization with various configurations."""
        test_name = "Core Engine Initialization"
        
        try:
            with patch('pathlib.Path.home', return_value=self.temp_dir):
                # Test basic initialization
                from core.voiceflow_core import VoiceFlowEngine, create_engine
                
                # Test with minimal config
                engine = create_engine({'model': 'base', 'device': 'cpu'})
                assert engine is not None
                assert engine.data_dir.exists()
                assert engine.db_path.exists()
                
                # Test database initialization
                conn = sqlite3.connect(engine.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                conn.close()
                
                assert 'transcriptions' in tables or 'transcriptions_legacy' in tables
                
                # Test statistics tracking
                stats = engine.get_stats()
                assert isinstance(stats, dict)
                assert 'total_transcriptions' in stats
                
                self.log_result(test_name, "PASS", "Engine initialization successful")
                
        except Exception as e:
            self.log_result(test_name, "FAIL", f"Engine initialization failed: {e}")
    
    def test_secure_database_integration(self):
        """Test secure database integration."""
        test_name = "Secure Database Integration"
        
        try:
            # Test with mock encryption
            with patch('utils.secure_db.Fernet') as mock_fernet:
                mock_cipher = Mock()
                mock_cipher.encrypt.return_value = b'encrypted_test_data'
                mock_cipher.decrypt.return_value = b'Original test text'
                mock_fernet.return_value = mock_cipher
                mock_fernet.generate_key.return_value = b'test_encryption_key'
                
                from utils.secure_db import SecureDatabase
                
                # Create secure database
                db = SecureDatabase(self.temp_dir / "secure_test.db")
                
                # Test encryption/decryption
                original_text = "Test transcription for security"
                encrypted = db.encrypt_text(original_text)
                decrypted = db.decrypt_text(encrypted)
                
                assert decrypted == "Original test text"  # From mock
                
                # Test storage
                success = db.store_transcription(
                    text=original_text,
                    processing_time=150.0,
                    word_count=4,
                    model_used="test-model",
                    session_id="test-session"
                )
                assert success is True
                
                # Test retrieval
                history = db.get_transcription_history(limit=1)
                assert len(history) == 1
                assert history[0]['text'] == "Original test text"
                
                self.log_result(test_name, "PASS", "Secure database integration working")
                
        except ImportError:
            self.log_result(test_name, "SKIP", "Cryptography not available")
        except Exception as e:
            self.log_result(test_name, "FAIL", f"Secure database test failed: {e}")
    
    def test_authentication_workflow(self):
        """Test authentication workflow."""
        test_name = "Authentication Workflow"
        
        try:
            with patch('pathlib.Path.home', return_value=self.temp_dir):
                from utils.auth import AuthManager, extract_auth_token
                
                # Create auth manager
                auth = AuthManager()
                
                # Test token generation
                assert auth.auth_token is not None
                assert len(auth.auth_token) >= 32
                
                # Test token validation
                assert auth.validate_token(auth.auth_token) is True
                assert auth.validate_token("invalid_token") is False
                
                # Test session management
                client_id = "test-client-123"
                session_id = auth.create_session(client_id)
                
                assert auth.validate_session(session_id) is True
                assert session_id in auth.active_sessions
                
                # Test session expiry
                auth.session_timeout = 1  # 1 second for testing
                time.sleep(1.1)
                assert auth.validate_session(session_id) is False
                
                # Test WebSocket token extraction
                mock_ws = Mock()
                mock_ws.request_headers = {'Authorization': f'Bearer {auth.auth_token}'}
                
                extracted_token = extract_auth_token(mock_ws)
                assert extracted_token == auth.auth_token
                
                self.log_result(test_name, "PASS", "Authentication workflow functional")
                
        except Exception as e:
            self.log_result(test_name, "FAIL", f"Authentication test failed: {e}")
    
    def test_input_validation_security(self):
        """Test input validation for security."""
        test_name = "Input Validation Security"
        
        try:
            from utils.validation import InputValidator, ValidationError
            
            # Test safe inputs
            safe_texts = [
                "Hello world",
                "This is a normal transcription.",
                "Testing 123 with numbers and punctuation!"
            ]
            
            for text in safe_texts:
                validated = InputValidator.validate_text(text)
                assert isinstance(validated, str)
            
            # Test dangerous patterns
            dangerous_texts = [
                "<script>alert('xss')</script>",
                "'; DROP TABLE transcriptions; --",
                "__import__('os').system('rm -rf /')"
            ]
            
            blocked_count = 0
            for dangerous_text in dangerous_texts:
                try:
                    InputValidator.validate_text(dangerous_text)
                except ValidationError:
                    blocked_count += 1
            
            # At least some dangerous patterns should be blocked
            if blocked_count > 0:
                self.log_result(test_name, "PASS", f"Blocked {blocked_count}/{len(dangerous_texts)} dangerous patterns")
            else:
                self.log_result(test_name, "WARN", "No dangerous patterns blocked - validation may be insufficient")
            
            # Test JSON validation
            valid_json = '{"type": "test", "data": "safe content"}'
            result = InputValidator.validate_json_message(valid_json)
            assert isinstance(result, dict)
            assert result['type'] == 'test'
            
        except Exception as e:
            self.log_result(test_name, "FAIL", f"Input validation test failed: {e}")
    
    def test_ai_enhancement_integration(self):
        """Test AI enhancement integration."""
        test_name = "AI Enhancement Integration"
        
        try:
            with patch('core.ai_enhancement.requests') as mock_requests:
                # Mock successful Ollama connection
                mock_requests.get.return_value.status_code = 200
                mock_requests.get.return_value.json.return_value = {
                    'models': [{'name': 'llama3.3:latest'}]
                }
                
                # Mock AI enhancement response
                mock_session = Mock()
                mock_session.post.return_value.status_code = 200
                mock_session.post.return_value.json.return_value = {
                    'response': 'Enhanced: Hello, world!'
                }
                mock_requests.Session.return_value = mock_session
                
                from core.ai_enhancement import AIEnhancer, create_enhancer
                
                # Test enhancer creation
                enhancer = create_enhancer({'enabled': True})
                assert enhancer.use_ai_enhancement is True
                assert enhancer.ollama_url is not None
                
                # Test text enhancement
                original_text = "hello world"
                enhanced_text = enhancer.enhance_text(original_text)
                assert enhanced_text == "Enhanced: Hello, world!"
                
                # Test fallback when AI unavailable
                mock_requests.get.side_effect = Exception("Connection failed")
                fallback_enhancer = create_enhancer({'enabled': True})
                
                fallback_result = fallback_enhancer.enhance_text("test input")
                assert fallback_result == "Test input."  # Basic formatting
                
                self.log_result(test_name, "PASS", "AI enhancement integration working")
                
        except Exception as e:
            self.log_result(test_name, "FAIL", f"AI enhancement test failed: {e}")
    
    def test_configuration_system(self):
        """Test configuration system integration."""
        test_name = "Configuration System"
        
        try:
            with patch('pathlib.Path.home', return_value=self.temp_dir):
                from utils.config import VoiceFlowConfig, get_config
                
                # Test default configuration
                config = VoiceFlowConfig()
                assert config.get('audio', 'model') is not None
                assert config.get('ai', 'enabled') is not None
                
                # Test configuration file creation and loading
                config.set('test', 'value', 'integration_test')
                config.save()
                
                # Create new config instance to test loading
                new_config = VoiceFlowConfig()
                assert new_config.get('test', 'value') == 'integration_test'
                
                # Test environment variable integration
                test_env = {'VOICEFLOW_MODEL': 'test-model'}
                with patch.dict(os.environ, test_env):
                    env_config = VoiceFlowConfig()
                    assert env_config.get('audio', 'model') == 'test-model'
                
                self.log_result(test_name, "PASS", "Configuration system working")
                
        except Exception as e:
            self.log_result(test_name, "FAIL", f"Configuration test failed: {e}")
    
    def test_error_handling_integration(self):
        """Test error handling across components."""
        test_name = "Error Handling Integration"
        
        try:
            with patch('pathlib.Path.home', return_value=self.temp_dir):
                from core.voiceflow_core import create_engine
                from core.ai_enhancement import create_enhancer
                
                # Test engine with failing audio recorder
                with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
                    mock_recorder = Mock()
                    mock_recorder.text.side_effect = Exception("Audio device unavailable")
                    mock_recorder_class.return_value = mock_recorder
                    
                    engine = create_engine()
                    
                    # Should handle error gracefully
                    result = engine.process_speech()
                    assert result is None  # Should return None on error, not crash
                
                # Test AI enhancer with network failure
                with patch('core.ai_enhancement.requests') as mock_requests:
                    mock_requests.get.side_effect = Exception("Network unreachable")
                    
                    enhancer = create_enhancer()
                    
                    # Should fallback to basic formatting
                    result = enhancer.enhance_text("test input")
                    assert result == "Test input."
                    assert enhancer.use_ai_enhancement is False
                
                # Test database connection failure
                with patch('sqlite3.connect', side_effect=sqlite3.OperationalError("Database locked")):
                    engine = create_engine()
                    # Should not crash during initialization
                    assert engine is not None
                
                self.log_result(test_name, "PASS", "Error handling working correctly")
                
        except Exception as e:
            self.log_result(test_name, "FAIL", f"Error handling test failed: {e}")
    
    def test_performance_integration(self):
        """Test performance impact of integrated features."""
        test_name = "Performance Integration"
        
        try:
            # Test encryption performance
            with patch('utils.secure_db.Fernet') as mock_fernet:
                mock_cipher = Mock()
                mock_cipher.encrypt.return_value = b'encrypted_data'
                mock_cipher.decrypt.return_value = b'original_text'
                mock_fernet.return_value = mock_cipher
                mock_fernet.generate_key.return_value = b'test_key'
                
                from utils.secure_db import SecureDatabase
                
                db = SecureDatabase(self.temp_dir / "perf_test.db")
                
                # Test encryption speed
                start_time = time.perf_counter()
                for i in range(100):
                    db.encrypt_text(f"Test text {i}")
                encryption_time = time.perf_counter() - start_time
                
                avg_encryption_time = (encryption_time / 100) * 1000  # ms
                
                # Should be reasonably fast
                assert avg_encryption_time < 50  # Less than 50ms per operation
                
                # Test validation performance
                from utils.validation import InputValidator
                
                start_time = time.perf_counter()
                for i in range(100):
                    InputValidator.validate_text(f"Test validation text {i}")
                validation_time = time.perf_counter() - start_time
                
                avg_validation_time = (validation_time / 100) * 1000  # ms
                assert avg_validation_time < 10  # Less than 10ms per validation
                
                self.log_result(test_name, "PASS", 
                    f"Performance acceptable (encrypt: {avg_encryption_time:.1f}ms, validate: {avg_validation_time:.1f}ms)")
                
        except Exception as e:
            self.log_result(test_name, "FAIL", f"Performance test failed: {e}")
    
    def test_concurrent_operations(self):
        """Test concurrent operations across components."""
        test_name = "Concurrent Operations"
        
        try:
            with patch('pathlib.Path.home', return_value=self.temp_dir):
                from core.voiceflow_core import create_engine
                
                # Create multiple engine instances
                engines = []
                for i in range(3):
                    with patch('core.voiceflow_core.AudioToTextRecorder'):
                        engine = create_engine()
                        engines.append(engine)
                
                # Test concurrent database operations
                def store_transcriptions(engine, worker_id):
                    for i in range(5):
                        engine.store_transcription(f"Worker {worker_id} text {i}", 100)
                
                threads = []
                for i, engine in enumerate(engines):
                    thread = threading.Thread(target=store_transcriptions, args=(engine, i))
                    threads.append(thread)
                    thread.start()
                
                # Wait for all threads to complete
                for thread in threads:
                    thread.join()
                
                # Verify all data was stored
                conn = sqlite3.connect(engines[0].db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM transcriptions_legacy")
                count = cursor.fetchone()[0]
                conn.close()
                
                expected_count = 3 * 5  # 3 workers * 5 transcriptions each
                assert count == expected_count
                
                self.log_result(test_name, "PASS", f"Successfully handled {expected_count} concurrent operations")
                
        except Exception as e:
            self.log_result(test_name, "FAIL", f"Concurrent operations test failed: {e}")
    
    def test_end_to_end_workflow(self):
        """Test complete end-to-end workflow."""
        test_name = "End-to-End Workflow"
        
        try:
            with patch('pathlib.Path.home', return_value=self.temp_dir):
                with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
                    with patch('core.ai_enhancement.requests') as mock_requests:
                        with patch('pyautogui.typewrite') as mock_typewrite:
                            # Setup complete mock environment
                            mock_recorder = Mock()
                            mock_recorder.text.return_value = "hello world integration test"
                            mock_recorder_class.return_value = mock_recorder
                            
                            # Mock AI enhancement
                            mock_requests.get.return_value.status_code = 200
                            mock_requests.get.return_value.json.return_value = {
                                'models': [{'name': 'llama3.3:latest'}]
                            }
                            
                            mock_session = Mock()
                            mock_session.post.return_value.status_code = 200
                            mock_session.post.return_value.json.return_value = {
                                'response': 'Hello world integration test.'
                            }
                            mock_requests.Session.return_value = mock_session
                            
                            from core.voiceflow_core import create_engine
                            from core.ai_enhancement import create_enhancer
                            
                            # Create integrated components
                            engine = create_engine({'enable_ai_enhancement': True})
                            enhancer = create_enhancer({'enabled': True})
                            
                            # Execute complete workflow
                            # 1. Process speech
                            raw_text = engine.process_speech()
                            assert raw_text == "hello world integration test"
                            
                            # 2. Enhance text
                            enhanced_text = enhancer.enhance_text(raw_text)
                            assert enhanced_text == "Hello world integration test."
                            
                            # 3. Inject text
                            injection_result = engine.inject_text(enhanced_text)
                            assert injection_result is True
                            mock_typewrite.assert_called_once_with(enhanced_text)
                            
                            # 4. Verify database storage
                            conn = sqlite3.connect(engine.db_path)
                            cursor = conn.cursor()
                            cursor.execute("SELECT raw_text, word_count FROM transcriptions_legacy ORDER BY id DESC LIMIT 1")
                            result = cursor.fetchone()
                            conn.close()
                            
                            assert result is not None
                            assert result[0] == raw_text
                            assert result[1] == 4  # word count
                            
                            self.log_result(test_name, "PASS", "Complete workflow executed successfully")
            
        except Exception as e:
            self.log_result(test_name, "FAIL", f"End-to-end workflow test failed: {e}")
    
    def run_all_tests(self):
        """Run all integration tests."""
        print("🚀 Starting VoiceFlow Integration Testing Suite")
        print("=" * 60)
        
        self.setup()
        
        try:
            # Core component tests
            self.test_core_engine_initialization()
            self.test_secure_database_integration()
            self.test_authentication_workflow()
            self.test_input_validation_security()
            self.test_ai_enhancement_integration()
            self.test_configuration_system()
            
            # Integration tests
            self.test_error_handling_integration()
            self.test_performance_integration()
            self.test_concurrent_operations()
            self.test_end_to_end_workflow()
            
        finally:
            self.teardown()
        
        # Generate summary
        self.generate_summary()
    
    def generate_summary(self):
        """Generate test summary."""
        print("\n" + "=" * 60)
        print("🧪 INTEGRATION TEST SUMMARY")
        print("=" * 60)
        
        total_tests = len(self.test_results)
        passed = len([r for r in self.test_results if r['status'] == 'PASS'])
        failed = len([r for r in self.test_results if r['status'] == 'FAIL'])
        warned = len([r for r in self.test_results if r['status'] == 'WARN'])
        skipped = len([r for r in self.test_results if r['status'] == 'SKIP'])
        
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⚠️  Warnings: {warned}")
        print(f"⏭️  Skipped: {skipped}")
        
        success_rate = (passed / total_tests) * 100 if total_tests > 0 else 0
        print(f"\n🎯 Success Rate: {success_rate:.1f}%")
        
        if failed > 0:
            print("\n❌ FAILED TESTS:")
            for result in self.test_results:
                if result['status'] == 'FAIL':
                    print(f"  • {result['test']}: {result['details']}")
        
        if warned > 0:
            print("\n⚠️  WARNINGS:")
            for result in self.test_results:
                if result['status'] == 'WARN':
                    print(f"  • {result['test']}: {result['details']}")
        
        # Overall assessment
        if success_rate >= 90:
            print("\n🌟 EXCELLENT: System integration is highly robust")
        elif success_rate >= 80:
            print("\n✅ GOOD: System integration is solid with minor issues")
        elif success_rate >= 70:
            print("\n⚠️  ACCEPTABLE: System integration works but needs improvement")
        else:
            print("\n❌ POOR: System integration has significant issues")
        
        print("\n📊 Detailed results saved to test_results.json")
        
        # Save detailed results
        with open(self.temp_dir.parent / "integration_test_results.json", 'w') as f:
            json.dump(self.test_results, f, indent=2, default=str)

def main():
    """Main entry point for integration testing."""
    try:
        test_suite = IntegrationTestSuite()
        test_suite.run_all_tests()
    except KeyboardInterrupt:
        print("\n\n⚠️  Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n💥 Testing suite failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()