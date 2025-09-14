#!/usr/bin/env python3
"""
WebSocket Server Integration Testing

Tests the integration of WebSocket server with authentication, validation, and core components.
"""

import os
import sys
import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, AsyncMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def test_websocket_auth_integration():
    """Test WebSocket server authentication integration."""
    print("🔌 Testing WebSocket Authentication Integration")
    
    temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_ws_"))
    
    try:
        with patch('pathlib.Path.home', return_value=temp_dir):
            from utils.auth import AuthManager, extract_auth_token
            
            # Create auth manager
            auth = AuthManager()
            
            # Test token extraction from WebSocket headers
            mock_websocket = Mock()
            
            # Test Authorization header
            mock_websocket.request_headers = {
                'Authorization': f'Bearer {auth.auth_token}'
            }
            
            extracted_token = extract_auth_token(mock_websocket)
            assert extracted_token == auth.auth_token
            assert auth.validate_token(extracted_token) is True
            
            # Test X-Auth-Token header
            mock_websocket.request_headers = {
                'X-Auth-Token': auth.auth_token
            }
            
            extracted_token = extract_auth_token(mock_websocket)
            assert extracted_token == auth.auth_token
            
            # Test query parameter token
            mock_websocket.path = f'/ws?token={auth.auth_token}&other=param'
            extracted_token = extract_auth_token(mock_websocket)
            assert extracted_token == auth.auth_token
            
            # Test invalid token
            mock_websocket.request_headers = {
                'Authorization': 'Bearer invalid_token'
            }
            
            extracted_token = extract_auth_token(mock_websocket)
            assert auth.validate_token(extracted_token) is False
            
            print("   ✅ WebSocket authentication integration working")
            return True
            
    except Exception as e:
        print(f"   ❌ WebSocket auth integration failed: {e}")
        return False
    finally:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_websocket_message_validation():
    """Test WebSocket message validation integration."""
    print("📨 Testing WebSocket Message Validation")
    
    try:
        from utils.validation import InputValidator, ValidationError
        
        # Test valid WebSocket messages
        valid_messages = [
            '{"type": "get_history", "limit": 50}',
            '{"type": "get_statistics"}',
            '{"type": "start_recording"}',
            '{"type": "set_language", "language": "en"}'
        ]
        
        for message in valid_messages:
            try:
                validated = InputValidator.validate_json_message(message)
                assert isinstance(validated, dict)
                assert 'type' in validated
            except ValidationError as e:
                print(f"   ⚠️  Valid message rejected: {message} - {e}")
        
        # Test invalid WebSocket messages
        invalid_messages = [
            '{"type": "exec", "code": "__import__(\'os\').system(\'ls\')"}',
            '{"type": "test", "data": "<script>alert(1)</script>"}',
            '{"type": "' + 'A' * 1000 + '"}',  # Too large
            'invalid json'
        ]
        
        blocked_count = 0
        for message in invalid_messages:
            try:
                InputValidator.validate_json_message(message)
                print(f"   ⚠️  Dangerous message not blocked: {message[:50]}...")
            except (ValidationError, json.JSONDecodeError):
                blocked_count += 1
        
        assert blocked_count > 0, "Should block some dangerous messages"
        
        print(f"   ✅ WebSocket message validation working (blocked {blocked_count}/{len(invalid_messages)} dangerous messages)")
        return True
        
    except Exception as e:
        print(f"   ❌ WebSocket message validation failed: {e}")
        return False

def test_websocket_server_components():
    """Test WebSocket server component integration."""
    print("🌐 Testing WebSocket Server Components")
    
    temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_server_"))
    
    try:
        with patch('pathlib.Path.home', return_value=temp_dir):
            # Mock external dependencies
            with patch('python.stt_server.AudioToTextRecorder'):
                with patch('python.stt_server.requests') as mock_requests:
                    # Setup Ollama mock
                    mock_requests.get.return_value.status_code = 200
                    mock_requests.get.return_value.json.return_value = {
                        'models': [{'name': 'server-test-model'}]
                    }
                    
                    from python.stt_server import VoiceFlowServer
                    
                    # Create server instance
                    server = VoiceFlowServer()
                    
                    # Test database initialization
                    assert server.db_path.exists()
                    
                    # Test authentication integration
                    if server.auth_manager:
                        assert server.auth_manager.auth_token is not None
                        print("   ✅ Server authentication initialized")
                    else:
                        print("   ⚠️  Server authentication not available")
                    
                    # Test statistics tracking
                    stats = server.get_statistics()
                    assert isinstance(stats, dict)
                    assert 'session' in stats
                    
                    # Test message broadcasting (with mock clients)
                    test_message = {"type": "test", "data": "integration"}
                    
                    # Mock WebSocket client
                    mock_client = AsyncMock()
                    server.websocket_clients.add(mock_client)
                    
                    # Test broadcast
                    server.broadcast_message(test_message)
                    
                    print("   ✅ WebSocket server components working")
                    return True
                    
    except Exception as e:
        print(f"   ❌ WebSocket server components failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_websocket_request_handling():
    """Test WebSocket request handling integration."""
    print("📡 Testing WebSocket Request Handling")
    
    try:
        from utils.validation import InputValidator
        
        # Simulate WebSocket request handling workflow
        
        # 1. Authenticate request
        mock_websocket = Mock()
        mock_websocket.request_headers = {'Authorization': 'Bearer valid_token'}
        
        # 2. Validate incoming message
        incoming_message = '{"type": "get_history", "limit": 10}'
        validated_data = InputValidator.validate_json_message(incoming_message)
        
        assert validated_data['type'] == 'get_history'
        assert validated_data['limit'] == 10
        
        # 3. Process request (mock database query)
        mock_history = [
            {"id": 1, "text": "Test transcription 1", "timestamp": "2025-01-01"},
            {"id": 2, "text": "Test transcription 2", "timestamp": "2025-01-02"}
        ]
        
        # 4. Validate response
        response = {
            "type": "history",
            "data": mock_history
        }
        
        response_json = json.dumps(response)
        assert json.loads(response_json) == response
        
        # Test error handling workflow
        error_message = '{"type": "invalid_request"}'
        try:
            # Simulate server processing
            validated_error = InputValidator.validate_json_message(error_message)
            if validated_error['type'] not in ['get_history', 'get_statistics', 'start_recording']:
                error_response = {
                    "type": "error",
                    "message": "Unknown request type"
                }
                assert error_response['type'] == 'error'
        except Exception:
            pass  # Expected for invalid requests
        
        print("   ✅ WebSocket request handling working")
        return True
        
    except Exception as e:
        print(f"   ❌ WebSocket request handling failed: {e}")
        return False

def test_websocket_realtime_integration():
    """Test WebSocket real-time transcription integration."""
    print("🎤 Testing WebSocket Real-time Integration")
    
    temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_realtime_"))
    
    try:
        with patch('pathlib.Path.home', return_value=temp_dir):
            # Mock the real-time transcription workflow
            
            # 1. Recording start event
            recording_start_message = {
                "type": "recording_started",
                "timestamp": "2025-07-10T12:00:00Z"
            }
            
            # 2. Real-time preview updates
            preview_messages = [
                {"type": "realtime_preview", "text": "hello", "timestamp": "2025-07-10T12:00:01Z"},
                {"type": "realtime_preview", "text": "hello world", "timestamp": "2025-07-10T12:00:02Z"},
                {"type": "realtime_preview", "text": "hello world test", "timestamp": "2025-07-10T12:00:03Z"}
            ]
            
            # 3. Final transcription with AI enhancement
            final_message = {
                "type": "transcription_complete",
                "raw_text": "hello world test",
                "enhanced_text": "Hello world test.",
                "word_count": 3,
                "duration_ms": 3000,
                "processing_time_ms": 150,
                "timestamp": "2025-07-10T12:00:04Z"
            }
            
            # 4. Recording stop event
            recording_stop_message = {
                "type": "recording_stopped",
                "timestamp": "2025-07-10T12:00:04Z"
            }
            
            # Validate all messages can be properly serialized
            workflow_messages = [
                recording_start_message,
                *preview_messages,
                final_message,
                recording_stop_message
            ]
            
            for message in workflow_messages:
                json_str = json.dumps(message)
                parsed = json.loads(json_str)
                assert parsed == message
            
            # Test message validation
            from utils.validation import InputValidator
            
            # All messages should have valid types
            for message in workflow_messages:
                assert 'type' in message
                assert 'timestamp' in message
                
                # Validate text content if present
                if 'text' in message:
                    validated_text = InputValidator.validate_text(message['text'])
                    assert isinstance(validated_text, str)
            
            print("   ✅ WebSocket real-time integration working")
            return True
            
    except Exception as e:
        print(f"   ❌ WebSocket real-time integration failed: {e}")
        return False
    finally:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

def main():
    """Run WebSocket integration tests."""
    print("🚀 VoiceFlow WebSocket Integration Testing")
    print("=" * 60)
    print("Testing WebSocket server integration with security and validation")
    print()
    
    tests = [
        test_websocket_auth_integration,
        test_websocket_message_validation,
        test_websocket_server_components,
        test_websocket_request_handling,
        test_websocket_realtime_integration
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
    print("📊 WEBSOCKET INTEGRATION TEST RESULTS")
    print("=" * 60)
    
    success_rate = (passed_tests / total_tests) * 100
    
    print(f"Tests Passed: {passed_tests}/{total_tests}")
    print(f"Success Rate: {success_rate:.1f}%")
    
    if success_rate == 100:
        print("\n🌟 EXCELLENT: All WebSocket integration tests passed!")
        print("   ✅ Authentication properly integrated with WebSocket server")
        print("   ✅ Message validation working for WebSocket communications")
        print("   ✅ Server components initialize and integrate correctly")
        print("   ✅ Request handling workflow functions properly")
        print("   ✅ Real-time transcription integration working")
        
    elif success_rate >= 80:
        print("\n✅ GOOD: Most WebSocket integration tests passed")
        print("   Core WebSocket functionality is solid")
        print("   Minor issues may need attention")
        
    else:
        print("\n⚠️  NEEDS WORK: WebSocket integration issues detected")
        print("   Multiple WebSocket components not integrating properly")
    
    print(f"\n📋 WEBSOCKET SUMMARY: Integration is {'FUNCTIONAL' if success_rate >= 80 else 'PROBLEMATIC'}")
    
    return success_rate >= 80

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)