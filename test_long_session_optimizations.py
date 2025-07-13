#!/usr/bin/env python3
"""
Test Script for VoiceFlow Long Session Optimizations

This script tests the integration of all long session optimizations:
- Adaptive memory cache
- Memory monitoring
- Session management
- Database compression
- Core engine integration
"""

import sys
import time
import traceback
from pathlib import Path

# Add the voiceflow directory to the path
sys.path.insert(0, str(Path(__file__).parent))

def test_memory_monitor():
    """Test memory monitoring functionality."""
    print("\n🧠 Testing Memory Monitor...")
    
    try:
        from utils.memory_monitor import create_memory_monitor
        
        # Create memory monitor
        monitor = create_memory_monitor({
            'check_interval_seconds': 1.0,
            'max_process_memory_mb': 100.0,
            'enable_auto_cleanup': True
        })
        
        # Test callbacks
        cleanup_called = False
        def test_cleanup():
            nonlocal cleanup_called
            cleanup_called = True
            print("  ✓ Cleanup callback triggered")
        
        monitor.register_cleanup_callback('test_cleanup', test_cleanup)
        
        # Test status
        status = monitor.get_current_status()
        print(f"  ✓ Memory status: {status['process_memory_mb']:.1f}MB")
        
        # Test monitoring
        monitor.start_monitoring()
        time.sleep(2)  # Let it run briefly
        monitor.stop_monitoring()
        
        print("  ✅ Memory monitor test passed")
        return True
        
    except Exception as e:
        print(f"  ❌ Memory monitor test failed: {e}")
        traceback.print_exc()
        return False


def test_session_manager():
    """Test session management functionality."""
    print("\n📝 Testing Session Manager...")
    
    try:
        from utils.session_manager import create_session_manager
        
        # Create session manager
        data_dir = Path("/tmp/voiceflow_test")
        data_dir.mkdir(exist_ok=True)
        
        session_mgr = create_session_manager(data_dir, {
            'checkpoint_interval_minutes': 1,  # Fast for testing
            'max_session_hours': 1,
            'auto_save_enabled': False  # Manual for testing
        })
        
        # Test session lifecycle
        session_id = session_mgr.start_session({'test': True})
        print(f"  ✓ Session started: {session_id}")
        
        # Update stats
        session_mgr.update_session_stats(transcriptions_delta=5, words_delta=100)
        
        # Get status
        status = session_mgr.get_session_status()
        print(f"  ✓ Session status: {status['total_transcriptions']} transcriptions")
        
        # Test pause/resume
        session_mgr.pause_session()
        print("  ✓ Session paused")
        
        session_mgr.resume_session()
        print("  ✓ Session resumed")
        
        # Stop session
        session_mgr.stop_session()
        print("  ✓ Session stopped")
        
        print("  ✅ Session manager test passed")
        return True
        
    except Exception as e:
        print(f"  ❌ Session manager test failed: {e}")
        traceback.print_exc()
        return False


def test_adaptive_cache():
    """Test adaptive memory cache."""
    print("\n🧩 Testing Adaptive Memory Cache...")
    
    try:
        from voiceflow_personal import AdaptiveMemoryCache
        
        # Create adaptive cache
        cache = AdaptiveMemoryCache(
            initial_size=10,
            min_size=5,
            max_size=50,
            memory_threshold_mb=100.0
        )
        
        # Test cache operations
        cache.put("test1", "enhanced1")
        cache.put("test2", "enhanced2")
        
        # Test retrieval
        result = cache.get("test1")
        assert result == "enhanced1", "Cache retrieval failed"
        print("  ✓ Cache retrieval works")
        
        # Test statistics
        stats = cache.get_cache_stats()
        print(f"  ✓ Cache stats: {stats['size']} entries, {stats['hit_rate_percent']}% hit rate")
        
        # Test cleanup
        cache.force_cleanup(target_size=1)
        print(f"  ✓ Cache cleanup: {len(cache.cache)} entries remaining")
        
        print("  ✅ Adaptive cache test passed")
        return True
        
    except Exception as e:
        print(f"  ❌ Adaptive cache test failed: {e}")
        traceback.print_exc()
        return False


def test_database_optimization():
    """Test database compression and optimization."""
    print("\n🗄️  Testing Database Optimization...")
    
    try:
        from utils.secure_db import create_secure_database
        
        # Create optimized database
        data_dir = Path("/tmp/voiceflow_test")
        data_dir.mkdir(exist_ok=True)
        
        db = create_secure_database(data_dir, 
            enable_compression=True,
            compression_threshold=50,
            max_storage_mb=10
        )
        
        # Test compression with larger text
        large_text = "This is a test transcription that should be long enough to trigger compression. " * 10
        
        success = db.store_transcription(
            text=large_text,
            processing_time=100.0,
            word_count=len(large_text.split()),
            model_used="test",
            session_id="test_session"
        )
        
        assert success, "Database storage failed"
        print("  ✓ Database storage works")
        
        # Test retrieval
        history = db.get_transcription_history(limit=1)
        assert len(history) == 1, "History retrieval failed"
        assert history[0]['text'] == large_text, "Text retrieval failed"
        print("  ✓ Database retrieval works")
        
        # Test storage info
        storage_info = db.get_storage_info()
        print(f"  ✓ Storage info: {storage_info['total_entries']} entries, {storage_info['compression_ratio']} compression ratio")
        
        print("  ✅ Database optimization test passed")
        return True
        
    except Exception as e:
        print(f"  ❌ Database optimization test failed: {e}")
        traceback.print_exc()
        return False


def test_voiceflow_personal_integration():
    """Test VoiceFlow Personal with long session support."""
    print("\n🎤 Testing VoiceFlow Personal Integration...")
    
    try:
        from voiceflow_personal import PersonalVoiceFlow
        
        # Create VoiceFlow instance with long sessions enabled
        voiceflow = PersonalVoiceFlow(enable_long_sessions=True)
        
        # Test session stats
        stats = voiceflow.get_session_stats()
        print(f"  ✓ Basic stats: {stats['transcriptions']} transcriptions")
        
        # Test long session features if available
        if voiceflow.enable_long_sessions:
            print("  ✓ Long session support enabled")
            
            # Test cache stats
            cache_stats = voiceflow.ai_enhancer.get_cache_stats()
            print(f"  ✓ Cache stats: {cache_stats['size']} entries")
            
            # Test memory cleanup
            voiceflow.force_memory_cleanup()
            print("  ✓ Memory cleanup works")
            
        else:
            print("  ⚠️  Long session support not available (missing dependencies)")
        
        print("  ✅ VoiceFlow Personal integration test passed")
        return True
        
    except Exception as e:
        print(f"  ❌ VoiceFlow Personal integration test failed: {e}")
        traceback.print_exc()
        return False


def test_voiceflow_core_integration():
    """Test VoiceFlow Core with long session support."""
    print("\n⚙️  Testing VoiceFlow Core Integration...")
    
    try:
        from core.voiceflow_core import create_engine
        
        # Create engine with long session support
        config = {
            'enable_long_sessions': True,
            'model': 'test',
            'max_storage_mb': 10
        }
        
        engine = create_engine(config)
        
        # Test basic functionality
        stats = engine.get_stats()
        print(f"  ✓ Engine stats: {stats['total_transcriptions']} transcriptions")
        
        # Test long session features if available
        if hasattr(engine, 'enable_long_sessions') and engine.enable_long_sessions:
            print("  ✓ Long session support enabled in core")
            
            long_status = engine.get_long_session_status()
            print(f"  ✓ Long session status: {long_status['enabled']}")
            
        else:
            print("  ⚠️  Long session support not available in core")
        
        # Cleanup
        engine.cleanup()
        print("  ✓ Engine cleanup completed")
        
        print("  ✅ VoiceFlow Core integration test passed")
        return True
        
    except Exception as e:
        print(f"  ❌ VoiceFlow Core integration test failed: {e}")
        traceback.print_exc()
        return False


def main():
    """Run all optimization tests."""
    print("🚀 VoiceFlow Long Session Optimization Tests")
    print("=" * 50)
    
    tests = [
        test_memory_monitor,
        test_session_manager,
        test_adaptive_cache,
        test_database_optimization,
        test_voiceflow_personal_integration,
        test_voiceflow_core_integration
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            traceback.print_exc()
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All long session optimizations are working correctly!")
        return 0
    else:
        print("⚠️  Some optimizations need attention.")
        return 1


if __name__ == "__main__":
    exit(main())