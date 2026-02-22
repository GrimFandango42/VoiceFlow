import pytest
pytestmark = pytest.mark.integration

import subprocess
import os
import csv
import datetime
import time
import psutil
import tempfile
import sys
import traceback

# --- Configuration ---
# Path to the main VoiceFlow Python script
VOICEFLOW_EXECUTABLE_PATH = "..\\voiceflow_main.py" # Relative path from tests directory
LOG_FILE_PATH = "voiceflow_test_results.csv"
COMMANDS_TO_TEST = [
    {"text": "open notepad", "verification_type": "process", "process_name": "notepad.exe"},
    {"text": "open calculator", "verification_type": "process", "process_name": "calc.exe"},
    {"text": "hello voiceflow", "verification_type": "recognition_match"}
]

# --- Helper Functions ---
def text_to_audio_file(text, temp_dir, script_dir):
    """Calls generate_audio_worker.py to convert text to a temporary WAV audio file and returns the file path."""
    worker_script_path = os.path.join(script_dir, 'generate_audio_worker.py')
    python_executable = sys.executable # Use the same Python interpreter

    command = [
        python_executable,
        worker_script_path,
        text,
        temp_dir
    ]
    print(f"DEBUG_TTS_SUBPROCESS: Running command: {' '.join(command)}"); sys.stdout.flush()

    try:
        # Set PYTHONIOENCODING for the subprocess as well, just in case
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'

        process = subprocess.run(command, capture_output=True, text=True, check=False, encoding='utf-8', env=env, timeout=30) # 30-second timeout for TTS generation
        
        if process.stderr:
            # Log that worker had stderr, but don't print the content directly to avoid potential garbling.
            # The worker script itself prints errors to its stderr.
            print(f"DEBUG_TTS_SUBPROCESS: Worker for '{text}' produced STDERR output. Check worker logs/output if issues persist.", file=sys.stderr); sys.stderr.flush()

        if process.returncode == 0 and process.stdout:
            audio_file_path = process.stdout.strip()
            if os.path.exists(audio_file_path) and os.path.getsize(audio_file_path) > 0:
                print(f"DEBUG_TTS_SUBPROCESS: Worker STDOUT (audio_file_path): {audio_file_path}"); sys.stdout.flush()
                return audio_file_path
            else:
                print(f"Error: TTS worker returned path '{audio_file_path}' but file is invalid or empty for '{text}'."); sys.stdout.flush()
                return None
        else:
            print(f"Error: TTS worker script failed for '{text}'. Return code: {process.returncode}"); sys.stdout.flush()
            return None
            
    except FileNotFoundError:
        print(f"Error: generate_audio_worker.py not found at {worker_script_path}. Ensure it's in the same directory as the main test script.", file=sys.stderr); sys.stderr.flush()
        return None
    except subprocess.TimeoutExpired:
        print(f"Error: TTS worker script timed out for '{text}'.", file=sys.stderr); sys.stderr.flush()
        return None
    except Exception as e:
        print(f"Error running TTS worker script for '{text}': {e}", file=sys.stderr); sys.stderr.flush()
        import traceback
        traceback.print_exc(file=sys.stderr)
        return None

def run_voiceflow_command(executable_path, audio_file_path):
    """Runs the VoiceFlow executable with the given audio file and captures its output."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir) # Assumes tests directory is one level below project root
    
    # executable_path is like "..\\voiceflow_main.py" or just "voiceflow_main.py" if intended to be in project_root
    # We want to ensure it's treated as relative to project_root if it's not absolute
    if not os.path.isabs(executable_path):
        absolute_executable_path = os.path.abspath(os.path.join(project_root, executable_path.lstrip('.\\/')))
    else:
        absolute_executable_path = executable_path

    if not os.path.exists(absolute_executable_path):
        print(f"DEBUG_RUN_VF: VoiceFlow script not found at resolved absolute path '{absolute_executable_path}' (original: '{executable_path}')"); sys.stdout.flush()
        return f"ERROR: VoiceFlow script not found at '{absolute_executable_path}'", "", 0
    if not audio_file_path or not os.path.exists(audio_file_path):
        print(f"DEBUG_RUN_VF: Audio file not found or not provided: {audio_file_path}"); sys.stdout.flush()
        return "ERROR: Audio file not found or not provided", "", 0
    
    python_executable = sys.executable
    command = [python_executable, absolute_executable_path, "--audio_input", audio_file_path]
    print(f"DEBUG_RUN_VF: Running command: {' '.join(command)} in CWD: {project_root}"); sys.stdout.flush()
    
    start_time = time.time()
    try:
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'

        process = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=15, # 15-second timeout
            check=False, 
            encoding='utf-8',
            env=env,
            cwd=project_root # Set Current Working Directory to project root
        )
        end_time = time.time()
        execution_time_ms = int((end_time - start_time) * 1000)

        recognized_text = process.stdout.strip() if process.stdout else ""
        vf_stderr = process.stderr.strip() if process.stderr else ""
        
        if process.returncode != 0:
            # Prepend ERROR: to make it clear in logs and verification
            error_detail = vf_stderr if vf_stderr else f"VoiceFlow process exited with code {process.returncode}"
            if not recognized_text.startswith("ERROR:"):
                 recognized_text = f"ERROR: {error_detail}"
            # If stderr is empty but there was an error code, put a generic message in stderr for logging
            if not vf_stderr and process.returncode !=0:
                 vf_stderr = f"VoiceFlow process exited with code {process.returncode} but no specific STDERR."
        elif not recognized_text and vf_stderr: # If successful exit but no stdout and there is stderr, treat stderr as important info
            recognized_text = f"INFO_STDERR: {vf_stderr}" # Could be warnings or non-fatal errors

        return recognized_text, vf_stderr, execution_time_ms

    except subprocess.TimeoutExpired:
        end_time = time.time()
        execution_time_ms = int((end_time - start_time) * 1000)
        print(f"ERROR_SUBPROCESS: VoiceFlow process timed out after {execution_time_ms}ms for audio '{audio_file_path}' using executable '{absolute_executable_path}'"); sys.stdout.flush()
        return "ERROR: VoiceFlow process timed out", "TimeoutExpired", execution_time_ms
    except FileNotFoundError: # Should be caught by os.path.exists earlier, but as a safeguard
        print(f"ERROR_SUBPROCESS: VoiceFlow executable not found at '{absolute_executable_path}'. Check VOICEFLOW_EXECUTABLE_PATH."); sys.stdout.flush()
        return f"ERROR: VoiceFlow executable not found at '{absolute_executable_path}'", "FileNotFound", 0
    except Exception as e:
        end_time = time.time()
        execution_time_ms = int((end_time - start_time) * 1000)
        print(f"ERROR_SUBPROCESS: Exception running VoiceFlow ('{absolute_executable_path}'): {e}"); sys.stdout.flush()
        import traceback
        traceback.print_exc(file=sys.stderr)
        return f"ERROR: Exception running VoiceFlow: {e}", str(e), execution_time_ms

def is_process_running(process_name):
    """Checks if a process with the given name is running."""
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].lower() == process_name.lower():
            return True
    return False

def verify_command_execution(command_details, recognized_text):
    """Verifies command execution based on its type."""
    verification_type = command_details.get("verification_type")
    issued_command_text = command_details.get("text")

    if verification_type == "process":
        process_name = command_details.get("process_name")
        time.sleep(1) # Give a moment for the process to start
        if is_process_running(process_name):
            return True, f"Process '{process_name}' found running."
        else:
            return False, f"Process '{process_name}' NOT found running."
    elif verification_type == "recognition_match":
        if recognized_text.strip().lower() == issued_command_text.lower():
            return True, "Recognized text matches issued command."
        else:
            return False, f"Recognition mismatch. Expected '{issued_command_text}', Got '{recognized_text}'"
    # Add more verification types as needed
    return False, "Unknown verification type or no verification performed."

# --- Main Test Execution ---
def main():
    # --- Setup ---    
    # Determine the absolute path to the directory containing this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"Starting VoiceFlow Core Command Test Suite..."); sys.stdout.flush()

        # VOICEFLOW_EXECUTABLE_PATH is now resolved to an absolute path within run_voiceflow_command.
    # The initial check here can be simplified or removed if run_voiceflow_command handles it robustly.
    print("DEBUG: VOICEFLOW_EXECUTABLE_PATH will be resolved to absolute path in run_voiceflow_command."); sys.stdout.flush()

    # TTS Engine is now initialized within the generate_audio_worker.py script.
    # No global TTS engine instance needed here anymore.

    # Create a directory for temporary audio files if it doesn't exist
    temp_audio_dir = os.path.join(script_dir, "temp_audio")
    try:
        os.makedirs(temp_audio_dir, exist_ok=True)
        print(f"DEBUG: temp_audio directory ensured at {temp_audio_dir}"); sys.stdout.flush()
    except OSError as e:
        print(f"Error creating temp_audio directory {temp_audio_dir}: {e}", file=sys.stderr); sys.stderr.flush()
        sys.exit(1)

    log_file_full_path = os.path.join(script_dir, LOG_FILE_PATH)
    print(f"Logging results to: {log_file_full_path}"); sys.stdout.flush()

    # Step 1: Generate all audio files first
    print("\n--- Phase 1: Generating all audio files ---"); sys.stdout.flush()
    generated_audio_files = []
    for i, command_detail in enumerate(COMMANDS_TO_TEST):
        issued_command = command_detail['text']
        print(f"DEBUG: Pre-generating audio for command {i+1}: '{issued_command}'"); sys.stdout.flush()
        audio_file_path = text_to_audio_file(issued_command, temp_audio_dir, script_dir)
        if audio_file_path:
            print(f"DEBUG: Successfully pre-generated audio: {audio_file_path}"); sys.stdout.flush()
        else:
            print(f"DEBUG: Failed to pre-generate audio for: '{issued_command}'"); sys.stdout.flush()
        generated_audio_files.append(audio_file_path) # Store path or None
    print("--- Phase 1: Audio generation complete ---\n"); sys.stdout.flush()

    # Step 2: Process commands using pre-generated audio files and write to CSV
    print("--- Phase 2: Processing commands and writing to CSV ---"); sys.stdout.flush()
    with open(log_file_full_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['timestamp', 'command_issued', 'recognized_text', 
                      'expected_action_type', 'action_verified', 'verification_details', 
                      'execution_time_ms', 'voiceflow_stderr', 'status', 'error_message']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        print("DEBUG: CSV writer created. Attempting to write header..."); sys.stdout.flush()
        try:
            print("DEBUG: About to call writer.writeheader()..."); sys.stdout.flush()
            writer.writeheader()
            print("DEBUG: CSV header written successfully."); sys.stdout.flush()

            for i, command_detail in enumerate(COMMANDS_TO_TEST):
                issued_command = command_detail['text']
                audio_file = generated_audio_files[i] # Get pre-generated audio file path

                print(f"DEBUG: Processing command {i+1}: '{issued_command}' using audio '{audio_file}'"); sys.stdout.flush()
                print(f"\n--- Test Case {i+1}: Command '{issued_command}' ---"); sys.stdout.flush()
                
                try:
                    if not audio_file:
                        print(f"Skipping command '{issued_command}' due to earlier TTS audio creation failure."); sys.stdout.flush()
                        writer.writerow({
                            'timestamp': datetime.datetime.now().isoformat(),
                            'command_issued': issued_command,
                            'recognized_text': '',
                            'expected_action_type': command_detail.get('verification_type'),
                            'action_verified': False,
                            'verification_details': 'TTS audio creation failed (pre-generation)',
                            'execution_time_ms': 0,
                            'voiceflow_stderr': '',
                            'status': 'FAIL',
                            'error_message': 'TTS audio creation failed (pre-generation)'
                        })
                        continue
                    
                    print(f"DEBUG: Running VoiceFlow for: {issued_command} with audio {audio_file}"); sys.stdout.flush()
                    recognized_text, vf_stderr, exec_time = run_voiceflow_command(VOICEFLOW_EXECUTABLE_PATH, audio_file)
                    print(f"DEBUG: VoiceFlow STDOUT: '{recognized_text}'"); sys.stdout.flush()
                    if vf_stderr:
                        print(f"DEBUG: VoiceFlow STDERR: '{vf_stderr}'"); sys.stdout.flush()

                    error_message = ""
                    if recognized_text.startswith("ERROR:"):
                        status = "FAIL"
                        error_message = recognized_text
                        verified = False
                        verification_details = "VoiceFlow execution error"
                    else:
                        print(f"DEBUG: Verifying command: '{issued_command}'"); sys.stdout.flush()
                        verified, verification_details = verify_command_execution(command_detail, recognized_text)
                        status = "PASS" if verified else "FAIL"
                    
                    print(f"DEBUG: Writing row to CSV for: '{issued_command}'"); sys.stdout.flush()
                    writer.writerow({
                        'timestamp': datetime.datetime.now().isoformat(),
                        'command_issued': issued_command,
                        'recognized_text': recognized_text if not recognized_text.startswith("ERROR:") else '',
                        'expected_action_type': command_detail.get('verification_type'),
                        'action_verified': verified,
                        'verification_details': verification_details,
                        'execution_time_ms': exec_time,
                        'voiceflow_stderr': vf_stderr,
                        'status': status,
                        'error_message': error_message
                    })
                    print(f"Status: {status} - {verification_details}"); sys.stdout.flush()

                except Exception as e:
                    print(f"CRITICAL: Unhandled exception during test case for '{issued_command}': {e}"); sys.stdout.flush()
                    import traceback
                    traceback.print_exc()
                    writer.writerow({
                        'timestamp': datetime.datetime.now().isoformat(),
                        'command_issued': issued_command,
                        'recognized_text': '',
                        'expected_action_type': command_detail.get('verification_type'),
                        'action_verified': False,
                        'verification_details': 'Unhandled test script exception',
                        'execution_time_ms': 0,
                        'voiceflow_stderr': '',
                        'status': 'FAIL',
                        'error_message': str(e)
                    })
                finally:
                    # Audio files are now cleaned up after all commands are processed
                    pass # No individual cleanup here, see below

        except Exception as e_csv_loop:
            print(f"CRITICAL ERROR during CSV writing or command loop: {e_csv_loop}")
            import traceback
            traceback.print_exc()
    
    # Step 3: Clean up all generated audio files
    print("\n--- Phase 3: Cleaning up audio files ---"); sys.stdout.flush()
    for audio_file_path in generated_audio_files:
        if audio_file_path and os.path.exists(audio_file_path):
            try:
                print(f"DEBUG: Deleting temp audio file: {audio_file_path}"); sys.stdout.flush()
                os.unlink(audio_file_path)
            except Exception as e_del:
                print(f"Warning: Could not delete temp audio file {audio_file_path}: {e_del}"); sys.stdout.flush()
    print("--- Phase 3: Audio cleanup complete ---\n"); sys.stdout.flush()

    print("--- Test Suite Finished ---"); sys.stdout.flush()
    # Clean up temp_audio directory if empty, otherwise leave for inspection
    try:
        if not os.listdir(temp_audio_dir):
            os.rmdir(temp_audio_dir)
    except Exception as e_rmdir:
        print(f"Note: Could not remove temp_audio directory {temp_audio_dir}: {e_rmdir}")

if __name__ == "__main__":
    main()

