#!/usr/bin/env python3
"""Fix import paths after project restructure."""

import os
import re
from pathlib import Path

def fix_imports_in_file(file_path: Path):
    """Fix imports in a single file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        original_content = content

        # Fix relative imports from localflow
        content = re.sub(r'from \.([a-zA-Z_][a-zA-Z0-9_]*)', r'from voiceflow.utils.\1', content)
        content = re.sub(r'from \.([a-zA-Z_][a-zA-Z0-9_]*)', r'from voiceflow.core.\1', content)
        content = re.sub(r'from \.([a-zA-Z_][a-zA-Z0-9_]*)', r'from voiceflow.ui.\1', content)
        content = re.sub(r'from \.([a-zA-Z_][a-zA-Z0-9_]*)', r'from voiceflow.integrations.\1', content)

        # Fix localflow imports
        content = re.sub(r'from localflow\.', r'from voiceflow.', content)
        content = re.sub(r'import localflow\.', r'import voiceflow.', content)

        # Fix specific common imports
        import_fixes = {
            'from voiceflow.utils.config import': 'from voiceflow.core.config import',
            'from voiceflow.utils.settings import': 'from voiceflow.utils.settings import',
            'from voiceflow.utils.visual_indicators import': 'from voiceflow.ui.visual_indicators import',
            'from voiceflow.utils.visual_config import': 'from voiceflow.ui.visual_config import',
            'from voiceflow.utils.textproc import': 'from voiceflow.core.textproc import',
            'from voiceflow.utils.inject import': 'from voiceflow.integrations.inject import',
            'from voiceflow.utils.hotkeys_enhanced import': 'from voiceflow.integrations.hotkeys_enhanced import',
            'from voiceflow.utils.logging_setup import': 'from voiceflow.utils.logging_setup import',
        }

        for old_import, new_import in import_fixes.items():
            content = content.replace(old_import, new_import)

        # Write back if changed
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Fixed imports in: {file_path}")
            return True

    except Exception as e:
        print(f"Error fixing {file_path}: {e}")

    return False

def main():
    """Fix all imports in the project."""
    src_dir = Path("src/voiceflow")
    scripts_dir = Path("scripts/dev")

    fixed_count = 0

    # Fix imports in src directory
    for py_file in src_dir.rglob("*.py"):
        if fix_imports_in_file(py_file):
            fixed_count += 1

    # Fix imports in dev scripts
    for py_file in scripts_dir.glob("*.py"):
        if fix_imports_in_file(py_file):
            fixed_count += 1

    print(f"\nFixed imports in {fixed_count} files")

if __name__ == "__main__":
    os.chdir(Path(__file__).parent.parent.parent)  # Go to project root
    main()