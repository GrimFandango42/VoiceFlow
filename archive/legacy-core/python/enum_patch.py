# Enum compatibility patch for Python 3.13
import enum
import sys

# Add missing global_enum attribute for older packages
if not hasattr(enum, 'global_enum'):
    def global_enum(cls):
        return cls
    enum.global_enum = global_enum

print("Enum compatibility patch applied successfully")
