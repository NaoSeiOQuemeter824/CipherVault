"""CipherVault package init.

Holds the library version string and exports public modules.
Increment version numbers on meaningful changes:
 MAJOR (X.0.0): incompatible / large redesign
 MINOR (1.X.0): feature additions (new commands, format changes)
 PATCH (1.0.X): small improvements / fixes / instrumentation
"""

__version__ = "1.3.1"  # Partilha simplificada: exportar PEM público; contactos via ficheiro

__all__ = ["crypto", "__version__"]
