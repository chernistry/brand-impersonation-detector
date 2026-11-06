"""
Brand-impersonation detection pipeline.

    sensor -> normalize -> cheap filters -> classify -> rank
           -> analyst decision -> signed evidence -> offline verify

The pipeline runs end to end with no API keys and no accounts, using bundled
fixtures and a deterministic rule-based classifier. Setting the relevant
environment variables switches individual stages to live services.

Design rule: sensors are cheap and swappable, the pipeline shape is fixed, and
the evidence receipt is verifiable offline.
"""

__version__ = "0.1.1"
