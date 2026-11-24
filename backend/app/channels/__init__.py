"""Shield & Channels.

Search / Maps channel adapters, the Sweep service, Guard blocklist generation,
the trust-policy adapter, and the official UAE source registry
(``channels.official``). This package does not embed verdict logic; it calls the
shared brain (``core.scorer``) in-process through its public functions.
"""
