"""Live evidence for the Checker: domain registration age (RDAP), hostname / identity checks,
secure page inspection (markup only), threat-feed lookups and their freshness.

Everything here produces EVIDENCE. The verdict is still decided in exactly one place:
``core.scorer`` (signals) → ``channels.trust_policy.decide`` (final tag).
"""
