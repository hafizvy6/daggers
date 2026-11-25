"""Official UAE source registry and government-claim verification engine.

Layering (pure → impure):

* ``normalize``, ``extract``, ``compare``, ``verify`` — pure functions. No
  network, no clock reads (``now`` is always passed in), no file writes.
* ``models``, ``registry`` — data model plus YAML loading/validation. The only
  write path is the explicit human approval CLI.
* ``fetch``, ``snapshots``, ``discover`` — the retrieval layer. Kept separate so
  a failed retrieval can never be mistaken for a verification.
"""

POLICY_VERSION = "daggers-trust-2.2"  # 2.0: two SAFE paths, compromise → FAKE, data gaps ≠ evidence
