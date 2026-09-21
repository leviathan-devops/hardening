# Why the weights server is hardened
Operator ruling 2026-09-21: "this needs the strictest runtime hardening like we
did with the weights server." The weights server hosts the Bonsai 27B seat model
on :18081; it reads model weights + a LoRA and serves an [OI]-compatible API.

Threat model: it is the single source of the seat's intelligence. If it can be
reached or subverted, every agent that calls it is affected, so it must not be
able to read the operator's hand/phone/discord runtime, and it must not gain
privilege or write outside its own caches.

CRITICAL DEPENDENCY (learned the hard way): the service reads its chat template
from
  /home/leviathan/JARVIS_WORKSPACE/Shared_Workspace/JARVIS_LOCAL_BONSAI/config/chat-template.jinja
so JARVIS_WORKSPACE must stay REACHABLE. An earlier apply made the whole
workspace InaccessiblePaths= and the server exited 1 immediately. The narrow
correct form blocks only /home/leviathan/JARVIS_DISCORD (the phone repo).
