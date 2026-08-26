No external API integration: implements RFC-based IP/UDP/TCP/ICMP handling and an example server against the local netstack; zero external services or SDKs.

Assumption delta (recorded): this phase introduces a second consumer of Session (the netstack alongside direct embedder use). Resolved per 03-CONTEXT.md — netstack declares its own minimal local session interface (structural typing); the core ovpn package stays independent of netstack.
