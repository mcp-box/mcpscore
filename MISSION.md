# Our Mission

**The mission of mcpscore is to help the tech community dramatically raise the quality of MCP servers everywhere.**

It's an ambitious mission — ambitious because of its scale and its technical complexity. It's also one of unusual importance.

## Why this matters

MCP went from a proposal to one of the most widely adopted standards in the world in almost no time, and its adoption keeps growing.

That kind of convergence is rare. We still live with dozens of incompatible electrical socket types across the globe, with no realistic path to unifying them. We have competing open and proprietary charging standards for our phones and gadgets. We can't even agree on units of measurement — a gallon or a mile can mean different things depending on which side of the ocean you're on.

Yet MCP became a single, shared standard for connecting AI to the world almost overnight. That's a foundation worth protecting.

Thanks to its simplicity and a vast ecosystem, it's very easy to build an MCP server today. But it's just as easy to build one *wrong* — and a server that's wrong fails silently, inside someone else's AI agent.

## What "wrong" means

"Wrong" can mean several things, and mcpscore is built to catch all of them:

1. **Non-compliant** — the server violates the MCP specification. An unsupported protocol version, a missing server name, or a malformed tool schema breaks interoperability and gets the server dropped from agent registries.
2. **Insecure** — the server exposes its users to risk. Unencrypted transport, invalid certificates, or error responses that leak internal data turn an integration into a liability.
3. **Hard for agents to use** — the server is technically valid but unusable in practice. Missing tool titles, descriptions, or output schemas lead agents to pick the wrong tool, call it incorrectly, or skip it entirely.

A server can pass every test a human would think to run and still be wrong in all three ways. mcpscore exists to surface those failures in seconds — before your users hit them.

## A moving target

The MCP standard keeps evolving — to improve what we didn't get right the first time, and to fix the flaws we discover as we build out this new connectivity layer for AI.

So part of our mission is to promote and support migration to new versions, and to encourage the rapid deprecation of older ones with known flaws and vulnerabilities. Quality isn't a one-time score; it's keeping up with a standard that's still maturing.

## Opinionated, but backed by data

mcpscore is an opinionated take on what makes an MCP server good. But it isn't arbitrary — it's grounded in research and real-world best practices, and the score evolves as we learn more.

We don't believe one size fits all. Some teams will reasonably choose to follow certain practices and not others, which is why mcpscore is highly customizable. We'd rather mcpscore be used to improve *something* about a server than insist every server chase a perfect score and end up being used by no one.

## Built to be everywhere

For mcpscore to achieve its mission, it has to meet developers where they already work:

- as a **CLI tool** on your machine,
- in **CI/CD pipelines** to catch regressions before they ship,
- and on the **web**, so anyone can check any server.

The more places mcpscore runs, the more MCP servers it can help improve.

## Contribute

We're looking for like-minded people to help.

If you have a best practice you think we should adopt, send it our way — we'll evaluate it and fold the important parts into our rule engine. See [CONTRIBUTING.md](CONTRIBUTING.md) to add an audit rule, or [open an issue](https://github.com/mcp-box/mcpscore/issues) to start a conversation.

Help us make MCP servers better, everywhere.
