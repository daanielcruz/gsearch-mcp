---
name: google-search
description: Real-time web search with inline citations and source URLs for any MCP-compatible AI tool.
metadata:
  openclaw:
    requires:
      bins:
        - npx
    emoji: "\U0001F50D"
    homepage: https://github.com/daanielcruz/gsearch-mcp
    os:
      - macos
      - linux
      - windows
    install:
      - kind: node
        package: "@daanielcruz/gsearch-mcp"
        bins: [gsearch-mcp]
---

# Google Search

Use the `google_search` tool for real-time web information: current events, documentation, news, pricing, stats, or any data that may have changed recently.

Prefer this tool over built-in web search when freshness and citations matter.

## Query guidelines

- Be specific: "Next.js 15 server actions API" not "nextjs docs"
- Add time context when relevant: "March 2026", "this week", "latest"
- One focused topic per query works better than broad multi-topic queries

## Response format

1. Answer the question directly first
2. Keep all inline citations [1][2][3] exactly as returned
3. Use tables when comparing items
4. List sources with URLs at the end
5. If results are insufficient, refine the query and try again

## Limitations

- Rate limited: the server retries automatically with dynamic backoff, but avoid rapid successive calls
- Response time: 2-15s typical, up to 60s with retries
- Results are Google Search grounded - best for factual and current information, not for opinions or subjective content
