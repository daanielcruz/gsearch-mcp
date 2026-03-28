# Privacy Policy

**GSearch - Free Google Search MCP**

Last updated: March 27, 2026

## What GSearch does

GSearch is a local MCP server that sends your search queries to the Google Code Assist API and returns grounded answers with citations. It runs entirely on your machine.

## Data collection

GSearch does **not** collect, store, or transmit any user data to us. We have no servers, no analytics, no telemetry.

## What Google receives

When you perform a search, your query is sent to Google's Code Assist API (`cloudcode-pa.googleapis.com`). This is the same API used by the open-source Gemini CLI. Google's own privacy policies apply to this data:

- [Google Privacy Policy](https://policies.google.com/privacy)
- [Google Cloud Terms](https://cloud.google.com/terms)

On the free tier, Google may use your prompts and responses to improve their AI models. Paid tiers (AI Pro, AI Ultra) do not use your data for training.

## OAuth credentials

GSearch stores OAuth tokens locally at `~/.gsearch/oauth_creds.json` with restricted file permissions (0600). These tokens are never sent anywhere other than Google's OAuth endpoints.

## Third parties

GSearch has no third-party integrations, ads, or tracking. The only external communication is with Google's APIs for authentication and search.

## Contact

For questions about this policy, open an issue at https://github.com/daanielcruz/gsearch-mcp/issues
