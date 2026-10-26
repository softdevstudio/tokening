# Tokening v0.1.1

This release makes refusals easier to read and turns the demo replay into a step-by-step walkthrough. Grant checking, consumption and credential handling are unchanged from v0.1.0.

Refusal reasons now say what the grant allows and what the call did. A call aimed at the wrong post reads "Grant is bound to id 2; call sent id 3." A call to another tool reads "Grant allows wp_update_post; call asked for wp_delete_post." An extra field lists the fields the grant does accept, and a length refusal gives the actual size and the limit. Numbers and booleans can appear in a reason. String values never do, because a bound or sent string can hold private text and reasons are stored in the audit log. Use counts read "1 use" rather than "1 use(s)", including in GET /grant.

The demo replay opens at step 0 with the grant explained. Play, Next step and Previous step move through the run one record at a time. Each step has a short caption and shows the request the agent sent. The post card follows the replay from its starting title to the state verified in WordPress after the run. Long grant IDs are shortened on the page. Add ?embed to the replay URL to hide its own header when it sits inside another page; it then reports its height to that page so the frame fits on phones. The replay still sends no network requests and holds no credentials.

The Docker demo now records each scripted request (tool and short scalar arguments) and the seeded posts before the agent runs. The replay keeps only numbers, booleans and strings of up to 60 characters from those requests.

Download the archive for your operating system and architecture, verify it against SHA256SUMS and read README.md inside it. Archive names have no version, so latest/download links keep working. The limits listed for v0.1.0 still apply: the MCP agent profile is 2025-06-18, responses are buffered to 1 MiB, and stdio targets, OAuth server duties, rate limiting and vault key rotation are outside this release. The review recorded for this release is a project source review, not an external security audit.

Licence: Apache 2.0. Third-party notices are included in every archive.
