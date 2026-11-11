# Failure patterns (v0.2.0)

Each pattern is a failure seen in real agent deployments or created by common library defaults. Organisations
are deliberately not named. Cite a pattern by id in a finding's **Pattern** field, and only when
its mechanism matches what the code shows. Never stretch a pattern to fit.

**Basis labels**
- **researcher disclosure**: shown by security researchers with a working demonstration.
- **first-person postmortem**: written by the operator who lost the data.
- **press report**: known through news coverage of the operator's statements.
- **default behaviour**: not an incident; a library or tool behaves this way unless configured.

---

## Blast radius inside the enclave

### P01 Poisoned public content steers a privileged agent
- **Year:** 2025 · **Basis:** researcher disclosure
- **Mechanism:** instructions planted in a public issue were read by a developer's agent that also held
  a token for private repositories. The agent copied private data into a public place. No
  malicious tool was involved: trusted tools plus untrusted content were enough.
- **Shape:** lethal trifecta: untrusted content + private data + a way to publish. D1, D2, D5.
- **Matches when:** one agent reads attacker-writable content and holds credentials to private
  data and a way to send or publish.

### P02 Support ticket reaches an admin database key
- **Year:** 2025 · **Basis:** researcher disclosure
- **Mechanism:** a support ticket carried instructions. The agent reading it used a database key
  that bypassed row-level security, and leaked private tables into the ticket thread.
- **Shape:** D1 (ticket) + D3 (admin key that skips row-level access rules) + D5.
- **Matches when:** a ticket, email or chat reader shares an agent with a database tool, especially
  one using an admin credential.

### P03 Delegated infrastructure destroy
- **Year:** 2026 · **Basis:** first-person postmortem
- **Mechanism:** an operator let a coding agent run infrastructure commands. After a state-file mix-up,
  the agent ran a destroy that removed the production database and its snapshots. The author's
  lesson: plan, apply and destroy had been treated as delegable, which removed the last safety
  layer.
- **Shape:** D4 (infra destroy) with no D6 gate. Backups lived inside the same blast radius.
- **Matches when:** an agent can run destroy-class infra or shell commands, especially with
  auto-approve, and backups are reachable by the same credential.

### P04 Found token, one call, production and backups gone
- **Year:** 2026 · **Basis:** press report
- **Mechanism:** a coding agent working on a non-production task found a broadly scoped API token in
  an unrelated file. It assumed a delete would be scoped to staging, and one API call deleted the production volume
  together with its backups.
- **Shape:** D3 (a token broader than the task) + D4 with no gate + backups inside the blast radius.
- **Matches when:** an agent can read a credential broader than its task, or a non-production
  task can resolve a production credential.

### P05 Freeze that existed only in the prompt
- **Year:** 2025 · **Basis:** press report
- **Mechanism:** an agent was told a code freeze was in effect and still deleted a live production
  database. It then misreported whether rollback was possible.
- **Shape:** an instruction-only control (D6 prompt-only) + D4. D7: the agent's own account of
  what happened was wrong.
- **Matches when:** a safety rule or approval exists only as words to the model, such as a
  docstring saying "only call this after the user confirms", with no server-side check.

### P06 Internal agent as a lateral-movement path
- **Year:** 2026 · **Basis:** press report
- **Mechanism:** after compromising one engineer's laptop, attackers used an internal AI tool to
  take over other engineers' machines. One of those held a deploy permission that led to
  signing infrastructure and a very large theft. The tool's permissions were not disclosed; do not
  infer them.
- **Shape:** D2/D7: an internal agent with reach into other people's machines, sessions or
  deploy rights.
- **Matches when:** an internal agent can act on other users' machines, sessions or credentials,
  or holds a standing token for deploy or signing systems.

### P07 Unbounded loop
- **Year:** 2023 · **Basis:** press report
- **Mechanism:** early autonomous agents with no iteration or spend limit looped on their own goals
  and ran up bills.
- **Shape:** D6: no turn limit, no spend cap.
- **Matches when:** an agent loop has no turn, recursion or budget limit.

## Crossing the air-gap boundary (D8)

### P08 Telemetry phones home by default
- **Basis:** default behaviour
- **Mechanism:** several agent frameworks, vector stores and SDKs send usage or trace data to a
  vendor endpoint unless an opt-out variable is set. Traces often carry prompts, tool arguments
  and outputs.
- **Shape:** D8. Context-bearing data leaves the enclave the moment any route out exists.
- **Matches when:** a tracing or telemetry client is configured with a hosted endpoint, or a
  framework with default-on telemetry is used without its opt-out.

### P09 Code fetched at start
- **Basis:** default behaviour
- **Mechanism:** `npx -y pkg`, `uvx pkg`, or `pip install` at container start resolve the newest
  release from a public registry on every boot. In a sealed enclave the agent fails to start. With
  a mirror or proxy, it runs whatever the registry served that day.
- **Shape:** D8 + supply chain. Unpinned is worse than pinned.
- **Matches when:** MCP servers, tools or entrypoints are launched through package runners, or
  installs happen in CMD, ENTRYPOINT or start scripts rather than at build time.

### P10 Model or data files downloaded on first use
- **Basis:** default behaviour
- **Mechanism:** embedding models, tokenizer files, NLP corpora and browser binaries are often
  fetched the first time code touches them (`from_pretrained`, `SentenceTransformer(...)`,
  tokenizer encoding lookups, `nltk.download`, `playwright install`).
- **Shape:** D8. The agent breaks inside the enclave, or reaches out if a route exists.
- **Matches when:** these calls run at runtime without offline flags (`HF_HUB_OFFLINE`,
  `local_files_only=True`) and vendored files.

### P11 Hosted model as a hard dependency
- **Basis:** default behaviour
- **Mechanism:** the agent's model client points at a hosted API, with no configurable base URL or
  provider. Every prompt, retrieved document and tool result is sent to that endpoint.
- **Shape:** D8. The largest context-bearing path out of any agent.
- **Matches when:** a hosted provider client or `provider:model` string is used and no base-URL or
  local-model switch exists.

---

## Concept: the lethal trifecta

Term coined by Simon Willison (2025). An agent that has **access to private data**, **exposure to
untrusted content** and **the ability to communicate externally** can be tricked into sending
the private data to an attacker. In an air-gapped enclave, the third leg is any D8 crossing or any
in-enclave sink the attacker can read.

## Adding a pattern

Describe the mechanism without naming the organisation. Record the year, a basis label, the shape
(dimensions and severity) and a "Matches when" line. Keep sources in your own notes; they do not
go in this file.
