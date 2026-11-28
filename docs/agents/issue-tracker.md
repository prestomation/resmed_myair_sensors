# Local Markdown issue tracker

Use one directory per feature under `.scratch/<feature-slug>/`.

- Publish the spec to `.scratch/<feature-slug>/spec.md`.
- Publish each implementation ticket as its own file at `.scratch/<feature-slug>/issues/<NN>-<slug>.md`. Number tickets starting at `01`.
- Record triage state on a `Status:` line near the top. Use the values in [triage labels](triage-labels.md).
- Append comments and conversation history under `## Comments`.

Create the feature directory when publishing. Fetch a ticket by reading the supplied file path or matching its number within the feature. Record ticket dependencies under `Blocked by:` using numbers from the same feature.

## Wayfinding operations

- Store the map in `.scratch/<effort>/map.md` with Notes, Decisions-so-far, and Fog sections.
- Store child tickets in `.scratch/<effort>/issues/<NN>-<slug>.md`, starting at `01`. Put the question in the body. Use a `Type:` line with `research`, `prototype`, `grilling`, or `task`.
- Record dependencies on a `Blocked by:` line such as `Blocked by: 01, 02`. A child ticket is unblocked when all listed tickets have `Status: resolved`.
- Select the first open, unblocked, unclaimed child ticket by number. Save `Status: claimed` before starting work.
- To resolve the ticket, append the answer under `## Answer`, save `Status: resolved`, then add a short summary and a link to the ticket in the map’s Decisions-so-far section.
