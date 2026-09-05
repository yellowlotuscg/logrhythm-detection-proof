# Sources: LogRhythm detection proof

Official documentation consulted for this offline reference project.
All URLs below were fetched and read during research on 2026-09-05, before
the repository content was written. Titles are rendered in ASCII.

## LogRhythm SIEM documentation (docs.logrhythm.com)

1. "Create New AI Engine Rules" - rule block types including the
   THRESHOLD "Observed" block, and the Deployment Manager / AI Engine
   rule creation flow that a genuine AIE rule would use.
   https://docs.logrhythm.com/lrsiem/docs/create-new-ai-engine-rules

2. "Filters - Thresholds" - documents threshold time limits (1 minute to
   30 days) and the anchored-window semantics this proof implements:
   "The duration begins from the time the first log appears that meets
   the threshold criteria."
   https://docs.logrhythm.com/lrsiem/docs/filtersthresholds

3. "Filters - Unique Values" - documents occurrence counts and time
   limits for rule blocks, and notes that group-by fields cannot be used
   for Unique Values blocks.
   https://docs.logrhythm.com/lrsiem/docs/filtersunique-values

4. "Glossary of LogRhythm Products and Components" - definitions for
   Advanced Intelligence Engine, AI Engine Rule, AI Engine Rule Block,
   Alarm Aggregation, and related vocabulary used in the README.
   https://docs.logrhythm.com/lrsiem/docs/glossary-of-logrhythm-products-and-components

5. "Core Threat Detection User Guide - AI Engine Rules" - preconfigured
   detection rules. AIE Rule ID 3 ("Compromise: Distributed Brute
   Force") describes tracking multiple failed authentication attempts by
   origin login and host before a following authentication success.
   https://docs.logrhythm.com/kbmodules/docs/core-threat-detection-user-guide-ai-engine-rules

6. "UEBA User Guide - AI Engine Rules" - preconfigured rules describing
   failed-authentication correlation patterns, including AIE Rule ID
   1264 ("Lateral: Brute Force Internal Auth Failure": multiple failed
   authentication attempts from the same internal origin host to the
   same impacted host) and AIE Rule ID 1266 ("Lateral: Failed Auths then
   Success").
   https://docs.logrhythm.com/kbmodules/docs/ueba-user-guide-ai-engine-rules

## LogRhythm SIEM developer documentation (developers.exabeam.com)

7. "LogRhythm SIEM" developer portal - current home of LogRhythm SIEM
   developer documentation, including AI Engine API changelog entries
   for 7.24.0 and 7.25.0.
   https://developers.exabeam.com/logrhythm-siem

8. "LogRhythm REST API" - REST API families (Administration, AI Engine
   Cache Drilldown, Alarm, Case, Metrics, Search) and the API account /
   token model. Relevant as the integration boundary for a live
   deployment; nothing in this repo calls any of these APIs.
   https://developers.exabeam.com/logrhythm-siem/docs/logrhythm-rest-api

## Notes on what the docs do NOT pin down

- The AI Engine threshold filter documentation describes time limits and
  field criteria, but the exact runtime grouping and window bookkeeping
  of the product is not specified page by page. This proof implements
  one documented, deterministic interpretation (anchored window,
  inclusive boundary) and labels it as such; it is not a claim about
  LogRhythm runtime behavior.
- Preconfigured rule descriptions (AIE Rules 3, 1263, 1264, 1266) name
  fields such as origin login, origin host, and impacted host. The
  synthetic event vocabulary used here (identity, source) is a simplified
  stand-in for those concepts, chosen for a self-contained fixture.
- None of the pages above contain an exportable rule artifact. This
  repository contains no genuine exported AIE rule and no vendor
  deployment was performed.
