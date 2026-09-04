# Accepted findings

Every `nosemgrep` in this repository is listed here. A suppression that is not
in this table is a defect: the gate is being silenced without a decision behind
it.

| Date | Rule | Location | Why it was accepted | Revisit when |
|---|---|---|---|---|
| 2026-09-03 | `sqlalchemy-execute-raw-query` | `app/repository.py`, `_page` | Rule targets SQLAlchemy `text()` queries. This is psycopg. The one dynamic element is an `Identifier` composed by psycopg from the `SORTABLE` allow list; values remain bound parameters. | The module adopts SQLAlchemy, or `_page` starts accepting a caller supplied fragment. |
| 2026-09-04 | `dynamic-urllib-use-detected` | `triage/github.py`, `_urllib_transport` | The rule warns that urllib accepts `file://`. Every URL here is assembled from the API base constant, repository paths and query values the script itself encodes, and the transport refuses anything that is not `https://` before opening it. | The client starts accepting a URL or base from configuration or from an alert payload. |

## Rules for suppressing

1. Suppress the **specific rule id**, never a bare `# nosemgrep`. A bare
   suppression hides every future finding on that line, including ones nobody
   has assessed.
2. State why in a comment next to it, with a date.
3. Add a row here.
4. A suppression is a decision with an owner, not a way to make CI green.
