# Issue tracker: GitHub

Issues and PRDs for this repository live as GitHub issues in `Cd1s/ssm`. Use
the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a
  heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --comments`, filtering comments
  with `jq` and also fetching labels.
- **List issues**: `gh issue list --state open --json
  number,title,body,labels,comments` with appropriate `--label` and `--state`
  filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`.
- **Apply or remove labels**: `gh issue edit <number> --add-label "..."` or
  `gh issue edit <number> --remove-label "..."`.
- **Close an issue**: `gh issue close <number> --comment "..."`.

Infer the repository from `git remote -v`; `gh` does this automatically when
run inside the clone.

## Pull requests as a triage surface

**PRs as a request surface: no.** Set this to `yes` only if the repository
starts treating external pull requests as feature requests.

When enabled, pull requests use the same labels and states as issues:

- Read with `gh pr view <number> --comments` and `gh pr diff <number>`.
- List external pull requests with `gh pr list --state open`, retaining only
  authors whose association is `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR`, or
  `NONE`.
- Comment, label, and close with the corresponding `gh pr` commands.

GitHub shares one number space across issues and pull requests. Resolve an
ambiguous `#<number>` with `gh pr view <number>` and fall back to
`gh issue view <number>`.

## Skill operations

- When a skill says to publish to the issue tracker, create a GitHub issue.
- When a skill says to fetch the relevant ticket, run
  `gh issue view <number> --comments`.

## Wayfinding operations

For `/wayfinder`, the map is one issue and its tickets are child issues.

- Label the map `wayfinder:map` and keep its notes, decisions so far, and fog
  in the issue body.
- Represent tickets as GitHub sub-issues where supported. Otherwise, use a
  task list in the map and start each ticket with `Part of #<map>`.
- Represent blocking with GitHub issue dependencies where supported.
  Otherwise, start the child with `Blocked by: #<number>`.
- Claim a ticket with `gh issue edit <number> --add-assignee @me`; this is the
  session's first write.
- Resolve a ticket by commenting with the answer, closing it, and adding its
  context pointer to the map.
