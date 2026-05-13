# Week 3 — Exercises

Three paper exercises. Each takes 40-60 minutes. Do them in order; the third builds on the first two.

1. **[Exercise 1 — STRIDE on a todo app](exercise-01-stride-on-todo-app.md)** — draw the DFD, walk STRIDE per element, produce a candidate threat list. (~50 min)
2. **[Exercise 2 — Attack tree for "compromise an SSH-accessible server"](exercise-02-attack-tree-for-ssh.md)** — decompose a single attacker goal into AND/OR sub-goals down to leaf actions; annotate with cost. (~45 min)
3. **[Exercise 3 — Risk register](exercise-03-risk-register.md)** — merge the findings from exercises 1 and 2 into a single risk register, with L/M/H scoring, owners, dispositions. (~45 min)

## Workflow

- **Pen and paper first.** A DFD on paper is faster to draw, faster to revise, and easier to defend. Photograph the result; commit the PNG; iterate digitally only if needed.
- **Write the justification.** Every threat in the list has a one-line explanation. "Spoofing of user via password guess" is a threat; "credentials accepted without rate limiting" is the *vulnerability* that makes it tractable. Distinguish in writing.
- **Cite primary sources.** When you say "this is rate-limited per OWASP guidance," link the cheat sheet. When you say "this is T1110.004," link the ATT&CK page.
- **No theatre.** A threat list of 50 items that the analyst could not defend on a whiteboard is worse than a list of 12 they could.

## Self-grading

After each exercise, ask: *Could a senior engineer who has not seen this system follow my reasoning from the DFD to the list of threats to the prioritised register, without my speaking?* If yes, move on. If no, the gap is in the writing, not the analysis.
