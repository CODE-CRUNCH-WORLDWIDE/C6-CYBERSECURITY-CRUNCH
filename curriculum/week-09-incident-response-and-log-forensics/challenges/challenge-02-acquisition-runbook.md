# Challenge 2 — Write a Memory-Acquisition Runbook for Your Own Laptop

> Estimated time: 90-120 minutes.
> Prerequisite: Lecture 3 read; the LiME and AVML READMEs skimmed.
> Output: a runbook in this file's Appendix A that an analyst could execute against your own laptop (or a VM you own) to acquire memory, hash the image, and update the chain-of-custody log.

---

## Why this challenge

A runbook is the difference between a procedure that works at 02:47 in the morning and a procedure that fails because someone has to read documentation under pressure. Memory acquisition is the procedure most often skipped in small environments because no one wrote the runbook before the incident. This challenge produces the runbook your future self will reach for.

The runbook lives in a Git repository, is reviewed by peers, is tested on a tabletop, and is read aloud by the incoming on-call at the start of every shift. The version you write here is the seed; in a real environment the team would iterate on it.

---

## Authorised use

The runbook you write is for **your own laptop, or a virtual machine you own**. Memory acquisition is the most invasive read possible against a system — it captures keys, credentials, decrypted document contents, and the contents of every running process. Running the runbook against a system you do not own is a CFAA / SCA / CMA / 2013/40/EU violation. Read the README banner before you begin.

If you do not own a Linux laptop or a VM you can use, run the runbook end-to-end on a free-tier cloud VM that you spin up specifically for the exercise. AWS, GCP, Azure, and Hetzner all offer credentials that cover a single-vCPU VM for the duration of the exercise. Destroy the VM and the captured image immediately after the exercise; the captured image contains your credentials.

---

## Task

Produce a runbook with the following sections. Each section is required.

### 1. Preconditions

A bulleted checklist the responder confirms before starting acquisition. Examples:

- Is the host in scope of the authorisation? (Reference the engagement letter ID or, for this exercise, "exercise authorisation: my own laptop / my own VM").
- Is `AVML` (or `LiME`) on the responder's jump kit? Hash and version recorded?
- Is there enough free disk space for the dump (host RAM size plus 10% overhead)?
- Is there a path to write to that is not on the affected host's primary disk (USB drive, network share)?
- Is there a writable, signed Git repository for the chain-of-custody log?

### 2. Acquisition commands

The exact command sequence to acquire the memory image, in the order to run it. Use the commands from Lecture 3 §§ 3 and 4. Annotate every command with what it does and what could fail.

### 3. Immediate post-acquisition

Hashing, custody-log update, and verification. Use Exercise 4's `exercise-04-custody-log.py` to populate the custody log; cite the exact invocation.

### 4. Transfer

How the image is moved from the affected host to the analysis host, with the integrity check at each step. Use `scp` for the lab; in a production environment the team would use a method that does not pass through ephemeral storage.

### 5. Storage at the analysis host

Where the image is stored, with what permissions, and for how long. Cite a retention policy.

### 6. Verification

A re-verification command sequence the analyst runs immediately before opening the image in Volatility 3. Defends against the "the disk got swapped during transfer" failure mode.

### 7. Volatility 3 plugin baseline

The minimal set of Volatility 3 plugins to run against the image immediately, with the output written to a structured directory. See Lecture 3 § 5.1 for the canonical baseline.

### 8. Rollback / abort

What the analyst does if the acquisition fails partway. Specifically:

- If `AVML` fails with a non-zero exit code, what is the next step?
- If the SHA-256 of the dump does not match between the source and the analysis host, what is the next step?
- If the analyst realises mid-acquisition that they are running against the wrong host, what is the next step?

---

## Validation rubric

A runbook is good if it satisfies all of:

- **Every command is copy-paste runnable.** No `<placeholder>` left unresolved. Where a placeholder is unavoidable (the engagement letter ID, the hostname), make the placeholder explicit and surrounded by clear delimiters.
- **Every command has an annotation.** What does it do; what could fail; what does the responder do if it fails.
- **Every artefact has a destination.** The dump file, the custody-log entry, the Volatility output. The runbook says where each lives by the end of the procedure.
- **The chain-of-custody integration is explicit.** The runbook does not leave the custody-log update as a "do this too"; it lists the exact `exercise-04-custody-log.py` invocation.
- **The legal frame is restated.** The runbook's preamble includes a one-paragraph "this runbook may only be run against authorised targets" statement.

---

## Stretch — automate it

Wrap the runbook's commands into a single shell script `acquire-memory.sh` that:

- Accepts the target hostname, the authorisation reference, and the operator's name as positional arguments.
- Refuses to run if `/etc/machine-id` is not present (an unsafe target).
- Logs every command to a transcript file alongside the dump.
- Exits non-zero if any step fails, with a structured error code per step.

Test the script end-to-end against your own laptop or a VM you own. Commit the script alongside the runbook.

---

## Deliverable

Commit the completed runbook to Appendix A of this file. The runbook should be roughly 100-200 lines long; longer than that becomes hard to read under pressure, shorter than that usually skips a required step.

---

## Appendix A — Your runbook

```markdown
# Memory-acquisition runbook (target: <my laptop / my VM>)

## Preconditions

- [ ] Target in scope: <reference>
- [ ] AVML present at /path/to/avml; version <X.Y.Z>; SHA-256 <hash>
- [ ] Free disk space on target: <command> shows <N> GB free; required <M> GB
- [ ] Writable destination: <path>
- [ ] Custody-log repository: <git remote>; current HEAD <hash>

## 1. Acquisition

```bash
# <command 1, with annotation>

# <command 2, with annotation>

# ...
```

## 2. Immediate post-acquisition

```bash
# Hash the dump (sha256 + md5).
sha256sum <path/to/dump.lime> | tee <path/to/dump.lime.sha256>
md5sum    <path/to/dump.lime> | tee <path/to/dump.lime.md5>

# Update the custody log.
python3 .../exercise-04-custody-log.py generate ...
```

## 3. Transfer

```bash
# <command sequence with integrity check>
```

## 4. Storage

- Path on analysis host: <path>
- Permissions: <octal>
- Retention: <policy>

## 5. Verification before analysis

```bash
# <command sequence>
```

## 6. Volatility 3 baseline

```bash
# <plugin invocations>
```

## 7. Rollback / abort

- If acquisition fails: <action>
- If hash mismatch: <action>
- If wrong host: <action>

## Legal frame

> This runbook may be executed only against systems for which the operator
> holds a current, written authorisation to acquire memory. ...
```

---

## Self-check before commit

- [ ] Appendix A is populated end-to-end.
- [ ] Every placeholder is either resolved or clearly marked for the responder to fill in at run time.
- [ ] The legal-frame paragraph is present.
- [ ] The runbook's command count is between 15 and 40 (longer suggests redundancy; shorter suggests omission).
- [ ] You have actually run the runbook against your own laptop or a VM you own, end-to-end. Commit a transcript of the run as `runbook-transcript.txt` alongside the runbook.

When all five are true, commit. There is no reference solution for this challenge; the runbook you write is correct if it produces the correct artefacts when executed.
