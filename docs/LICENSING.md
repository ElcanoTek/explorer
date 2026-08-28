# Licensing Explorer, in plain English

Explorer is **source-available**, not open source. The licence is the
[Business Source License 1.1](../LICENSE) (BSL 1.1) — the same licence used by
MariaDB, Sentry, CockroachDB and others. This page explains what that means
in practice. **The [LICENSE](../LICENSE) file is what actually binds; this is
a reading aid, not a substitute, and it does not change the terms.**

## The short version

- The source is public. Read it, fork it, patch it, share your fork.
- Run it for anything **except production**.
- Need production use now? Buy a licence: **licensing@elcanotek.com**.
- Wait long enough and it becomes MIT — two years after the version you hold
  was published, automatically, with no action from anyone.

## The parameters

BSL is a template; a licensor fills in four blanks. Ours:

| Parameter | Value |
|---|---|
| **Licensor** | ElcanoTek, Inc. |
| **Licensed Work** | Explorer — a search interface for SES-to-S3 email archives. |
| **Additional Use Grant** | **None.** |
| **Change Date** | Two years after the version was first made publicly available. |
| **Change License** | MIT |

"Additional Use Grant: None" is the strictest setting BSL allows. Some
projects grant limited production use (e.g. "up to three servers"). We grant
none: until the Change Date, **non-production use only**.

## What you may do today

- Read, study and audit the entire source.
- Copy, modify and create derivative works.
- Redistribute it, modified or not — as long as this licence travels with it
  and is displayed conspicuously.
- **Use it non-production**: development, testing, evaluation, a proof of
  concept, CI, a demo, a security review, a local experiment against your own
  archive.
- Contribute patches (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

## What you may not do today

- **Use it in production.** Without a commercial licence, no production use of
  any kind.
- Offer it to others as a hosted or managed service.
- Strip the licence, or relicense it under terms of your own.
- Claim the Change License (MIT) before that version's Change Date arrives.
- Use ElcanoTek trademarks or logos. The licence grants no trademark rights,
  and this repository contains ElcanoTek branding assets under
  `app/static/design-system/logos/`. You may keep them where the licence
  requires attribution; do not use them to brand your own product.

Violating the licence terminates your rights **for every version**, not just
the one you misused, and terminates them automatically.

## What counts as "non-production"?

BSL 1.1 does not define the term, so read it the way a reasonable engineer
would: production is when other people, or a business, depend on the thing
working.

Comfortably non-production:

- Running Explorer on your laptop against a test bucket.
- A staging deployment used only to evaluate whether to buy a licence.
- Reading the code to learn how date-partitioned S3 scanning works.
- Running the test suite; benchmarking; writing a patch.
- A security researcher reproducing a bug.

Production, licence required:

- Your team actually uses it to search a real mail archive as part of doing
  their jobs — even internal-only, even for one person, even unpaid.
- It is deployed on infrastructure your business relies on, or is
  monitored/on-call like a service that matters.
- You embed it in a product, or host it for a client or customer.
- Anyone outside your evaluation is depending on it.

The honest test: *if it broke, would anyone be inconvenienced beyond the
person evaluating it?* If yes, that is production.

When you are unsure, ask — licensing@elcanotek.com. We would much rather
answer a question than have you guess.

## The rolling two-year Change Date

This is the part that surprises people, so precisely:

**Each published version gets its own Change Date, fixed at two years after
that version was published. The clock starts when the version ships, not when
you obtained it, and it never restarts for a copy already out in the world.**

So:

- The commit you are holding was authored on some date `D`. That version
  becomes MIT on `D + 2 years`.
- A later commit produces a *new* version with a *later* Change Date. That
  does not extend the deadline on the copy you already have.
- Waiting does not help; the two years pass anyway. A version published in
  March 2026 is MIT in March 2028 whether or not anyone touched the repo since.
- On the Change Date, that version's rights switch to **MIT** automatically —
  no announcement, no signature, no permission. Production use, commercial
  use, sublicensing: all fine, for that version.

To see the effective date for the exact code you have:

```bash
./scripts/bsl-change-date.sh
# commit:        1cdf21c (2026-06-12)
# Change Date:   2028-06-12
# Change License: MIT
```

Pass a ref to check another version: `./scripts/bsl-change-date.sh v1.2.0`.

Practically, this means yesterday's Explorer is always free software and
today's is not. If you can live two years behind, you never need to pay us.

### The four-year cap

BSL 1.1 has a backstop the licensor cannot remove. Rights convert to the
Change License on the **Change Date, or the fourth anniversary of a version's
first public distribution, whichever comes first**. Our Change Date is two
years, so it always arrives first and the cap never binds — but it is there in
the licence text, and it means no licensor using BSL can hold a version
proprietary for more than four years.

### What this is not

- Not a subscription that expires — the MIT grant, once it arrives, is
  permanent and irrevocable for that version.
- Not "open source after two years" for the *project*; it is per version.
- Not a promise about future versions. We can change the parameters (or the
  licence) for versions not yet published. We cannot change them for versions
  already out.

## Commercial licences

Email **licensing@elcanotek.com**. Tell us roughly what you want to do —
internal deployment, embedding it in a product, hosting it for clients — and
we will quote terms. Existing arrangements are also how you get production
rights on the current version instead of waiting.

## Reporting a licensing problem

If you think a file in this repository is missing a header, carries the wrong
one, or bundles third-party code whose licence conflicts with BSL 1.1, open an
issue. Third-party components we know about are listed in
[NOTICE](../NOTICE).

## FAQ

**Can I use this at work to search our company mailbox archive?**
That is production. You need a commercial licence, or you wait for that
version's Change Date.

**Can I fork it and publish my fork?**
Yes. Keep the BSL licence and the notices; your fork carries the same
restrictions, and each of your versions has its own Change Date derived from
the same rule.

**Can I sell support for Explorer?**
Selling services around software your customers are not licensed to run in
production does not work well. Talk to us first.

**Is BSL an OSI-approved open-source licence?**
No. BSL 1.1 is a source-available licence. Its Change License (MIT here) is
open source, which is why each version eventually becomes open source.

**Do I owe anything for a version that has passed its Change Date?**
No. That version is MIT — use it in production, commercially, however you
like. Note that support, fixes and new features live in newer versions, which
are still under BSL until their own dates arrive.

**I contributed a patch. Who owns it?**
You keep your copyright; you licence the contribution under BSL 1.1 to the
project, and you agree it may be relicensed under the Change License or a
commercial licence. See [CONTRIBUTING.md](../CONTRIBUTING.md).
