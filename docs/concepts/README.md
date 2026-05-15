# Concepts

This folder is the terminology baseline for `jw-guard`.

The files here are stricter than the draft documents. Drafts may contain
useful examples, project preferences, or platform-specific opinions. Concepts
must define the language needed to express those opinions without embedding
them as universal rules.

Read in order:

1. `00-terminology.md` - locked words and their intended meaning.
2. `01-fundamental-form.md` - the minimum abstract form of a security model.
3. `02-minimum-atoms-and-declarations.md` - the smallest type atoms and
   declaration objects needed for that form.
4. `03-deterministic-concretisation.md` - how declarations become canonical
   model referents and how observations are compared without hidden judgment.
5. `04-loop-control.md` - deterministic control-loop gate for Goal/State/Loop/Mayrun.
6. `05-l1-type-definition.md` - deterministic Layer-1 type definition over L0 atoms.
7. `06-l2-typegate.md` - deterministic Layer-2 type-theory gate for composition.
8. `07-l3-type-definition.md` - provisional Layer-3 graph/reference semantics candidate (pending abstraction strategy).
9. `08-l4-type-definition.md` - provisional Layer-4 normative semantics candidate (pending semantics decision).
10. `09-type-axis-detectability.md` - locked L1-L2 detection and foundational deconstructability helper.
11. `10-graph-primitives-axis.md` - first-principles atomic graph axis for abstraction decisions.

## Core Principle

Security is the typed restriction of permitted relations across declared
boundaries.

A security model is therefore not just topology and not just policy. It is a
policy-bearing graph of typed referents, boundaries, surfaces, edges, and actors.

## Authority Rule

When a draft conflicts with these concept documents, these concept documents
win until deliberately revised.

When Rust code conflicts with these concept documents, either the code is wrong
or the concept document is incomplete. The correction must preserve the
distinction between neutral vocabulary and project-specific policy opinion.
