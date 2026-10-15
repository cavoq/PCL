# 📚 Documentation

Start with [Run PCL](QUICKSTART.md) for commands or [Policy format](POLICY_FORMAT.md)
for writing rules.

| Question | Canonical reference |
|---|---|
| 🚀 Which inputs and flags do I need? | [Run PCL](QUICKSTART.md) |
| 📝 What belongs in policy YAML? | [Policy format](POLICY_FORMAT.md) |
| ➕ Which operators and operands exist? | [Operators](OPERATORS.md) |
| 🌳 Which paths and encoding facts can I target? | [Node model](NODE_MODEL.md) |
| 🧪 How do I test a policy? | [Policy tests](TESTING.md) |
| 🏗️ Which package owns a behavior? | [Architecture](../architecture.md) |
| 🏛️ What does a standard pack cover? | [RFC 5280](../policies/RFC5280-COVERAGE.md), [RFC 4055](../policies/RFC4055-COVERAGE.md), [TR-03116](../policies/TR03116-TLS-SERVER-COVERAGE.md) |
| 📋 What changed when upgrading? | [Changelog](../CHANGELOG.md) |

## Documentation conventions

Keep one canonical description of each behavior; link to it from other pages.
Use tables for field contracts and coverage, and one working example per workflow.
Workflows use Purpose, Inputs, Command, Result, and Failure behavior in that order.
Coverage pages use Scope, a requirement matrix, Executable evidence, and Limits;
the exhaustive RFC 5280 rule ledger is also checked by tests.
Keep version-specific migrations in the changelog and source/edition metadata in
policy YAML. Preserve limits and evidence when shortening text.
Retain the project's emoji navigation, badges, and visual styling when
consolidating content; compact documentation should keep its personality.

## Testing policies

The suite format moved to [Policy tests](TESTING.md).

## Strict profile extension schemas

Canonical paths moved to the [node model](NODE_MODEL.md#strict-profile-extension-schemas).

## Migration notes

See the [changelog](../CHANGELOG.md) for upgrade guidance.
