# Changelog

## 0.1.2

- Publish releases with GitHub Trusted Publishing.

## 0.1.1

- Remove the duplicate README icon and place the CloudBurn tip after the introductory feature list.
- Remove maintainer development and publishing instructions, and the outdated extension-pack announcement, from the README.

## 0.1.0

- Reject malformed IAM and template inputs before simulation, and keep editor findings consistent with supported policy behavior.
- Preserve the latest discovered scenarios during overlapping refreshes and runs; report empty suites as errors.
- Retain integration-test reports and editor logs while cleaning temporary profiles.
- Add Numeric, Date and IPv4/IPv6 conditions and IAM policy variables.
- Select and validate policies inside CloudFormation and Terraform, with explicit reference values.
- Preserve embedded policy selections in saved scenarios and run them in CI with the CLI.
- Add the matching IAM icon and links to the companion IAM extensions and all three packs.
- Add local IAM identity-policy request debugging with statement and condition explanations.
- Add live IAM policy validation with editor squiggles and Problems entries for structural errors and broad-permission warnings.
- Add source navigation and result invalidation when the request or policy changes.
- Save regression scenarios and run them through VS Code’s Testing panel.
- Add scenario JSON validation, example policies, packaged-extension tests, and CI.
- License the extension under Apache-2.0, using the MIT IAM catalog.
