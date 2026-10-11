# AWS IAM Policy Debugger

**Unpublished development preview.** This extension is not available in the VS Code Marketplace. Build a local VSIX from this checkout to try it.

Validate IAM JSON while you edit, explain an identity-policy access decision, and keep the expected outcome as a regression test. Everything runs locally in VS Code. No AWS credentials are required.

- Catch policy errors and security warnings as editor squiggles and Problems entries.
- See why each statement matched or failed: action, resource, and individual conditions.
- Jump from the explanation to the statement in your editor.
- Save a named scenario and choose its expected outcome.
- Discover and run `*.iam-tests.json` files in the Testing panel.
- Test current editor contents, including unsaved policy changes.

## See it in action

These are real captures of the packaged preview in an isolated VS Code profile, using disposable example policies and a fictional AWS account.

### Validate as you edit

Spot broad permissions and `iam:PassRole` on every role, with findings located on the values you need to review.

![IAM policy warnings underlined in the editor and listed in Problems](docs/images/policy-validation.png)

### Explain an access decision

Inspect each statement's action, resource and condition matches beside the policy. Save the request and its expected decision as a named scenario.

![IAM debugger explains matching statements beside the policy](docs/images/policy-debugger.png)

### Run policy regression tests

Saved scenarios appear in VS Code's Testing panel. They use current editor contents, so you can test a policy change before saving it.

![Saved IAM scenarios running in the Testing panel](docs/images/policy-scenarios.png)

### Short demo

Scope broad permissions to clear the warnings, simulate a read over TLS, then remove TLS and see the explicit Deny match.

![Demo of repairing policy findings and testing TLS access](docs/images/policy-demo.gif)

## Build and try the preview

Use Node.js 24 and VS Code 1.85 or newer. From this checkout:

```sh
fnm use
npm ci
npm run package
```

Run **Extensions: Install from VSIX** in VS Code and select `.vscode-test/iam-policy-debugger.vsix`. You can also press F5 after `npm run compile` to open an Extension Development Host with the examples workspace.

1. Open a trusted local workspace containing a standalone identity-policy JSON file. The [examples](examples/) include an uploads policy and 2 scenarios.
2. Open the policy and run **IAM: Debug Access for Current Policy** from the Command Palette. It is also available in the editor toolbar and Explorer context menu.
3. Enter a concrete IAM user/role ARN, action, resource ARN, and resource account ID. Use `aws` as the account ID for an AWS-owned ARN such as `arn:aws:iam::aws:policy/AWSLambdaExecute`. For the uploads example, use `s3:GetObject` and `arn:aws:s3:::example-uploads/photo.jpg` in account `123456789012`.
4. Supply request context explicitly, for example `{"aws:SecureTransport":"true"}`. Principal/account fields identify the scenario; they do **not** automatically populate condition keys such as `aws:PrincipalArn` or `aws:ResourceAccount`.
5. Click **Simulate access**. Expand the scope description and inspect each statement. Click a statement’s **Open** button to select its source.
6. Give the scenario a name and choose **Allowed**, **Explicitly denied**, or **Implicitly denied**. Save it, then run it in the Testing panel.

The policy must be saved before you save a scenario. Saves to the same scenario file are serialized within an extension host. Existing scenarios are preserved; duplicate names and dirty scenario files produce errors. Changing the request or policy clears the debugger result until you simulate again.

## Policy validation

Open a standalone JSON policy. Documents with a top-level `Statement` or an IAM language `Version` are recognized automatically. Findings update with unsaved edits; ordinary project JSON and `*.iam-tests.json` suites are excluded. Open documents are checked after activation, including policies opened later in the session.

Errors cover strict JSON syntax, duplicate JSON keys, required statement elements, conflicting element pairs, effects, versions, data types, ARN shape, concrete action names in the bundled catalog, condition structure, invalid condition operators, multiple Bool values, and condition keys with conflicting capitalization. Warnings cover missing versions, wildcard actions/resources, public principals, broad `iam:PassRole`, and Allow statements using `NotAction` or `NotResource`.

Validation accepts resource policies, role trust-policy structure, policy variables, and standard condition operators such as Numeric, Date and IP. The debugger supports the smaller identity-policy subset below. These are local structural and best-practice checks inspired by the [web policy validator](https://towardsthecloud.com/tools/aws-iam-policy-validator). They do not call AWS Access Analyzer or implement all its service-specific checks. A clean Problems view does not prove deployment validity or least privilege.

## What a decision means

**Allowed by this policy** means an Allow statement matched and no Deny statement matched within this one policy. **Explicitly denied** means a Deny statement matched. **Implicitly denied** means no Allow statement matched.

This is a policy-matching tool, not an effective-permissions calculation or a live AWS authorization check. It excludes other identity policies, resource policies, SCPs, RCPs, permissions boundaries, session policies, endpoint policies, service settings, and dependent actions. Cross-account authorization still requires the appropriate resource-side permissions. The supplied context is treated as a hypothetical request; the extension does not verify whether AWS would supply those keys for that action.

## Supported policy features

| Feature                | Support                                                                 |
| ---------------------- | ----------------------------------------------------------------------- |
| Identity-policy JSON   | Single statement or array; strict JSON without comments                 |
| Allow / Deny           | Explicit Deny takes precedence                                          |
| Action / NotAction     | String or array; `*` and `?`; case-insensitive                          |
| Resource / NotResource | String or array; `*` and `?`; case-sensitive                            |
| String conditions      | Equals, NotEquals, EqualsIgnoreCase, NotEqualsIgnoreCase, Like, NotLike |
| ARN conditions         | Equals, Like, NotEquals, NotLike; component-wise wildcards              |
| Boolean / existence    | Bool and Null                                                           |
| Optional keys          | IfExists for supported operators except Null                            |
| Multivalue context     | ForAnyValue and ForAllValues for String and ARN operators               |

Conditions across keys/operators use AND. Positive policy values use OR; negated values use NOR. Missing-key and empty-set behavior follows the supported AWS condition operators. Unqualified operators require a single request value; use a set operator for arrays containing multiple values. Combining set qualifiers with IfExists is not supported.

Unsupported operators (including Numeric, Date, IP, and Binary), policy variables, Principal/NotPrincipal, and malformed policy features return errors even in unmatched statements. IAM role sessions, anonymous/service principals, and actions requiring multiple required resource types are not supported. Use `*` as the request resource only for actions without resource-level permissions. The bundled MIT IAM catalog validates action names and resource types; it is a release snapshot, not a live catalog.

AWS references: [policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html), [condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html).

## Scenario format

Each scenario file contains `version: 1` and a `tests` array. The extension supplies JSON completion and validation for these files. Policy paths are relative to the scenario file and must stay inside its workspace folder.

```json
{
  "version": 1,
  "tests": [{
    "name": "Application can read uploads over TLS",
    "policy": "uploads.json",
    "expected": "Allowed",
    "request": {
      "principal": "arn:aws:iam::123456789012:role/Application",
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::example-uploads/photo.jpg",
      "resourceAccountId": "123456789012",
      "context": {"aws:SecureTransport": "true"}
    }
  }]
}
```

Context values are strings or arrays of strings. Use `"true"` / `"false"` for request boolean values. Context key names are case-insensitive; ambiguous duplicates and explicit null context are rejected. Policy Bool/Null values may also be JSON booleans.

Run all or selected scenarios from the Testing panel, or use **IAM: Run Scenarios in Current File**. Mismatches appear as failed tests; invalid or unsupported policy inputs appear as errors. The Testing panel output includes the evaluation scope.

## Development

Scaffold adapted from [AWS IAM Actions Snippets](https://github.com/towardsthecloud/vscode-iam-actions-snippets).

```sh
fnm use
npm ci
npm run compile
npm test
npm run test:integration -- 1.85.0
npm run package
```

Press F5 to launch an Extension Development Host with the examples workspace. Packaging writes `.vscode-test/iam-policy-debugger.vsix`. Integration tests unpack and execute that VSIX in an isolated VS Code profile. On Linux, run `xvfb-run -a npm test`. Reports are saved under `.vscode-test/results/`. CI tests the minimum and stable VS Code releases and produces a VSIX artifact without publishing it.

For interactive UI validation, run `IAM_UI_TEST=1 npm run test:integration -- stable`, attach `playwright-cli -s=iam attach --cdp=http://127.0.0.1:9241`, and run `playwright-cli -s=iam run-code --filename=tests/playwright-ui.cjs`. The test host waits up to 10 minutes; finish with `curl http://127.0.0.1:9242`. The UI script exercises simulation, saving, invalidation, navigation, and a narrow panel. Its screenshot and trace stay in `.vscode-test/results/`. See [capture instructions](docs/images/README.md) for the README screenshots and demo.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The policy evaluator is independently implemented. The bundled [ACT Security Labs IAM catalog](https://github.com/act-security-labs/iam-data) is MIT-licensed; its license is retained in `licenses/iam-data.txt`. No ACT simulator code is included.
