# Original bilateral sibling sharing

A broad existing-device approval and the joining device's own broader SDK choice
remain separate live originals. A third-device enrollment creates a B/C sharing
channel only from both genuine originals, authenticated SDK roster evidence and
fresh Core guards. A/C approval alone never grants B/C permission.

The joining choice is captured before positive native continuation. Every expected
sibling has a distinct child state, the same fixed deadline and explicit synchronous
cancellation. Native C completion and native B settlement wait for their own durable
bilateral policy and the authenticated encrypted peer-commit observation. Closing,
dropping or cancelling an original cancels its children and blocked publication;
it does not revoke an already committed durable policy. Revocation is separate.

## Intake and projection recovery

MLS-authenticated controls which cannot yet enter Core authentication may be held
as negative observations under the same live original. C's buffer admits only its
exact group and known predecessor leaf, with 16 KiB wire bounds, four controls per
peer and a fixed total bound. The known original approver may have an older
in-flight control. Overflow is refused explicitly; cancellation clears the buffer.
No wire parsing, row, ACK or diagnostic counter creates a permission.

Core-authenticated source, recipient and enrollment-approval observations reject
wrong-recipient controls before attempting addressed request authentication. Pending
C controls retry the ordinary sibling, automatic and manual dispatch chain after
full Core authentication. B pending consent/proof retries remain bound to their
exact original channel nonce and source.

A transient approver control formerly stayed at the application projection head,
preventing the already retained B/C request from reaching its original. Retaining
that bounded negative control lets the rest of the batch progress; it does not
weaken authentication or create new transport identities.

## Qualification record

Frozen Git captures retain the source and underlying raw logs on macbook.m5 under
`/Users/pj/project/build/bilateral-original-sharing-*`.

| Cohort | Observation |
| --- | --- |
| v9 wrong-recipient regression | Genuine B-to-A request observed by C: behavioral RED 0/1, GREEN 1/1. |
| v23 `57b4d4fd429f745c5dc65a74d1842c600b7f5b77` | Natural fault RED: one A projection attempted 27 times; exact B request remained in a durable pending application event. |
| v24 `85ec3ef58dccb040884ce0325a4d8ae528d051cd` | Natural fault passed five serial runs. This cohort retained A correctly but changed B's retry site; it did not yet qualify full C retry dispatch. |
| v27 `aca5724d3e241a63d92feb8df78a5488e016c1c2` | Controlled actual-C-original head regression RED 0/1 (40.476 s), unchanged source hashes. |
| v28 `6d270a40f766fdeb6c2f4b4fecf8c3718a09a838` | Same regression GREEN 1/1 (14.425 s). A's actual authentication failure and later Core retry were observed; release required a genuine Core-approved expected-B channel under the same C choice. |
| v29 `cf26ac3d0079ce45096e8a602acd49e5d82ec344` | Broad App suite: 28/29 passed. The unordered head fixture failed its test-only failure-observation assertion after bilateral completion; strict/default gates had not run. |
| v30 / v31 | The first ordering barrier also failed: it waited on an unrelated natural control which could itself require B publication. These are retained fixture-dependency failures, not qualification. |
| v32 `27558116c1e0e8f2f28b875ffe345cf0d18a97a3` | A held public A-to-B action supplies the unrelated control independently. Behavioral RED 0/1 (41.478 s): the actual A projection repeated 26 times and B/C policies stayed absent. |
| v33 `9d1b6bd58e54ed5b6e21bf78845fe602beb0e03d` | Identical genuine-distractor regression GREEN 1/1 (14.574 s); checks actual A failure and later Core retry plus independent B/C completion. |

| v34 `57ad34f36338f5b4557f4c6096dcac3cdfa0e7e8` | Final test-helper context grouping: controlled 1/1, affected 12/12, default 3/3; App strict experimental/default and formatting pass. C/UniFFI experimental 9/9 and default 8/8, strict both configurations, convergence pin, actual cbindgen and documentation/parity checks pass. |

The final production inputs match v29. Later source differences are confined to
test-only publication ordering and the genuine A-to-B distractor fixture and test-helper argument grouping. The 28
passing v29 cases remain relevant; the affected sibling and native cases run again
on the final cohort. Strict checks use `-D warnings` without lint exemptions.

The controlled fixture uses real public SDK actions, a local relay and independent
stores. It checks all three durable bilateral policy counts, native completion and
encrypted confirmations. The test-only failure probe cannot approve or persist
anything. Compiler/installer failures are preserved separately and are not
behavioral REDs. This record does not establish final SDK promotion, generated
foreign-language adoption or installed three-device message delivery. Exact commands,
source hashes and raw-log hashes are in
[`original-sibling-sharing-verification.json`](../../docs/original-sibling-sharing-verification.json).
