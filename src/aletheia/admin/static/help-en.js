// Admin panel help text (English): per-field help, per-section help, error tips and the
// basic usage documentation ("Help" view). Mirrors help.js key-for-key. Static, trusted content only.

// ---------------------------------------------------------------------------
// Per-field help ("How to fill this in" disclosure under each field)
// ---------------------------------------------------------------------------
export const FIELD_HELP = {
  "login.email": `The email address you were registered with in Aletheia. Not case-sensitive.`,
  "login.password": `At least 12 characters. If your account was created by an administrator, use the temporary
    password they gave you. After 10 failed attempts within 15 minutes, access is temporarily locked.`,
  "login.organization": `Only needed if your email belongs to more than one organization. Enter the public identifier
    (<code>org_</code> followed by 22 characters); your administrator can give it to you, and it appears at the top
    of the panel once you are signed in.`,

  "offer.template": `The template defines what data the credential carries. Only templates with a <b>published</b>
    version are listed; if the one you need is missing, publish it in <a href="#/templates">Templates</a>.`,
  "offer.holder_reference": `An identifier of <b>your own</b> to find this credential later (for example, a student
    record number). It is optional and opaque: <b>do not use email addresses or personal data</b>. Maximum 128 characters.
    <br>Example: <code>LEG-2026-00412</code>`,
  "offer.claims": `The credential data, with the fields defined by the selected template. In <b>Form</b> you fill
    them in field by field; in <b>JSON</b> you type or paste them directly (both modes stay in sync).
    The fields are listed below (those marked with * are required), and you can insert an example to fill in.
    <ul><li>Text in quotes: <code>"Ana"</code>.</li>
    <li>Numbers without quotes: <code>40</code>.</li>
    <li>Dates as <code>"YYYY-MM-DD"</code> text: <code>"2026-09-30"</code>.</li>
    <li>Yes/no: <code>true</code> or <code>false</code>.</li></ul>
    Aletheia stores this data encrypted only until the holder receives the credential; after that it is deleted.`,

  "template.slug": `Short, permanent template identifier: lowercase letters, numbers and hyphens; starts with a letter
    or number; up to 63 characters. It becomes part of the credential <b>type</b> (<code>vct</code>) and cannot be
    changed later.<br>Examples: <code>certificado-curso</code>, <code>diploma-grado</code>.`,
  "template.name": `A readable name for you and your team. Example: <code>Course completion certificate</code>.`,
  "version.claims_schema": `The fields each credential will have. In <b>Form</b>, add fields and choose their type,
    whether they are required and whether the holder can hide them (this also fills in the field below). In <b>JSON</b>
    you edit a restricted JSON Schema directly:
    <ul><li>Types: <code>object</code>, <code>string</code>, <code>integer</code>, <code>number</code>,
      <code>boolean</code> and <code>date</code> (YYYY-MM-DD date).</li>
    <li>Constraints: <code>required</code>, <code>minLength</code>/<code>maxLength</code>,
      <code>minimum</code>/<code>maximum</code>, <code>enum</code>.</li>
    <li>Up to 3 levels of nesting and 50 properties per object.</li>
    <li>Lowercase names with <code>_</code>; <code>iss</code>, <code>exp</code>,
      <code>vct</code>, <code>cnf</code>, <code>status</code> and other reserved names are not allowed.</li></ul>
    Minimal example:
    <pre>{"type": "object",
 "properties": {
   "given_name": {"type": "string"},
   "course": {"type": "object",
     "properties": {"title": {"type": "string"}},
     "required": ["title"]}},
 "required": ["given_name", "course"]}</pre>`,
  "version.selective_disclosure": `Fields the holder can <b>show or hide</b> when presenting the credential.
    Enter comma-separated paths; for nested fields use a dot: <code>course.grade</code>.
    Recommended for personal data (name, date, grade). Fields not listed here are always visible.
    <br>Example: <code>given_name, family_name, completion_date, course.grade</code>`,
  "version.validity_days": `How many days each credential is valid from issuance (1 to 3650). After that period,
    verifications return <code>invalid</code> due to expiration. Example: <code>365</code>.`,

  "policy.name": `A unique policy name within your organization. Example: <code>graduate-admissions</code>.`,
  "policy.accepted_vcts": `Credential types this policy accepts, separated by commas. Copy the <code>vct</code>
    from <a href="#/templates">Templates</a> (it appears under each template's name). Empty accepts any type,
    but at least one is required to request credentials from a wallet (OID4VP).`,
  "policy.required_claims": `Fields the presentation <b>must</b> show to be valid, separated by commas.
    Example: <code>family_name</code>. If the holder does not show them, the result is
    <code>invalid</code> (<code>required_claim_missing</code>).`,
  "policy.require_holder_binding": `Requires the presenter to prove possession of the holder's key (KB-JWT signature).
    Leave it enabled unless you have a specific reason: without it, a stolen copy of the credential would pass.`,
  "policy.issuer": `The issuer URL (<code>iss</code>) this policy trusts. For issuers hosted on
    Aletheia it has the form <code>${location.origin}/issuers/org_…</code>; your own organization's URL is in
    <a href="#/signing-keys">Signing keys</a>. An issuer is <b>not</b> trusted just because it is on Aletheia: you
    must add it here.`,

  "oid4vp.trust_policy_id": `The policy decides which issuers and credential types are accepted. Only policies
    with at least one accepted <code>vct</code> are listed.`,
  "oid4vp.claims": `Which data to request from the holder. Comma-separated paths (nested with a dot). Empty requests the
    policy's <b>required claims</b>. Request only what you need: the holder will see the list before accepting.
    <br>Example: <code>family_name, course.grade</code>`,
  "oid4vp.client_id_scheme": `How Aletheia identifies itself to the wallet:
    <ul><li><b>x509_hash</b> (recommended): request signed with the verifier's certificate; this is what
      HAIP/EUDI-aligned wallets require.</li>
    <li><b>x509_san_dns</b>: the same, identifying by the certificate's domain. Requires a domain, not an IP.</li>
    <li><b>redirect_uri</b>: unsigned request; only for wallets or tests that support it.</li></ul>`,
  "oid4vp.encrypt_response": `The wallet encrypts its response so only Aletheia can read it (recommended).
    Disable it only for wallets that do not support encrypted responses.`,

  "present.trust_policy_id": `The policy the presentation will be evaluated against. When you create the request you
    will receive a <code>nonce</code> and an <code>aud</code> that you must give to the holder to sign the presentation.`,
  "present.presentation": `The presentation the holder gave you: the full SD-JWT text, with its parts
    separated by <code>~</code> and ending with the holder's signature (KB-JWT).
    <br>Format: <code>eyJ…(credential)~WyJ…(claim 1)~WyJ…(claim 2)~eyJ…(holder signature)</code>
    <br>If you did not create a request first, the result will be <code>indeterminate</code>: without a <code>nonce</code>
    it cannot be ruled out that this is a reused copy.`,

  "member.email": `The person's email address. If they already have an Aletheia account (through another organization),
    this role is added to it; otherwise the account is created and you will see a <b>temporary password</b> that you
    must give them through a secure channel.`,
  "member.display_name": `The name the rest of the team will see. Example: <code>Ana Pérez (Registrar's Office)</code>.`,
  "member.role": `What the person can do:
    <ul><li><b>owner</b>: everything, including declaring a signing key compromised.</li>
    <li><b>admin</b>: everything except compromising keys.</li>
    <li><b>issuer</b>: issue, view and revoke credentials.</li>
    <li><b>verifier</b>: verify presentations.</li>
    <li><b>auditor</b>: read-only access to credentials, audit log and usage.</li></ul>
    There must always be at least one owner.`,

  "apiclient.name": `Which system the key is for. Example: <code>Academic SIS — production</code>. The full key
    is shown <b>only once</b>: store it in that system's secrets manager.`,
};

// Per-section help ("What is this?" disclosure)
export const SECTION_HELP = {
  offer: `An <b>offer</b> prepares a credential for a holder. Aletheia returns a <b>QR code/link</b> and a
    <b>6-digit code</b> (<code>tx_code</code>). Deliver them through <b>separate channels</b> (e.g. the QR code by
    email and the code by SMS): that way, anyone who intercepts only one cannot claim the credential. The holder
    scans the QR code with their wallet, enters the code, and the credential is stored on their phone.`,
  templates: `A <b>template</b> defines the credential type (e.g. "course certificate"). Each change creates a new
    draft <b>version</b>; once <b>published</b> it is locked and new offers use it. Credentials already
    issued do not change.`,
  policy: `A <b>trust policy</b> is the rule you verify against: which issuers you trust, which types
    you accept and which data you require. Create one for each use case (e.g. "graduate admissions").`,
  oid4vp: `Request a credential directly from the holder's <b>wallet</b>: show the QR code, the holder scans it, chooses
    to share the requested data, and the result appears here automatically. This is the standard OpenID4VP protocol.`,
  present: `An alternative without a standard wallet: create a request, give the <code>nonce</code> and <code>aud</code>
    to the holder (or their application), and paste here the presentation they return.`,
  members: `People with access to your organization's panel, and their roles. Each person signs in with their own email
    and password; never share accounts.`,
  apiclients: `Keys that let <b>other systems</b> (e.g. your academic system) use the Aletheia API without a
    person. Each key has only the permissions you select. Revoke the ones you no longer use.`,
  signingkeys: `The key your organization signs credentials with. <b>Rotating</b> it creates a new one, and the previous
    one remains usable for verifying what was already issued. <b>Declaring it compromised</b> (owner only) invalidates
    everything signed with it: use this only if you believe someone obtained the key.`,
};

// Tips shown alongside API errors
export const ERROR_TIPS = {
  invalid_credentials: "Check your email and password.",
  organization_required: "Your user belongs to several organizations: specify which one.",
  rate_limited: "Too many attempts. Wait a few minutes.",
  invalid_claims: "The data does not match the template. See the help for the “Claims” field.",
  invalid_schema: "The schema is not valid. Expand the field help to see what is allowed.",
  invalid_dcql: "The policy needs at least one accepted vct to request credentials from a wallet.",
  verifier_identity_unavailable: "The verifier certificate is missing; use “redirect_uri” or ask the operator to configure it.",
  invalid_permissions: "An API key cannot have more permissions than you, nor manage members.",
  last_owner: "The organization must keep at least one owner.",
  conflict: "An item with that name or identifier already exists.",
  forbidden: "Your role does not have permission for this action.",
  unauthorized: "Your session has expired. Please sign in again.",
};

// ---------------------------------------------------------------------------
// Basic usage documentation ("Help" view)
// ---------------------------------------------------------------------------
export const DOCS = [
  {
    id: "conceptos",
    title: "Key concepts",
    body: `
      <dl class="glossary">
        <dt>Verifiable credential</dt><dd>A signed digital document (e.g. a course certificate) that the holder
          keeps on their phone and can show to anyone they choose. Anyone can check that it is authentic and has not been
          altered or revoked, without contacting the issuer.</dd>
        <dt>Issuer</dt><dd>Whoever creates and signs the credential: your organization.</dd>
        <dt>Holder</dt><dd>The person the credential is issued to and who keeps it.</dd>
        <dt>Wallet</dt><dd>The phone app where the holder keeps their credentials.</dd>
        <dt>Verifier</dt><dd>Whoever receives the credential and checks its validity (your own organization or another one).</dd>
        <dt>Selective disclosure</dt><dd>The holder chooses which data to show. For example, they can prove they completed a
          course without showing their grade.</dd>
        <dt>Revocation</dt><dd>Cancelling an issued credential (e.g. because of an error). It is final; verifiers see it
          within minutes.</dd>
        <dt>vct</dt><dd>The credential type identifier; Aletheia creates it from the template.</dd>
      </dl>`,
  },
  {
    id: "primeros-pasos",
    title: "Getting started: issue your first credential",
    body: `
      <ol class="steps">
        <li><b>Create a template</b> in <a href="#/templates">Templates</a>: an identifier (e.g.
          <code>certificado-curso</code>) and a name.</li>
        <li><b>Create a version</b> with the credential fields and mark which ones the holder can hide. The panel
          suggests an example schema you can adjust.</li>
        <li><b>Publish</b> the version. From then on it cannot be modified (to change it, create another version).</li>
        <li>In <a href="#/credentials">Credentials</a>, choose the template, use “Insert example” and fill in the holder's
          data. Click <b>Create offer</b>.</li>
        <li><b>Deliver the QR code and the 6-digit code through separate channels.</b> The code is shown only once; if
          it is lost, use “New link”.</li>
        <li>The QR code opens a page where the holder chooses: <b>Add to Apple Wallet</b> or <b>Add to Google Wallet</b> (a
          pass with a verifiable QR code) or <b>their credential wallet</b> (OpenID4VCI, with selective disclosure). In all
          cases they enter the code.</li>
        <li>When the holder receives it in their wallet, the status changes from <span class="tag offered">offered</span> to
          <span class="tag issued">issued</span>.</li>
      </ol>`,
  },
  {
    id: "estados",
    title: "Credential statuses",
    body: `
      <table><thead><tr><th>Status</th><th>Meaning</th><th>What you can do</th></tr></thead><tbody>
        <tr><td><span class="tag offered">offered</span></td><td>Offer created; the holder has not received it yet.</td><td>New link (if the code was lost or expired) or Cancel.</td></tr>
        <tr><td><span class="tag issued">issued</span></td><td>The holder has it in their wallet.</td><td>Revoke if needed.</td></tr>
        <tr><td><span class="tag offer_expired">offer_expired</span></td><td>No one received it within the time limit (72 h by default).</td><td>Create a new offer.</td></tr>
        <tr><td><span class="tag revoked">revoked</span></td><td>Revoked or cancelled. Final.</td><td>Issue another one if needed.</td></tr>
      </tbody></table>
      <p class="muted">If the holder enters the code incorrectly 5 times, the offer is locked: use “New link”.</p>`,
  },
  {
    id: "verificar-wallet",
    title: "Verify a credential from the holder's wallet",
    body: `
      <ol class="steps">
        <li>In <a href="#/verify">Verification</a>, create a <b>policy</b>: accepted types (copy the template's <code>vct</code>)
          and required data.</li>
        <li><b>Add the issuers</b> you trust (your own organization or third parties).</li>
        <li>In “Request from a wallet”, choose the policy and click <b>Create OID4VP request</b>.</li>
        <li>The holder scans the QR code, reviews which data is requested and accepts.</li>
        <li>The result appears automatically within a few seconds, with the data the holder chose to show.</li>
      </ol>
      <p class="muted">The data shown is kept encrypted for 10 minutes; the history stores only the result, never the personal data.</p>`,
  },
  {
    id: "resultados",
    title: "What each result means",
    body: `
      <table><thead><tr><th>Result</th><th>Meaning</th></tr></thead><tbody>
        <tr><td><span class="tag valid">valid</span></td><td>Authentic, current, not revoked, presented by its holder and compliant with the policy.</td></tr>
        <tr><td><span class="tag invalid">invalid</span></td><td>Must not be accepted. The reason explains why (see below).</td></tr>
        <tr><td><span class="tag indeterminate">indeterminate</span></td><td>A decision could not be made (e.g. the revocation status could not be checked). <b>Never</b> treat it as valid; try again later.</td></tr>
      </tbody></table>
      <h3>Common reasons</h3>
      <table><thead><tr><th>Code</th><th>What happened</th><th>What to do</th></tr></thead><tbody>
        <tr><td><code>issuer_not_trusted</code></td><td>The issuer is not in the policy.</td><td>Add it if you trust it.</td></tr>
        <tr><td><code>credential_revoked</code></td><td>The issuer revoked it.</td><td>Do not accept it.</td></tr>
        <tr><td><code>credential_expired</code></td><td>Its validity period has ended.</td><td>Request a current credential.</td></tr>
        <tr><td><code>required_claim_missing</code> / <code>requested_claim_missing</code></td><td>The holder did not show a required piece of data.</td><td>Ask them to share that data.</td></tr>
        <tr><td><code>vct_not_accepted</code></td><td>It is a different credential type.</td><td>Review the policy's accepted types.</td></tr>
        <tr><td><code>presentation_replayed</code></td><td>A previously used presentation was reused.</td><td>Create a new request.</td></tr>
        <tr><td><code>signature_invalid</code></td><td>The credential was altered.</td><td>Do not accept it.</td></tr>
        <tr><td><code>issuer_key_compromised</code></td><td>The issuer's key was declared compromised.</td><td>Ask the issuer to reissue it.</td></tr>
      </tbody></table>`,
  },
  {
    id: "revocar",
    title: "Revoke or cancel",
    body: `
      <p>In <a href="#/credentials">Credentials</a>, use <b>Revoke</b> (credential already received) or <b>Cancel</b>
        (pending offer) and choose the reason:</p>
      <ul><li><code>issued_in_error</code>: it was issued in error.</li>
        <li><code>superseded</code>: it was replaced by another one.</li>
        <li><code>holder_request</code>: the holder requested it.</li>
        <li><code>policy_violation</code>, <code>key_compromise</code>, <code>other</code>.</li></ul>
      <p>It is <b>irreversible</b>. Verifications in Aletheia see it immediately; external verifiers, within at most
        5 minutes.</p>`,
  },
  {
    id: "roles",
    title: "Roles and permissions",
    body: `
      <table><thead><tr><th>Permission</th><th>owner</th><th>admin</th><th>issuer</th><th>verifier</th><th>auditor</th></tr></thead><tbody>
        <tr><td>Issue, revoke credentials</td><td>✔</td><td>✔</td><td>✔</td><td></td><td></td></tr>
        <tr><td>View credentials and templates</td><td>✔</td><td>✔</td><td>✔</td><td></td><td>✔</td></tr>
        <tr><td>Create templates</td><td>✔</td><td>✔</td><td></td><td></td><td></td></tr>
        <tr><td>Verify presentations</td><td>✔</td><td>✔</td><td></td><td>✔</td><td></td></tr>
        <tr><td>Trust policies</td><td>✔</td><td>✔</td><td></td><td></td><td></td></tr>
        <tr><td>Members and API keys</td><td>✔</td><td>✔</td><td></td><td></td><td></td></tr>
        <tr><td>Audit log and usage</td><td>✔</td><td>✔</td><td></td><td></td><td>✔</td></tr>
        <tr><td>Rotate signing key</td><td>✔</td><td>✔</td><td></td><td></td><td></td></tr>
        <tr><td>Declare key compromised</td><td>✔</td><td></td><td></td><td></td><td></td></tr>
      </tbody></table>`,
  },
  {
    id: "integracion",
    title: "Integrate another system (API)",
    body: `
      <ol class="steps">
        <li>In <a href="#/api-clients">API keys</a>, create a key with only the permissions it needs (e.g.
          <code>credentials:issue</code>). It is shown once: store it as a secret.</li>
        <li>Your system sends <code>Authorization: Bearer ak_…</code> with every request.</li>
        <li>To issue: <code>POST /v1/credentials</code> with <code>{"template": "…", "claims": {…}}</code> and an
          <code>Idempotency-Key</code> header unique per issuance (prevents duplicates if you retry).</li>
      </ol>
      <p>The full API reference is at <a href="/docs" target="_blank" rel="noopener">/docs</a> (use the
        <b>Authorize</b> button to try it with your key).</p>`,
  },
  {
    id: "seguridad",
    title: "Security best practices",
    body: `
      <ul>
        <li>Deliver the QR code and the code through separate channels; never together in the same message.</li>
        <li>Mark personal data as hideable; in verifications, request only what is strictly necessary.</li>
        <li>Keep holder binding enabled in your policies.</li>
        <li>Review the <a href="#/audit">Audit log</a> regularly and revoke unused API keys.</li>
        <li>Use <code>holder_reference</code> with internal identifiers, never email addresses or ID numbers.</li>
        <li>Rotate the signing key at least once a year.</li>
      </ul>`,
  },
  {
    id: "faq",
    title: "Frequently asked questions",
    body: `
      <details class="faq"><summary>The holder lost the 6-digit code.</summary>
        <p>In <a href="#/credentials">Credentials</a>, click “New link” on the offer: it generates a new QR code and code and
          invalidates the previous ones.</p></details>
      <details class="faq"><summary>The holder lost the phone with the credential.</summary>
        <p>Aletheia does not keep a copy of the credential (for privacy). Revoke the old one with reason
          <code>superseded</code> and issue a new one.</p></details>
      <details class="faq"><summary>Can I correct a value in an issued credential?</summary>
        <p>No: signed credentials cannot be modified. Revoke the incorrect one (<code>issued_in_error</code>) and issue another.</p></details>
      <details class="faq"><summary>Why doesn't my template appear when creating an offer?</summary>
        <p>Only templates with a <b>published</b> version are listed.</p></details>
      <details class="faq"><summary>The verification says “indeterminate”.</summary>
        <p>Aletheia could not check something it needed (usually the revocation status of an external issuer). Try again
          in a few minutes; if it persists, contact the issuer.</p></details>
      <details class="faq"><summary>What is the difference between Apple or Google Wallet and a credential wallet?</summary>
        <p>The <b>Apple Wallet</b> or <b>Google Wallet</b> pass shows all the certificate data and a QR code: whoever scans it checks
          the issuer's signature and current validity live. It is convenient, but anyone who sees the QR code sees the data, and it does not prove
          that the person showing it is the holder. A <b>credential wallet</b> (OpenID4VCI) stores the credential bound
          to a key on the phone: the holder chooses which data to show and proves it belongs to them. The Google Wallet pass
          is also stored on Google's servers.</p></details>
      <details class="faq"><summary>What personal data does Aletheia store?</summary>
        <p>Credential data only while the offer is pending (encrypted, 7 days maximum), and data
          shown in a verification for 10 minutes (encrypted). The history stores results and dates, not personal
          data.</p></details>`,
  },
];
