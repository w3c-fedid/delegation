# Delegation-oriented FedCM

This is a [Proposal](https://fedidcg.github.io/charter#proposals) of the [Federated Identity Community Group](https://fedidcg.github.io/) to tackle the IdP Tracking problem in Social login.

# Stage

This is a [Stage 1](https://github.com/w3c-fedid/Administration/blob/main/proposals-CG-WG.md#stage-1) proposal.

# Champions

* @samuelgoto

# Participate
- https://github.com/w3c-fedid/delegation/issues

# Background and motivation

> This is a copy/paste from this [intent-to-prototype](https://groups.google.com/a/chromium.org/g/blink-dev/c/rwu9wFl0mF4/m/MWYK64jgBQAJ?e=48417069).

[Early on](https://github.com/w3c-fedid/FedCM/blob/main/meetings/2020/The%20Web%20Platform%2C%20Privacy%20and%20Federation%20-%20TPAC.pdf), we outlined a few important problems we wanted to address in federation: first and foremost [The Classification Problem](https://github.com/samuelgoto/WebID?tab=readme-ov-file#the-classification-problem) (the fact that browsers couldn’t tell the difference between federation and tracking), and then [The RP Tracking Problem](https://github.com/w3c-fedid/FedCM/blob/main/explorations/proposal.md#the-end-state) (the release of global identifiers, such as emails) and [The IdP Tracking problem](https://github.com/w3c-fedid/FedCM/blob/main/explorations/proposal.md#the-end-state) (the bundling of presentation with issuance).

It wasn’t clear where we should start, so we looked at three different variations that had different trade-offs. We called them the [Mediation-oriented](https://github.com/w3c-fedid/FedCM/blob/main/explorations/proposal.md#the-mediated-oriented-api) model, the [Permission-oriented](https://github.com/w3c-fedid/FedCM/blob/main/explorations/proposal.md#the-permission-oriented-api) model and the [Delegation-oriented](https://github.com/w3c-fedid/FedCM/blob/main/explorations/proposal.md#the-delegation-oriented-api) model. 

We learned quickly that it was key to start from the first two variations, because they were the most backwards compatible. So, the [Mediation-oriented](https://github.com/w3c-fedid/FedCM/blob/main/explorations/proposal.md#the-mediated-oriented-api) model and the [Permission-oriented](https://github.com/w3c-fedid/FedCM/blob/main/explorations/proposal.md#the-permission-oriented-api) model materialized - after many iterations - as FedCM’s mediated account chooser and the Storage Access API (by itself, or even [in conjunction with](https://github.com/explainers-by-googlers/storage-access-for-fedcm) FedCM). A series of [heuristics](https://github.com/amaliev/3pcd-exemption-heuristics/blob/main/explainer.md) were also put in place, which covers a lot of ground too, again optimizing for backwards compatibility with the Web.

The [Mediation-oriented API](https://github.com/w3c-fedid/FedCM/blob/main/explorations/proposal.md#the-mediated-oriented-api), notably, was a great starting point because it (a) solved [The Classification Problem](https://github.com/samuelgoto/WebID?tab=readme-ov-file#the-classification-problem), (b) allowed solving the [The RP Tracking Problem](https://github.com/w3c-fedid/FedCM/blob/main/explorations/proposal.md#the-end-state) (with directed identifiers) and, importantly, (c) didn’t require any user experience or behavioral change (as opposed to the [Permission-oriented](https://github.com/w3c-fedid/FedCM/blob/main/explorations/proposal.md#the-permission-oriented-api) variation), allowing it to be deployed at large scales.

So, while the first two variations optimized for backwards compatibility (and, between them, a trade-off between performance, extensibility and ergonomics), they had an inherent privacy design weakness: [The IdP Tracking problem](https://github.com/w3c-fedid/FedCM/blob/main/explorations/proposal.md#the-end-state).

That brings us to the [Delegation-oriented](https://github.com/w3c-fedid/FedCM/blob/main/explorations/proposal.md#the-delegation-oriented-api) model, which has great privacy properties in keeping IdPs blind, but requires us to redeploy a much larger part of the ecosystem: tens of thousands of relying parties.

We are not sure yet whether the delegation-oriented model is actually within reach at this point, but a few stars aligned recently. For one, the introduction of the [issuer-holder-verifier](https://www.w3.org/TR/vc-data-model-2.0/#ecosystem-overview) architecture, together with the deployment of new token types like [SD-JWT+KB](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt), made the unbundling of issuance from presentation a lot more accessible. Zero knowledge proofs have also advanced much since we started, giving us some hope that we could solve both the RP Tracking Problem and the IdP Tracking Problem at the same time.

Asides from the new externalities introduced, the development of the Mediation-oriented variation allowed us to stand on top of a much higher foundation compared to where we started from. The last 2-3 years of production experience of FedCM across thousands of websites and millions of users required us to design a series of features and extensions (e.g. [handling logged-out users](https://github.com/w3c-fedid/active-mode), [switching accounts](https://github.com/w3c-fedid/active-mode), [extensibility](https://github.com/w3c-fedid/custom-requests), [handling multiple idps at a time](https://github.com/w3c-fedid/multi-idp), [a registration mechanism](https://github.com/w3c-fedid/idp-registration), [the pull and push model](https://github.com/fedidcg/LightweightFedCM), and [a](https://github.com/w3c-fedid/FedCM/issues/553) [series](https://github.com/w3c-fedid/FedCM/issues/552) [of](https://github.com/w3c-fedid/FedCM/pull/498) [control](https://github.com/w3c-fedid/FedCM/pull/523) [knobs](https://github.com/w3c-fedid/FedCM/issues/352)) that we can build the delegation-oriented variation from.

This is still early and ambiguous, so it is very possible it won’t go anywhere. Nonetheless, it is probably the closest that we have ever been, and close enough that it feels worth taking a shot.  [The explainer linked above](https://github.com/w3c-fedid/delegation/issues/1) has some notes of the overall idea that we’d like to start from.

# Proposal

Here is an end to end demo to give a sense of what this could look like. Instructions on how to use this [here](https://github.com/w3c-fedid/delegation/issues/1).

https://github.com/user-attachments/assets/5de77f33-66fa-4d36-9e60-793aeebe7b85

Architecturally, here is more or less what we are proposing.  We'll break down this diagram into the following sections:

* The Verifier API
* The Issuer API
  * The VC Issuance endpoint
* The Browser as a holder

```mermaid
sequenceDiagram
    participant website
    participant browser
    participant issuer
    website->>browser: Give me a signed "sub" and "name", given "nonce"
    browser<<->>issuer: Vanilla FedCM, creates an account chooser
    browser->>browser: User selects account, choosing to Sign-in
    browser->>browser: Generate ephemeral key pair
    browser->>issuer: Issue me an SD-JWT bound to public key
    issuer->>browser: Here
    browser->>browser: Selectively disclose "sub" and "name"
    browser->>browser: Bind "aud" and "nonce" with private key
    browser->>browser: Throw away private key
    browser->>website: Here is a SD-JWT-KB
    website->>website: Checks issuer's signature
    website->>website: Checks "aud" and "nonce"
    website->>website: Accepts "sub" and "name"
```

## The Verifier API

In the three party model, the Identity Provider unbundles issuance from presentation, and delegates the latter to the browser. When it chooses to break itself into two parts, we’ll call the first an Issuer (rather than an Identity Provider) that delegates presentation to the second, a Holder (the browser), a now three party model (verifier-holder-issuer) rather than the two party model (rp-idp).

The three party model is compelling because it solves the [IdP Tracking Problem](https://github.com/w3c-fedid/FedCM/blob/main/explorations/proposal.md#the-end-state): the ability to login to websites without telling the Identity Provider.

The way this is constructed is by having the browser operate as a holder. The holder has to accept presentation requests from verifiers, accept provisioning requests from issuers and ask users permission for presentation.

To do so, it has to support a specific token format (e.g. SD-JWTs, MDocs and BBS) as well as an ontology (e.g. [OIDC’s standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims), [HTML5’s autocomplete](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#attr-fe-autocomplete-name) as well as [FedCM’s profiles](https://w3c-fedid.github.io/FedCM/#dictdef-identityprovideraccount)), so that it knows how to compute the selective disclosure as well as how to ask the user’s for their permission. 

For the sake of simplicity, let me start by anchoring on [SD-JWTs](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-14.html) and OIDC’s [standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims), because that’s what’s most comparable to OIDC’s Id Tokens (which uses [JWT’s](https://en.wikipedia.org/wiki/JSON_Web_Token) \+ [standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims), making the only delta the introduction of SD \- selective disclosures \- and KB to JWTs). 

The verifier is given a new attribute, called `format`, that they can use to specify that they are looking for an `SD-JWT+KB` (rather than a traditional `idtoken` JWT):

```javascript
const {token} = await navigator.credentials.get({
  identity: {
     mode: "active",
     providers: [{
       format: "vc+sd-jwt",
       fields: ["email"], // I only need the user's email
       nonce: "5678",
       configURL: "https://idp.example/config.json",
     }]
  }
});
```

When that format is used and supported by the issuer (see below how the issuer opts-in), the verifier gets what’s called an `SD-JWT+KB`.

This is a three part token: first, a set of SD (selective disclosures), an Issuer-Signed JWT and a KB (proof of possession key binding).

```javascript
const {jwt, discloures, kb} = parseSdJwtKb(token);
```

First, the verifier gets an Issuer-signed JWT like it normally would for idtokens:

```javascript
// Jwt Header
{
  // Tells the verifier how to verify the issuer's signature
  "alg" "ES256",
  // Tells the verifier where to find the issuer's public key
  "jku": "https://issuer.example/jku.json"
  // Tells the verifier that this is an SD-JWT
  "typ": "sd-jwt",
}

// Jwt Payload
{
  // Typical JWT attributes:
  "iss": "https://issuer.example",
  // The time this was issued
  "iat": 2342342,
  // The time when this token expires
  "exp": 234342342,

  // Notably, there are two key importants things that are deliberately
  // removed:
  //
  // - The "aud" and "nonce" are missing. See KB below.
  // - The "firstName", "email", "picture" standard claims. See discloures below.

  // Instead, two other attributes do that job now:

  // First, the holder's public key, who the issuer delegates "aud" and "nonce".
  "cnf": {
    "crv": "P-256",
    "kty": "EC",
    "x": "h29tWfkCJ73nJbP51C4SotdI0CuttfQS3Svt0se6gFU",
    "y": "mBavlbiJLFhGsuIJRz7wYLiW15gpiWEDLjE1gfVh_7k"
  },

  // Second, selective disclosures digests, without the original values revealed.
  // Also, delegated to the holder to disclose.
  "_sd": [
    "6phoD5MBMETkuf5BYia7JD01dubqJSwGuz-o_9M206E", 
    "8jxEyPj9mMqJ6DQW6xiQrkyjryn77Sbuc2N44ScEGlE", 
    "D45wfxz18dwlcKeuvFppyAPl4rc-WE2Fn3f5fg3W1Ow"
  ],
  "_sd_alg": "SHA-256"
}

// Jwt Signature
"METkuf5BYi .... D5MBa7JD01du"
```

But then, in addition to the Issuer-signed JWT, the verifier gets two more things. First, a list of attributes that the user chose to disclose:

```javascript
["6403945e2c0a34a4", "firstName", "Alice"]
["06cbb1a51984f444", "lastName", "Doe"]
```

You’ll probably notice that there are three parts here to each disclosure: a randomly generated salt (e.g. `6403945e2c0a34a4`), the disclosed field’s name (e.g. `firstName`) and the disclosed field’s value (e.g. `Alice`).

The salt is used to create a random value that can be used to compute a value such that it can be included in the `_sd` property in the Issuer-signed JWT, making it hard to reverse (e.g. from the `_sd` values, a verifier can’t invert `firstName` \= Alice) but easy to verify (e.g. from `[salt, name, value]` it is easy to verify it was intended by the issuer):

```javascript
const digest = SHA256(disclosure),

// Checks if the digest is included in the Issuer-signed JWT
if (!token.jwt._sd.includes(digest)) {
  throw Error("Disclosure didn't match")
}
```

The last bit that the verifier gets is what’s called the Key Binding token. The Key Binding token is used to prevent replay attacks: the verifier’s server has to be convinced that the token that it gets was addressed to them and is recent (e.g. matches a nonce). If the Key Binding token wasn’t provided or required by the verifier, a malicious verifier could use a SD-JWT to send it to *another* verifier to "replay it" (e.g. authenticate a user in another verifier when the user intended to authenticate into the specific verifier).

To do that, the verifier gets the following KB JWT:

```javascript
// Key Binding Jwt Header
{
  // Tells the verifier how to verify the signature
  "alg": "ES256",
 
  // Tells the verifier that this is a Key Binding JWT
  "typ": "kb+jwt",
}

// Key Binding Jwt Payload
{
  "aud": "https://verifier.example",
  "nonce": "__a_verifier_provided_challenge__",
}

// Key Binding Jwt Signature
"D5MBa7JD01du .... METkuf5BYi"
```

The `aud` and `nonce` fields allow the verifier to know that the SD-JWT+KB is addressed to them.

The verifier also verifies that the signature matches the public key that was provided by the Issuer-signed JWT, so that it can’t be forged by anyone but the holder that the issuer trusted with this specific Issuer-signed JWT.

## The Issuer API

In order to hand to the verifier what it needs, the browser coordinates with a cooperative issuer (as it normally would for baseline FedCM).

As baseline FedCM, the browser carries on as it normally would, all the way into the disclosure UI, but before the browser hits the `id_assertion_endpoint`.

The `id_assertion_endpoint` reveals to the IdP who the RP is (e.g. through the CORS Origin request), so that’s a non-starter to use it as is.

### The VC Issuance endpoint

To avoid revealing to the IdP who the Rp is, we introduce an entirely new HTTP endpoint, say `vc_issuance_endpoint` (which is mostly like the `id_assertion_endpoint` except for the fact that it doesn’t tell to the Issuer who the RP is) which the IdP can opt-in to (along with the formats it can issue):

```javascript
// IdP's Config File
{
  // usual endpoints
  "accounts_endpoint":  "...",
  "id_assertion_endpoint":  "...",

  // newly introduced vc_issuance_endpoint
  "vc_issuance_endpoint":  "...",

  // newly introduced parameter: tells the browser that
  // the vc_issuance_endpoint can return VC+SD-JWTs.
  "formats": ["vc+sd-jwt"],
}
```

With this information in the configURL from a cooperating IdP, when the browser arrives at the end of the flow, it notes that the `format="vc+sd-jwt"` (rather than the default, `id_token`) was passed by the RP, informing it that it should hit the `vc_issuance_endpoint`, rather than the `id_assertion_endpoint`.

For the `vc+sd-jwt` format, the browser releases only two things to the `vc_issuance_endpoint`:

1) First, `account_id` that was selected and  
2) Second, `holder_key`, a newly constructed public key of a public/private key pair, as a JWK  
3) Third, the `format` that was requested by the RP (an enumeration of supported formats by the browser)

| Parameter name | New? | Description |
| :---- | :---- | :---- |
| `account_id` | unchanged | unique ID of the signing in user. |
| `holder_key` | **new** | A JWK, containing a public key generated by the browser to which the IDP will issue the VC. This public key is part of the issuer-signed VC payload. |
| `format` | **new** | Credential Format Identifier string. For SD-JWT, this is `vc+sd-jwt`. The default value is `jwt`. In the future, we expect to add `mdoc`, and, possibly, `bbs`. |

When the `vc_issuance_endpoint` gets this, it constructs an SD-JWT to return to the browser (by either returning a `token` or using the Continuation API).

Here is an example of what that request looks like:

```
:method: POST
:authority: issuer.example
:scheme: https
:path: /issue
content-length: 225
accept: application/json
content-type: application/x-www-form-urlencoded
origin: null
sec-fetch-site: none
sec-fetch-mode: no-cors
sec-fetch-dest: webidentity
user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9
cookie: [3333 bytes were stripped]
```

You’ll note that nowhere in this request (headers or body) does the browser tell the issuer who the verifier is.

Here is an example of what the end result might look like:

```javascript
eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpZCI6IjEyMzQiLCJfc2QiOlsiNnBob0Q1TUJNRVRrdWY1QllpYTdKRDAxZHVicUpTd0d1ei1vXzlNMjA2RSIsIjhqeEV5UGo5bU1xSjZEUVc2eGlRcmt5anJ5bjc3U2J1YzJONDRTY0VHbEUiLCJENDV3Znh6MThkd2xjS2V1dkZwcHlBUGw0cmMtV0UyRm4zZjVmZzNXMU93Il0sIl9zZF9hbGciOiJTSEEtMjU2In0.T71daVMwfh9sd_9II_Wr67BHP4shOjhJ0vvqiC8tYrvTae8XirqnizIEpUoH7lEzKV5MaAlFZ8z2Tq5IRgXNfw~WyI2NDAzOTQ1ZTJjMGEzNGE0IiwiZmlyc3RuYW1lIiwiQWxpY2UiXQ~
```

## The Browser as a Holder

When the browser gets this token, it goes over the [Fields](https://github.com/w3c-fedid/custom-requests/issues/4) that were requested and only releases the disclosures that were (a) requested by the verifier and (b) acknowledged by the user. 

The browser, in possession of the SD-JWT, returns back to the Verifier the `<Issuer-signed JWT>` and the disclosure specifically for the specific fields and the KB:

```javascript
["f3e080eb88b5f735","email","alice@example.com"]
```

Because of replay attacks, the browser also signs the KB token with the audience (for scope) and the nonce (for freshness) provided by the RP:

```javascript
{
  "aud": "https://verifier.example",
  "nonce": "5678",
}
```

Here is an example of the response that the browser would send to the Verifier as a result of JS call:

```javascript
<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~<KB-JWT>
```

The browser throws away the public/private key that it used, rather than storing it.

The website, in possession with this token, can cryptographically get a signed assertion from the IdP, while keeping the IdP blind to this entire transaction. 

Ta-da.

### The Push Model

As far as the browser is concerned, I think we could make this work equally well with the push model. I think it is awkward for IdPs who are going to have to keep the content fresh (and increase the expiration times of the credentials), but it would be equivalent to the “classic three party model”.

Here is what this could look like:

```javascript
// Stores it in the browser
await navigator.credentials.create({
  identity: {
    format: "vc+sd-jwt",
    // uses the vc_issuance_endpoint defined in vc.json to
    // issue a vc+sd-jwt ahead of a presentation request.
    configURL:"https://issuer.example/vc.json",
  }
});
```

When RPs ask for the SD-JWT+KB, the browser can use the tokens that were issued ahead of time if they  aren’t expired (and fetch a new one if they are).

## Relationship with related APIs

### Registration, Passive mode, Lightweight and Multi-IdP

The intent here is that this proposal would seemingly  integrate with other parts of FedCM, most importantly the [Continuation API](https://github.com/w3c-fedid/custom-requests), [IdP Registration API](https://github.com/w3c-fedid/idp-registration), [Passive Mode](https://github.com/w3c-fedid/active-mode) and the [Multi-IDP API](https://github.com/w3c-fedid/multi-idp).  

For example, if the Issuer wanted to get permission from the user dynamically with their own words (e.g. confirming trust in the holder) using HTML/CSS/JS they could use the [Continuation API](https://github.com/w3c-fedid/custom-requests/issues/1) before IdentityProvider.resolve() with a token.

Here is how I think all of these things come together cohesively:

At the issuer:

```javascript
// At https://issuer.com

// Tells the browser that the user is logged-in, and uses the lightweight mode to cache the accounts endpoint
// See more information at: https://github.com/fedidcg/LightweightFedCM?tab=readme-ov-file#passive-mode-or-active-mode-without-fallback
navigator.login.setStatus("logged-in", {
  accounts: [{
    name: "Sam",
    email: "goto@google.com",
    picture: "https://accounts.google.com/profile/goto/profile.jpg",
  }]
});

// Asks the user to register itself as an Issuer
// More information at: https://github.com/w3c-fedid/idp-registration
IdentityCredential.register("https://issuer.com/vc.json");

// Issues a User Info VC to the browser's holder
// More information at: https://github.com/fedidcg/LightweightFedCM/issues/56#issuecomment-2542120956
navigator.credentials.create({
  identity: {
    configUrl: "https://issuer.com/vc.json",
  }
});
```

At the verifier:

```html
<html>
<script>
// More information at: https://github.com/w3c-fedid/FedCM/issues/694
const {token} = await navigator.credentials.get({
  identity: {
     mediation: "conditional",
     providers: [{
       type: "any", // accepts User Info VCs from anyone
       format: "vc+sd-jwt", // takes SD-JWTs
       fields: ["email"], // I just need the user's verified email address
     }]
  }
});

// Got an email address from the autofill!
// Creating a user account
const account = await fetch("/create-account.php", token);

// Gets a free passkey with a conditional create
// More information at: https://github.com/w3c-fedid/FedCM/issues/671
await navigator.credentials.create({
  publicKey: {
    user: account,
    mediation: "conditional",
  }
});

</script>

Welcome to my website!

Enter your email to create an account!
<form action="/create-account.php">
  <!-- User can either enter email manually or get a verified one through FedCM -->
  <input type="email" autocomplete="email fedcm">
  <input type="submit">
</form>

</html>
```

# HOWTO

Can I play with this? Yes, instructions [here](https://github.com/w3c-fedid/delegation/issues/1).

# Open Questions

This problem has a lot of design choices that we are still trying to understand. Here are a few open questions:

## Should we use ZKPs?

I think the answer is likely "yes", but the more interesting question is "which" and "how". BBS+ comes to mind as a first thought, but we haven't explored this space enough to understand how to use it. We would appreciate guidance here.

## Should we support mDocs?

I think the answer is also likely "yes". Besides zero knowledge proofs, we also have an intuition that we should support both SD-JWTs and mDocs. We started with SD-JWTs because there was better support in our codebase, but I think both could work equally well. If you know about any of these, we would love guidance if we are using them correctly too.

## Should we extend the Digital Credentials API?

First, I think it is useful to acknowledge that this use case (Social login) could (and should) be helped by the Digital Credentials API *too*: we should encourage issuing User Info VCs to third party wallets and use them when available.

However, I think if we relied only on that we'd either (a) have a much harder ecosystem activation / bootstrapping structure, (b) have to give up on the privacy properties of the three party model or (c) re-invent FedCM.

By that I mean: in (a) if we keep the current DC structure, it will have to presuppose that User Info VCs were issued to third party wallets ahead of time with enough penetration before this verifiers can call this reliably making it harder to bootstrap the ecosystem, in (b) if we keep the current DC structure, because the DC API connects with wallets, issuers will have to be bundled with holders in the same app - if you assume that (a) is a non-starter, which defeats the privacy properties that we are looking for or in (c) if we change the current DC structure, we'd have to re-invent the FedCM endpoints in it. 

For a bit more context, architecturally, Chrome implements the Digital Credentials API as a "dumb pipe" to third party wallets where the browser plays the role of redirecting the request to third party wallets, without introspecting - by design - the request: originally, an alternative to custom schemes like `mdoc://` and `openid4vp://`. This has a lot of design advantages, because it allow an entire industry (e.g. OpenID4VP and various formats like mDocs and VCs) to innovate without asking for the browser's permission. FedCM, on the other hand, has the  browser a lot more involved with a tighter (and hopefully allowing for a better) integration (e.g. understanding and using every single bit of the request) at the cost of ossification.

Specifically, FedCM already knows (a) [whether the user is logged in](https://w3c-fedid.github.io/login-status/) to a website or not and (b) [how to login the user to a websites](https://w3c-fedid.github.io/FedCM/#show-an-idp-login-dialog) when the user is logged-out as well as (c) gather [a list of accounts](https://w3c-fedid.github.io/FedCM/#fetch-accounts) without revealing who the RP is. Digital Credentials simply routes requests to wallets, so, so far, the intuition is that we'd have to re-invent these FedCM (e.g. the algorithms above) inside of Digital Credentials if we wanted to extend it. 

From an ecosystem activation energy perspective, there are a lot of benefits of having the neutral user-agent act as a holder: issuers can register with it with a lot less friction than they would register with a third-party wallet. This isn't applicable to a lot of cases  (e.g. government-issued credentials, issuers have one-off deals with wallets enforced by regulation), but we think is likely true for social login.

So, so far, the intuition so far is that, while FedCM and the DC API operate in a similar design space, the former is a high-level API for Social login and the other is an extensible low-level API across more use cases (e.g. birth certificates, drivers licenses, passports, etc), so, co-existing much like high-level APIs (e.g. `<p>`) and low-level APIs (e.g. `<canvas>`) co-exist in various parts of the Web Platform.

We are still learning from our prototype, so we'll keep an open mind about this architectural choice as we learn more about how they relate to one another.
