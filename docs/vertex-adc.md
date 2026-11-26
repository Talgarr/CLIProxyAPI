# Vertex AI with Application Default Credentials

Vertex ADC authenticates Gemini requests with Google OAuth access tokens. It
does not require a Google API key or a service-account private key. Credentials
use the existing `vertex` provider, auth store, model catalog, namespaces, and
request translation, including streaming and token counting.

## Browser login

Install the Google Cloud CLI, enable the Vertex AI API in your resource project,
and run:

```sh
./cli-proxy-api -config config.yaml -vertex-adc-login \
  -vertex-adc-project YOUR_PROJECT -vertex-adc-prefix vertex
```

This invokes `gcloud auth application-default login`, validates a token, and
saves a Vertex credential in the configured auth directory. Use `-no-browser`
to pass `--no-launch-browser` to gcloud. gcloud owns Google's browser and MFA
flow; CLIProxyAPI does not implement a separate Google OAuth client.

For keyless service-account impersonation:

```sh
./cli-proxy-api -config config.yaml -vertex-adc-login \
  -vertex-adc-project YOUR_PROJECT -vertex-adc-prefix vertex \
  -vertex-adc-impersonate-service-account agent@YOUR_PROJECT.iam.gserviceaccount.com
```

Your user needs Service Account Token Creator on the service account. The
identity making Vertex requests needs Vertex AI permissions, such as Vertex AI
User, in the resource project. Organisation policies and login requirements
continue to apply.

## Existing ADC

If ADC is already configured, gcloud is not required by CLIProxyAPI:

```sh
gcloud auth application-default login

./cli-proxy-api -config config.yaml -vertex-adc \
  -vertex-adc-project YOUR_PROJECT -vertex-adc-prefix vertex
```

Google's standard discovery checks `GOOGLE_APPLICATION_CREDENTIALS`, the local
ADC file, then an attached Google Cloud service account. User ADC and impersonated
ADC JSON are supported without a `private_key` field. Google's auth library also
handles external-account/federation credentials; referenced subject-token files,
executables, or identity endpoints must remain available on the runtime host.
Import only credential configurations you trust.

To select an explicit ADC file:

```sh
./cli-proxy-api -config config.yaml -vertex-adc \
  -vertex-adc-file /private/application_default_credentials.json \
  -vertex-adc-project YOUR_PROJECT -vertex-adc-location us-central1 \
  -vertex-adc-prefix vertex
```

An explicit resource project is necessary for user ADC, which usually contains
only a quota project. `-vertex-adc-location` defaults to `global`. A resource
project embedded in ADC can be used when `-vertex-adc-project` is omitted.

Do not combine `-vertex-adc-login` with `-vertex-adc-file` or
`GOOGLE_APPLICATION_CREDENTIALS`: gcloud creates credentials in its own default
location. Use `-vertex-adc` to register an existing file instead.

## v8 Management API import

You can also upload a Vertex ADC JSON file through the v8 management API:

```sh
curl -X POST "http://127.0.0.1:8317/v8/management/oauth/import?provider=vertex" \
  -H "Authorization: Bearer YOUR_MANAGEMENT_KEY" \
  -F "file=@/private/application_default_credentials.json" \
  -F "project_id=YOUR_PROJECT" \
  -F "location=global" \
  -F "prefix=vertex" \
  -F "quota_project_id=YOUR_QUOTA_PROJECT"
```

Non-`service_account` JSON uploads (such as `authorized_user` or
`impersonated_service_account`) are automatically validated and registered as
ADC credentials; set `auth_mode=adc` to import a `service_account` JSON as ADC.
See [v8 Management API](management-api-v8.md) for endpoint details.

## Quota, storage, and refresh

`-vertex-adc-quota-project` overrides `GOOGLE_CLOUD_QUOTA_PROJECT` and ADC's
`quota_project_id`, in that order. This value is sent as `X-Goog-User-Project`
on Vertex requests and is separate from the resource project (an explicit custom
`X-Goog-User-Project` header still takes precedence). The calling identity may
need Service Usage Consumer permissions in the quota project.

File-backed ADC is copied into a private auth record (mode `0600`) so it works
with the same persistence backends as other logins. It includes sensitive refresh
credentials; protect the auth directory and its backups. gcloud is not needed
for runtime refresh. Attached-account ADC is saved as `use_adc: true` instead
and is rediscovered on the runtime host; it is not a portable login.

The executor caches access tokens in memory and reacquires expired tokens using
Google's library and the credential/global proxy. Request-specific execution
proxies are not used for OAuth token exchange. Access tokens are not written to
the auth store. To change an imported login, register the new ADC and remove or
disable its previous credential if the identity changed.

Start the server normally after registration and select a published model such
as `vertex/gemini-2.5-flash`. Model access depends on your project and location.
Token validation during registration does not prove Vertex IAM permissions or
model availability; verify with an inference request.

Google references:

- [Vertex AI authentication](https://cloud.google.com/vertex-ai/generative-ai/docs/start/gcp-auth)
- [Local ADC and impersonation](https://cloud.google.com/docs/authentication/set-up-adc-local-dev-environment)
