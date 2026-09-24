## TUI integration boundary

`Model` keeps all terminal state and emits Bubble Tea commands. It does not
perform network, filesystem, process, service, or PATH operations directly.

The controller boundary used by the model is:

```go
type Controller interface {
    Start(context.Context, OperationRequest) (<-chan OperationEvent, error)
    OpenConfigFields(context.Context, ConfigFieldsRequest) (ConfigFieldsResult, error)
}

// Production controllers should also implement the typed provider boundary.
type ProviderWizardController interface {
    OpenProviderWizard(context.Context, ProviderWizardRequest) (ProviderWizardResult, error)
}

func NewModel(config ModelConfig) *Model
func Run(model *Model, options ...tea.ProgramOption) error
```

`OperationStagePackage` is sent immediately after the source, release, and
three installation roots are chosen. Its completed event must contain a
`StagedPackage` with `Verified=true`; this is the only package accepted by the
later `OperationInstall` request. The storage page then opens
`OpenConfigFields` with prefix `storage`, followed by provider prefixes
`llm`, `embedding`, and `rerank` for the advanced editor. The provider shortcut
uses `OpenProviderWizard` and the verified provider catalog. It collects typed
provider, endpoint, model, embedding dimension, rerank priority/enabled state,
API-key environment names, and an optional new secret. `InstallPlan.Providers`
carries the typed routes and protected `CredentialUpdates`. The secret is held
only until the controller writes the protected `.env` transaction, is masked in
every rendered view, and is never returned in a catalog result or summary.
The advanced `ConfigField` values are still edited in the TUI and copied into
`InstallPlan.ConfigFields`; the TUI does not invent or rename schema paths.

For PostgreSQL and ParadeDB, `InstallPlan.StorageSettings` contains
`PostgreSQLDSNVariable`, `PostgreSQLDSNValue`, and
`PostgreSQLCredentialPath`. The YAML editor must write only
`${PostgreSQLDSNVariable}` to `postgres.dsn`; the raw value is a protected
credential input and must be written to the selected `.env` atomically. An
empty value is valid only when `PostgreSQLCredentialConfigured` is true and the
variable reference and credential path are unchanged. Never include the raw
DSN in status, errors, summaries, or logs.

`Start` is a stream so download/install/service operations can report progress
without blocking `Update`. The controller owns cancellation and cleanup; the
TUI only sends a context cancellation when the user presses `Esc` during an
active operation. `OpenConfigFields` is a synchronous schema snapshot hook,
not a filesystem editor: it returns authoritative paths, editability, and
masked values, while the controller applies the final `InstallPlan`.

`InstallPlan.ServiceUser` is the explicitly confirmed local account used by a
Linux or macOS system service. The command layer may prefill
`ModelConfig.Defaults.ServiceUser` from the current local account; the TUI
displays that value and requires Enter confirmation before continuing. The TUI
never derives it from `SUDO_USER`, and Windows hides and clears this field.

The model constructor also accepts an initial `InstallationSnapshot`, so the
CLI can decide whether to enter first-install or installed navigation after its
own non-TTY and filesystem checks.

Every edit that changes `InstallPlan` invalidates the previous VMM validation.
The TUI will not enter confirmation or issue `OperationInstall` until a fresh
successful `OperationValidate` event marks the current plan valid.
