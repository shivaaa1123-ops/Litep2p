# Dynamic Configuration Module

The **Dynamic Configuration** module enables Litep2p nodes to receive configuration
updates at runtime via specially crafted heartbeat messages. Commands encoded in
the heartbeat payload can change in-memory settings and optionally persist them
to `config.json`, ensuring that remote adjustments survive process restarts.

## Command Signature

Dynamic configuration directives must be prefixed with the signature
`LITEP2P_CONFIG`. Any heartbeat payload without this signature is ignored by the
module:

```
<normal heartbeat data> LITEP2P_CONFIG <command arguments>
```

Whitespace between the signature and the command is ignored.

## Supported Commands

| Action  | Format                                                                 | Effect |
| ------- | ---------------------------------------------------------------------- | ------ |
| `set`   | `set <dotted.json.path> <value>`                                       | Updates the value at the given JSON path. The value is parsed as JSON when possible; otherwise it is persisted as a string. Empty values default to `null`. |
| `reset` | `reset <dotted.json.path>`                                             | Removes the key located at the provided JSON path. Fails if the key does not exist. |
| `reload`| `reload`                                                               | Reloads configuration from disk, discarding unpersisted in-memory overrides. |

### Examples

```
LITEP2P_CONFIG set logging.level "debug"
LITEP2P_CONFIG set communication.udp.port 31000
LITEP2P_CONFIG set security.noise_nk_protocol.enabled true
LITEP2P_CONFIG reset communication.udp.timeout_ms
LITEP2P_CONFIG reload
```

## Persistence

- Commands default to `persist = true`, meaning updates are flushed to the
  configuration file immediately.
- `set` and `reset` commands respect a `persist=false` flag only when specified
  by the caller through the `ConfigCommand` API.
- When `persist` is true, the module delegates disk writes to
  `ConfigManager::saveConfig`. If the configuration path cannot be resolved, the
  command fails and the original state is preserved.

## Thread Safety and Validation

- `ConfigManager` now guards all configuration reads/writes with a mutex and
  exposes helper methods for setting, erasing, and snapshotting configuration
  data. This ensures dynamic updates remain race-free with existing readers.
- Path traversal only creates nested objects when necessary. Attempts to reset a
  missing path or modify invalid structures are rejected with descriptive error
  messages.
- Command parsing is conservative: unsupported verbs or malformed payloads are
  ignored, and well-formed commands return detailed success/failure messages.

## Initialization & Usage

1. Construct a `DynamicConfigurationManager` instance.
2. Call `initialize(ConfigManager*, std::string config_path)` with the active
   `ConfigManager` singleton and the absolute path to `config.json`.
3. Feed inbound heartbeat payloads into `processHeartbeatMessage`. If a command
   is present, the method returns a `CommandResult` describing the outcome.
4. Optionally register observers with `addObserver` to react to configuration
   changes (e.g., refresh cached subsystems).
5. Use `reloadFromDisk` to restore the baseline configuration manually.

The module is currently packaged as a standalone component. Runtime integration
with the heartbeat dispatcher should be performed once the surrounding pipeline
is ready to consume the new behavior.
