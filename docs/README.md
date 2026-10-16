# vmkit documentation

The [top-level README](../README.md) covers what vmkit is, its status, a quick start, the architecture (components, VM lifecycle, network model, isolation layers), the API, requirements, the kernel and the tests.

| Document | Contents |
|---|---|
| [sandbox-helper.md](sandbox-helper.md) | How `vmkit-sandbox` works: the plan file, the `run`, `userns` and `init` stages, their handshake, root construction and the nested user namespace. |
| [superpowers/plans/2026-10-06-vmkit-sandbox-exec.md](superpowers/plans/2026-10-06-vmkit-sandbox-exec.md) | The implementation plan that turned the VMM-only sandbox into the general program sandbox (`vmkit::sandbox::spawn`), with its constraints and task list. Kept as a historical record; the code is authoritative where they differ. |

Related design documents live in the sibling repositories: [kiln](https://github.com/AlfonsoCampodonico/kiln) (VM layer requirements, kernel profile, guest network) and [potter](https://github.com/AlfonsoCampodonico/potter) (build sandbox requirements).
