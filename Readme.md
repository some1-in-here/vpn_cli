# vpn_cli

A CLI tool for VPN server management. Currently only WireGuard is ready; OpenVPN support may be developed in the future.

## Usage

```
vpn_cli [--app-config-path <path>] <command>
```

## Commands

| Command | Description |
|---------|-------------|
| `add-user <username>` | Add a new user |
| `delete-user <username>` | Delete a user and remove their peers |
| `enable-user <username>` | Enable a disabled user |
| `disable-user <username>` | Disable a user (removes from config) |
| `allocate-ip <username> [-o <path>]` | Allocate an IP, optionally write client config to file |
| `deallocate-ip <username>` | Deallocate IP from a user |
| `list-users` | List all users with IPs and status |
| `generate-config-example [<path>]` | Generate a sample config file |
| `export-peer by-ip <ip>` | Export peer config by IP |
| `export-peer by-public-key <key>` | Export peer config by public key |
| `export-user <nickname> -o <dir>` | Export all client configs for a user |

## Configuration

Default config path: `./vpn_cli.json`. Generate an example with `generate-config-example`.

Supports SQLite database and WireGuard or OpenVPN backends.
