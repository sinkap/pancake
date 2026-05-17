// migrations_embed.go: embeds migrations/ into the binary.
//
// Lives at fleet-server/ root because go:embed only sees siblings of the
// .go file holding the directive.

package fleetserver

import "embed"

//go:embed migrations/*.sql
var MigrationsFS embed.FS
