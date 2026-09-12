# The settings pane (server contract)

How the client's `settings` interface talks to the server, derived from its CS2 (`settings_init`,
`settings_cat_build`, `control_create`, `settings_get_state` and the row scripts) and the packet
senders in the binary. Nothing here is per-build; ids, opcodes and offsets live in the Ghidra DB and
the generated tables.

## What the client builds on its own

The pane is data-driven. `enum settings_all_categories` lists every page as a `settings_all_categories`
db row; a row's title column names the page, one column lists the sub-pages it groups and one lists
the setting structs it shows, in order. Each setting struct carries `settings_label`, `settings_desc`,
`control_type`, the slider/dropdown params (`control_min_val`, `control_max_val`, `control_enum`,
`control_dropdown_max`, `control_checkbox_inverted`) and the flags `settings_client_only`,
`settings_server_delay`, `settings_clan_system`, `settings_vis`, `settings_hide_if_disabled`,
`settings_var_reference` and `cws_id`.

The client lays out every row itself and reads each row's current value with `settings_get_state`,
which is a switch from struct to var (with a `settings_var_reference` fallback). It never writes a
var: a checkbox flips visually on click and then springs back on the next rebuild unless the server
moved the var, because the pane redraws from `onvartransmit`. So the server's whole job is: for every
row that is not `settings_client_only`, move the var the client reads for it.

## Row addressing

Rows are dynamic children of the pane's click layer. A row's child id packs the page and the row's
index on that page: `(base + page) * stride + index`, where `base` is the number of static children
the click layer already has. The server arms one slot range per page and resolves a click back to
the page's struct list from the same db rows. The value layer, the popup layer and the three number
boxes are armed separately.

## What each control sends

| `control_type` | Widget | Client → server | Server response |
|---|---|---|---|
| unset / 3 | checkbox | IF_BUTTON op 1 on the row | toggle the var |
| 4, 5 | native dropdown | IF_DROPDOWN_SELECT on the row (see `clientprot/interface.md`) | set the var to the entry value |
| 6, 7, 8 | slider | IF_BUTTON on the row (selects it), then IF_BUTTON on the value layer whose slot is the position | var = `control_min_val` + position |
| 9 | colour swatch | IF_BUTTON on the row, then IF_BUTTON on the popup layer whose slot is the palette index | var = palette index |
| 10 | button | IF_BUTTON op 1 on the row | an action (edit mode, reset colours, all beams off, jump to a page) |
| 1000-1002 | number box | IF_BUTTON on the box's display component | open a count dialog on the box's listener; the reply sets the var |
| 1, 2, 11 | title / separator | nothing | nothing |

A row whose `settings_server_delay` is set shows a spinner until the var arrives; every other row
just waits for the rebuild. Category clicks and cross-page links reach the server too (the layer is
armed) but are handled entirely client-side; the client remembers the open page in the
`settings_last_master_category` / `settings_last_category` varbits, so the server can send the
player to a page by setting those two.

## Values that are not one var

`settings_get_state` derives some rows: a bit of a shared varp (`testbit`), a pair of vars (the
combat mode is one choice spread over the legacy-combat flag and the mode var; targeting is two
flags), an enum lookup (the familiar left-click dropdowns store the enum's value while the row shows
its index), a high-contrast pair (accessibility highlight rows read one of two vars depending on the
high-contrast flag), and the warning screens (`cws_id` → a counter that counts as "shown" while it
is at or below the last-shown value). The server mirrors each of those the same way it reads them;
the mapping is in `org.projectx.core.game.settings.Settings`.
