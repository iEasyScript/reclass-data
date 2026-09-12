# Mobile Lobby + World Interface Set (949-1)

Decoded from a live **RS3 Android** login capture
(`data/client/android/captures/mobile-official-lobby-world-login/packets.jsonl`), which the injected
sniffer decoded through the mobile client's own 949-1 ServerProt table. Opcodes here are the same
949 wire opcodes the desktop server uses; names + sizes come from
`core/.../net/prot/revision/rev949/Rev949ServerProtStubs.kt`, and wire fields were decoded per the
rev949 encoders (`Rev949ServerCodecs*.kt`) against `world.gregs.voidps.buffer` transforms.

Every id below is resolved to its gameval dev-name via `re-resources/gamevals/gameval.py`. Component
hashes are `(interfaceId << 16) | componentId`.

Windows (single character, character "Yehp"):
- **Lobby set** — s2c `102.9s ≤ t < 109.4s` (after lobby login-success). Top = `lobbyscreen`.
- **World set** — s2c `t ≥ 109.4s` (world burst at `t≈113–114s`). Top = `toplevel_v2`.

Both tops are **identical to desktop** (`lobbyscreen` / `toplevel_v2`). Mobile is not a different
top-level interface — it is the desktop frame plus a mobile overlay container and a handful of
child substitutions.

---

## 1. MOBILE LOBBY

- `IF_OPENTOP` → `lobbyscreen` (906)
- `RESET_CLIENT_VARCACHE` before the varp/varc dump; no `STORE_SERVERPERM_VARCS_ACK` in the lobby.
- 19 `IF_OPENSUB` placements (all `type/layer = 1`, all parent = `lobbyscreen`), in wire order:

| # | child interface | parent slot (component) | slot id | vs desktop |
|---|-----------------|-------------------------|--------:|------------|
| 1 | `lobbyscreen_pane_playerinfo` | `playerinfo_panel` | 44 | shared |
| 2 | `lobbyscreen_pane_worldselect` | `worldselect_panel` | 45 | shared |
| 3 | **`lobbyscreen_pane_mobile_social`** | `friendslist_panel` | 46 | **MOBILE — replaces desktop friendslist+clanchat+friendschat** |
| 4 | `lobbyscreen_pane_options` | `options_panel` | 49 | shared |
| 5 | `lobbyscreen_report_abuse_stage1` | `report_abuse_stage1` | 144 | shared |
| 6 | `lobbyscreen_report_abuse_stage2` | `report_abuse_stage2` | 145 | shared |
| 7 | `lobbyscreen_report_abuse_ignore` | `report_abuse_ignore` | 146 | shared |
| 8 | `lobbyscreen_mobile_side_menu` | `mobile_sidemenu` | 154 | shared (already `MOBILE_SIDE_MENU`) |
| 9 | `lobbyscreen_evalid` | `email_validation` | 148 | shared |
| 10 | `lobbyscreen_u13` | `under_13` | 149 | shared |
| 11 | `lobbyscreen_windowmode_confirm` | `windowmode_confirm` | 100 | shared |
| 12 | `lobbyscreen_pvp_warning` | `pvp_warning` | 101 | shared |
| 13 | `lobbyscreen_input` | `input` | 99 | shared |
| 14 | `lobbyscreen_popup` | `popup` | 151 | shared |
| 15 | `lobbyscreen_logout_warning` | `logout_warning` | 147 | shared |
| 16 | `preload_cache` | `preload_cache` | 51 | shared |
| 17 | `lobbyscreen_clock` | `clock` | 139 | shared |
| 18 | `minimenu` | `minimenu_layer` | 171 | shared |
| 19 | `lobbyscreen_mobile_billing_info` | `mobile_billing_info` | 140 | shared (already `MOBILE_BILLING_INFO`) |

### Lobby IF_SETEVENTS

4 events, all on `lobbyscreen_pane_playerinfo` (child hash `lobbyscreen_pane_playerinfo` = 907),
components `139 / 143 / 142 / 165` (message-of-week + three bottom graphic layers), `settings =
`<in Ghidra DB>` (right-click option 0), slot 0..0 — same block as desktop `LOBBY_SETEVENTS_COMPONENTS`.

### Lobby vars

- **VARP** — 3212 packets (full serverperm varp cache; every id resolves to a gameval `var_player`
  name). Standard RS3 account-state dump, not mobile-specific.
- **VARC** (meaningful, gameval-named):
  `lobby_straight_through=0`, `lobby_is_jpp_account=1`, `last_clanchannelowner_init=1`,
  `last_clanchannelowner_attempttorejoin=2`, `toplevel_v2_skins_temp_varc=4096`,
  `mtxmgt_total_runecoins=294`, `mtxmgt_total_loyaltypoints=657000`, `wof_rsspintoken_balance=150`,
  `mtxmgt_total_tradeable_bonds=0`, `mtxmgt_total_untradeable_bonds=0`, `lobby_currency_th_keys=0`,
  `player_coord=56495750`.
- **VARCSTR** — `last_clanchannelowner="Yehp"`.

  These match the desktop `LobbyScreen.kt` varc block one-for-one.

### Lobby RUNCLIENTSCRIPT (op82), in order

- `7486`(i,i) ×2 — clock/timer setup (`lobbyscreen_clock:time`, `worldselect:time_current`).
- `10931`(i,i,i,i,s,s,s,s,i) ×12 — lobby news entries (slot, graphicId, category, -1, title, summary,
  slug, date, 0). Same script + arg shape as desktop `LOBBY_NEWS`.
- `10936` — lobby subif-visibility / news-end.

Note: the live mobile capture did **not** include `3060` (`lobbyscreen_tabswitch`) or `1299`
(`lobbyscreen_load`) that desktop `LobbyScreen.kt` sends; only the three scripts above appeared.

### Lobby diff vs desktop (`LobbyInterface` / `LobbyScreen.kt`)

- **Drops** the three separate desktop social panes: `lobbyscreen_pane_friendslist` (FRIENDS_LIST),
  `lobbyscreen_pane_clanchat` (CLAN_CHAT), `lobbyscreen_pane_friendschat` (FRIENDS_CHAT).
- **Adds** one consolidated `lobbyscreen_pane_mobile_social` (id 1044) into the **`friendslist_panel`**
  slot (46) — the mobile social pane replaces all three.
- Everything else (order + slots) is identical. `MOBILE_SIDE_MENU` and `MOBILE_BILLING_INFO`, already
  present in `LobbyInterface`, are confirmed live.

**Mobile lobby = desktop lobby with `{friendslist, clanchat, friendschat}` → `mobile_social`.**

---

## 2. MOBILE WORLD

- `IF_OPENTOP` → `toplevel_v2` (1477) — same as desktop.
- `RESET_CLIENT_VARCACHE` first; `STORE_SERVERPERM_VARCS_ACK` ×2 during the burst.
- 61 distinct `IF_OPENSUB` placements (`type/layer = 1`). Mobile opens the **entire** desktop
  `toplevel_v2` window set (gameworld, stats, inventory, worn, prayer, all ability books, friends,
  friendschat, clan, emotes, music, notes, group, telemetry, droplog, questlist, cheevo tracker/paths,
  ribbon, ribbon_extra, event_crafting, chat, minimenu, gravestone, statusicons, buff/debuff bars,
  xp_popup, parent tabs, targeting, status_effects, ragdoll tooltip, slayer_count) **plus** a mobile
  overlay container.

### Mobile-only placements (not in desktop `GameInterface`)

| child interface | parent slot | tag |
|-----------------|-------------|-----|
| `toplevel_v2_mobile` (276) | `toplevel_v2:mobile_toplevel` (687) | mobile container pane |
| `mobile_settings_button` (1376) | `toplevel_v2_mobile:settings_mobile` (16) | hosts minimap/compass/run-energy |
| `mobile_ribbon_left` (279) | `toplevel_v2_mobile:mobile_ribbon_left` (14) | |
| `mobile_chat_panel` (857) | `toplevel_v2_mobile:chat_panel` (27) | |
| `mobile_chat_overlay` (229) | `toplevel_v2_mobile:chat_panel_overlay` (28) | |
| `inv_drop_areas` (577) | `toplevel_v2_mobile:inv_drag_options_window` (18) | |
| `toplevel_v2_combat_bar_mobile` (1923) | `toplevel_v2_mobile:combat_bar_mobile` (9) | |
| `toplevel_v2_combat_bar_mobile_buttons` (1924) | `toplevel_v2_mobile:combat_bar_mobile_2` (22) | |
| `toplevel_v2_combat_bar_mobile_revo` (1925) | `toplevel_v2_combat_bar_mobile_buttons:revo_layer` (1924:182) | nested under 1924 |
| `toplevel_v2_run_energy` (326) | `mobile_settings_button:run_energy_layer` (1376:21) | |
| `crm_braze_login_popup` (1281) | `toplevel_v2:fullmodal_window_background` (726) | Braze marketing popup |

### Changed placements (same purpose, different child or parent than desktop)

| child interface | mobile slot | desktop `GameInterface` |
|-----------------|-------------|-------------------------|
| `toplevel_v2_minimap` | `mobile_settings_button:minimap_layer` (1376:22) | `toplevel_v2:minimap_window_content` |
| `toplevel_v2_compass` | `mobile_settings_button:compass_layer` (1376:20) | `toplevel_v2:minimap_layer` |
| `escape_menu_mobile` (274) | `toplevel_v2:floater_layer` (805) | desktop child = `escape_menu` |
| `clock_time` (1233) | `toplevel_v2:clock_window_background` (664) | desktop child = `clock_wrapper` |

### Desktop children NOT opened by mobile at this login

`toplevel_v2_combat_bar` (replaced by the mobile combat-bar chain), `escape_menu` (→ `escape_menu_mobile`),
`clock_wrapper` (→ `clock_time`). Situational desktop entries `chatdefault2..8`, `split_pm`, `graph`,
`group_ironman*`, and the `acc_create*` screens were not opened (not login-time on either platform).

### World IF_SETEVENTS / IF_SET*

~1256 `IF_SETEVENTS`, plus `IF_SETHIDE` ×14, `IF_SETTEXT` ×9 (e.g. `chat_v2:adventure`="Adventure",
`notes` loading text, poll error). These are the per-component interaction masks (`settings`
bitfields) attached to the opened windows — the same style as desktop, targeting the mobile children
where applicable.

### World vars

- **VARP** — 3351 packets / 3272 unique (full serverperm varp cache; all gameval-named). Account state.
- **VARC** (notable, gameval-named): the full `lvl_*_before_levelup_varc` block (all 29 skills),
  `comlevel_potential_varc=123`, `player_coord=56495750`, `player_kit_torso_client`,
  `chat_v2_profanity_filter=0`, `has_displayname_client=1`, the `music_*_toggle_varc` set, the full
  `clan_permissions_*` block, `telemetry_ready=1`, `wof_*`, `mtxmgt_*`. Account-state, not mobile-specific.
- **VARCSTR**: `last_clanchannelowner="Yehp"`, `lore_spell_opbase`/`_desc`, `trh_desc_cat_1..15`
  (treasure-hunter category descriptions), `notes0..29` (player notes; `notes0="Elder 2400"`).

### World RUNCLIENTSCRIPT (op82) — structural highlights

- Early frame init: `16300`(0), `671`(0), `20611`.
- `8862`(tabId, enabled) ×~30 — ribbon/tab enable-disable across the ribbon tab set.
- `139` = `subchanged_init` (only script with a named cs2 header among the world set).
- Buff-bar colour setup: `18950`/`18952`/`18951`(slot,r,g,b,?,4) ×8.
- Unlock/notify: `10623`(id, 0) ×many; `17050`(s,i) game-message
  ("You have unlocked the mobile pre-registration rewards!").
- Others: `11145`, `3143`, `14150`, `2651`, `6504`, `11670`, `17077`, `3530`, `4453`, `9945`,
  `3957`, `3543`, `20392`, `9542`, `16550`, `18954`, `8178`, `18468`, `7815`, `20093`, `4308`,
  `4704`, `8778`, `5559`. (Anonymous cs2 procs; not named in the dump.)

---

## 3. Clean gamevalled enumeration (1:1 for Kotlin enums)

### Mobile lobby placements (parent = `lobbyscreen`, order = wire order)

```
lobbyscreen_pane_playerinfo        -> playerinfo_panel
lobbyscreen_pane_worldselect       -> worldselect_panel
lobbyscreen_pane_mobile_social     -> friendslist_panel      # mobile-only child
lobbyscreen_pane_options           -> options_panel
lobbyscreen_report_abuse_stage1    -> report_abuse_stage1
lobbyscreen_report_abuse_stage2    -> report_abuse_stage2
lobbyscreen_report_abuse_ignore    -> report_abuse_ignore
lobbyscreen_mobile_side_menu       -> mobile_sidemenu
lobbyscreen_evalid                 -> email_validation
lobbyscreen_u13                    -> under_13
lobbyscreen_windowmode_confirm     -> windowmode_confirm
lobbyscreen_pvp_warning            -> pvp_warning
lobbyscreen_input                  -> input
lobbyscreen_popup                  -> popup
lobbyscreen_logout_warning         -> logout_warning
preload_cache                      -> preload_cache
lobbyscreen_clock                  -> clock
minimenu                           -> minimenu_layer
lobbyscreen_mobile_billing_info    -> mobile_billing_info
```

### Mobile world placements (order = wire order; `parent:slot` shown, default parent `toplevel_v2`)

```
gameworld                                             -> render_layer
stats_child                                           -> stats_window_background
toplevel_v2_inventory                                 -> inventory_window_background
inv_drop_areas                                        -> toplevel_v2_mobile:inv_drag_options_window
toplevel_v2_worn                                      -> worn_window_background
toplevel_v2_prayer                                    -> prayer_window_background
toplevel_v2_window_ability_book_magic                 -> ability_window_background_magic
toplevel_v2_window_ability_book_magic_ability         -> ability_window_background_magic_ability
toplevel_v2_window_ability_book_magic_combat          -> ability_window_background_magic_combat
toplevel_v2_window_ability_book_magic_teleport        -> ability_window_background_magic_teleport
toplevel_v2_window_ability_book_magic_skilling        -> ability_window_background_magic_skilling
toplevel_v2_window_ability_book_melee                 -> ability_window_background_melee
toplevel_v2_window_ability_book_defcon                -> ability_window_background_defcon
toplevel_v2_window_ability_book_defence               -> ability_window_background_defence
toplevel_v2_window_ability_book_constitution          -> ability_window_background_constitution
toplevel_v2_window_ability_book_ranged                -> ability_window_background_ranged
toplevel_v2_window_ability_book_necromancy            -> ability_window_background_necromancy
toplevel_v2_window_ability_book_necromancy_abilities  -> ability_window_background_necromancy_abilities
toplevel_v2_window_ability_book_necromancy_spells     -> ability_window_background_necromancy_spells
friends2                                              -> friends_list_window_background
friendschat_child                                     -> friendschat_window_background
clan_chat                                             -> clan_list_window_background
emotes2                                               -> emotes_window_background
music_v3_child                                        -> music_window_background
notes_child                                           -> notes_window_background
group_child                                           -> group_list_window_background
telemetry                                             -> telemetry_window_background
droplog                                               -> droplog_window_background
questlist_v4                                          -> questlist_window_background
cheevo_tracker                                        -> cheevo_tracker_window_background
cheevo_paths                                          -> cheevo_paths_window_background
toplevel_v2_ribbon                                    -> buttons_window_border
toplevel_v2_ribbon_extra                              -> ribbon_extra_context_menu_layer
toplevel_v2_minimap                                   -> mobile_settings_button:minimap_layer      # moved (desktop: minimap_window_content)
toplevel_v2_compass                                   -> mobile_settings_button:compass_layer      # moved (desktop: minimap_layer)
toplevel_v2_run_energy                                -> mobile_settings_button:run_energy_layer   # mobile-only
event_crafting                                        -> event_crafting_border
toplevel_v2_combat_bar_mobile                         -> toplevel_v2_mobile:combat_bar_mobile      # mobile combat bar (desktop: toplevel_v2_combat_bar)
toplevel_v2_combat_bar_mobile_buttons                 -> toplevel_v2_mobile:combat_bar_mobile_2
toplevel_v2_combat_bar_mobile_revo                    -> toplevel_v2_combat_bar_mobile_buttons:revo_layer
escape_menu_mobile                                    -> floater_layer                             # mobile (desktop: escape_menu)
chatdefault                                           -> chat_window_background
mobile_settings_button                                -> toplevel_v2_mobile:settings_mobile        # mobile-only
mobile_ribbon_left                                    -> toplevel_v2_mobile:mobile_ribbon_left     # mobile-only
mobile_chat_panel                                     -> toplevel_v2_mobile:chat_panel             # mobile-only
mobile_chat_overlay                                   -> toplevel_v2_mobile:chat_panel_overlay     # mobile-only
minimenu                                              -> minimenu_layer
gravestone_timer                                      -> grave_status_window_background
statusicons                                           -> statusicons_window_background
buff_bar                                              -> combat_status_window_background
xp_popup                                              -> xp_popup_window_background
toplevel_v2_parent                                    -> parent_window_tabs
debuff_bar                                            -> debuffs_window_background
toplevel_v2_targeting                                 -> levelup_layer
toplevel_v2_status_effects                            -> status_effects_overlay
toplevel_v2_ragdoll_store_tooltip                     -> tooltips_ragdoll_bounding_layer
clock_time                                            -> clock_window_background                    # mobile (desktop: clock_wrapper)
slayer_count                                          -> slayer_counter_window_background
toplevel_v2_mobile                                    -> mobile_toplevel                            # mobile container pane
crm_braze_login_popup                                 -> fullmodal_window_background                # mobile marketing popup
```

Note ordering: `toplevel_v2_mobile` (the container) is opened **after** several of its children in
the live stream (the client tolerates the sub being placed before its host pane appears in wire
order). The mobile sub-panes (`mobile_settings_button`, ribbon, chat, combat-bar, inv_drop_areas)
and the minimap/compass/run-energy that target them all key off `toplevel_v2_mobile` (276) and
`mobile_settings_button` (1376).

---

## 4. Diff summary vs desktop

**Lobby** — one substitution: desktop `{lobbyscreen_pane_friendslist, lobbyscreen_pane_clanchat,
lobbyscreen_pane_friendschat}` → single `lobbyscreen_pane_mobile_social` in the `friendslist_panel`
slot. All other 18 placements + order identical. (`mobile_side_menu`, `mobile_billing_info` already
in `LobbyInterface`.)

**World** — mobile = full desktop `toplevel_v2` frame **plus** a mobile overlay:
- **Adds** container `toplevel_v2_mobile` and its panes: `mobile_settings_button`, `mobile_ribbon_left`,
  `mobile_chat_panel`, `mobile_chat_overlay`, `inv_drop_areas`, `toplevel_v2_combat_bar_mobile`(+`_buttons`,
  `_revo`), `toplevel_v2_run_energy`, and `crm_braze_login_popup`.
- **Substitutes** children: `escape_menu`→`escape_menu_mobile`, `clock_wrapper`→`clock_time`,
  `toplevel_v2_combat_bar`→mobile combat-bar chain.
- **Re-parents** minimap/compass from `toplevel_v2` into `mobile_settings_button`.
- **Drops** `toplevel_v2_combat_bar` (replaced). No desktop game window is otherwise removed.

Vars/clientscripts are account-state serverperm dumps (all gameval-named) — not part of the
mobile-vs-desktop interface delta; the interface delta is entirely the placement set above.
