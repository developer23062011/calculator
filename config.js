// ---------------------------------------------------------------------------
//  Pocket Calculator — configuration
//  Supabase → Project Settings → API:
//    • Project URL
//    • anon / public key   (safe to publish — Row Level Security protects data)
//  NEVER put the service_role key here.
// ---------------------------------------------------------------------------
window.PC_CONFIG = {
  SUPABASE_URL: "https://mizqjawyxubygyweyajy.supabase.co",
  SUPABASE_ANON_KEY: "sb_publishable_q_Sw5XI6Hp_-heSX0b05dw_Pl2ajI9U",

  // UI-level cap on extra "User" accounts the Admin can create.
  MAX_USERS: 1,

  // Largest photo accepted (bytes). Photos are encrypted in memory, so keep sane.
  MAX_FILE_BYTES: 30 * 1024 * 1024,
};
