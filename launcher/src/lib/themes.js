// Colors derived from the character artwork for each theme.
export const THEMES = {
  // ── Dark ──────────────────────────────────────────────────────────────────

  // Rosie: bright teal hair, forest green jacket, gold belt, dark boots
  rosie: {
    "--bg":      "#060d0b",
    "--surface":  "#0c1814",
    "--surface2": "#142018",
    "--border":   "#203828",
    "--text":     "#c8e8de",
    "--muted":    "#508870",
    "--accent":   "#18b090",
    "--success":  "#4caf82",
    "--danger":   "#e05c6a",
  },

  // Asbal: black background, vivid crimson cape, gold trim, pale porcelain skin
  asbal: {
    "--bg":      "#0d0608",
    "--surface":  "#150b10",
    "--surface2": "#1e1018",
    "--border":   "#3a1a28",
    "--text":     "#f0e0e8",
    "--muted":    "#9a6878",
    "--accent":   "#c82040",
    "--success":  "#4caf82",
    "--danger":   "#e07040",
  },

  // Duston: warm dark earth, golden bronze armor, brown leather
  duston: {
    "--bg":      "#141008",
    "--surface":  "#1c170a",
    "--surface2": "#261e10",
    "--border":   "#3c3018",
    "--text":     "#e8dcc8",
    "--muted":    "#8a7858",
    "--accent":   "#a87830",
    "--success":  "#4a8a3a",
    "--danger":   "#c04030",
  },

  // Fostail: pure black, soft lavender hair, deep midnight blue, cyan highlights
  fostail: {
    "--bg":      "#0d0b14",
    "--surface":  "#131020",
    "--surface2": "#1a1530",
    "--border":   "#2c2545",
    "--text":     "#d8d0f0",
    "--muted":    "#7870a8",
    "--accent":   "#9068e0",
    "--success":  "#4caf82",
    "--danger":   "#e05c6a",
  },

  // Lushenda: red skin, purple hair, emerald green cape, cream bodysuit, gold boots
  lushenda: {
    "--bg":      "#0a0810",
    "--surface":  "#130f1e",
    "--surface2": "#1c1630",
    "--border":   "#362248",
    "--text":     "#ecd8f8",
    "--muted":    "#7848a8",
    "--accent":   "#2aac58",
    "--success":  "#4caf82",
    "--danger":   "#e05c6a",
  },

  // ── Light ─────────────────────────────────────────────────────────────────

  // Anlucia: warm cream, golden yellow dress, dusty rose cape, gold armor
  anlucia: {
    "--bg":      "#fdf6ec",
    "--surface":  "#fffaf3",
    "--surface2": "#f2e6d2",
    "--border":   "#dccaac",
    "--text":     "#2c1a08",
    "--muted":    "#8a6e52",
    "--accent":   "#b87228",
    "--success":  "#4a7a2a",
    "--danger":   "#c03020",
  },

  // Estella: pale ice blue garments, cool gray-teal, gold accents, ethereal
  estella: {
    "--bg":      "#eef4f8",
    "--surface":  "#f5f9fc",
    "--surface2": "#dde8f0",
    "--border":   "#b8ccd8",
    "--text":     "#0e1e28",
    "--muted":    "#4a6a80",
    "--accent":   "#3878aa",
    "--success":  "#2a7a3a",
    "--danger":   "#c04040",
  },

  // Kyururu: fresh mint green, sky blue, warm golden yellow, cheerful bright
  kyururu: {
    "--bg":      "#edfaf5",
    "--surface":  "#f5fdfa",
    "--surface2": "#d8f4ec",
    "--border":   "#a8e0cc",
    "--text":     "#0a2820",
    "--muted":    "#3a7860",
    "--accent":   "#22aa78",
    "--success":  "#2a8a4a",
    "--danger":   "#c03040",
  },

  // Maille: warm rose pink garments, copper-gold hair, cream/tan, elegant
  maille: {
    "--bg":      "#fdf0f2",
    "--surface":  "#fff5f7",
    "--surface2": "#f0dfe2",
    "--border":   "#dcc8cc",
    "--text":     "#2a1018",
    "--muted":    "#8a5868",
    "--accent":   "#b05870",
    "--success":  "#2a7a3a",
    "--danger":   "#c03030",
  },

  // Mereade: vibrant orange dress, deep indigo-blue hair, golden yellow
  mereade: {
    "--bg":      "#fff5ed",
    "--surface":  "#fff9f5",
    "--surface2": "#ffe8d8",
    "--border":   "#f0c8a8",
    "--text":     "#2a1008",
    "--muted":    "#8a5830",
    "--accent":   "#d06820",
    "--success":  "#2a7a3a",
    "--danger":   "#c03030",
  },

  // Seraphi: bright yellow dress, orange scarf, blue hair, dark gray underlayer
  seraphi: {
    "--bg":      "#fdf8e0",
    "--surface":  "#fffcf0",
    "--surface2": "#f8edbc",
    "--border":   "#e0cc70",
    "--text":     "#1a1600",
    "--muted":    "#b07028",
    "--accent":   "#3a6abf",
    "--success":  "#2a7a3a",
    "--danger":   "#c04040",
  },

  // Yuliza: vibrant true-blue hair, warm golden dress, striking contrast
  yuliza: {
    "--bg":      "#edf2fa",
    "--surface":  "#f5f8ff",
    "--surface2": "#dce5f5",
    "--border":   "#b8c8e8",
    "--text":     "#081030",
    "--muted":    "#3a5080",
    "--accent":   "#2854c8",
    "--success":  "#2a7a3a",
    "--danger":   "#c04040",
  },
};

export const THEME_GROUPS = [
  {
    label: "Dark",
    themes: [
      { id: "rosie",    label: "Rosie"    },
      { id: "asbal",    label: "Asbal"    },
      { id: "duston",   label: "Duston"   },
      { id: "fostail",  label: "Fostail"  },
      { id: "lushenda", label: "Lushenda" },
    ],
  },
  {
    label: "Light",
    themes: [
      { id: "anlucia",  label: "Anlucia"  },
      { id: "estella",  label: "Estella"  },
      { id: "kyururu",  label: "Kyururu"  },
      { id: "maille",   label: "Maille"   },
      { id: "mereade",  label: "Mereade"  },
      { id: "seraphi",  label: "Seraphi"  },
      { id: "yuliza",   label: "Yuliza"   },
    ],
  },
];

/** Apply a theme by writing its CSS variables directly to :root. */
export function applyTheme(name) {
  const t = THEMES[name] ?? THEMES.rosie;
  const root = document.documentElement;
  for (const [k, v] of Object.entries(t)) {
    root.style.setProperty(k, v);
  }
}
