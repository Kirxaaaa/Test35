import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(crypto.scrypt);

// Biens louables et tarif par jour ($). Le serveur recalcule toujours le total.
const PRIX = { Batte: 3000 };
// Tout compte dont le nom est « Syndicate » (casse ignorée) est administrateur avec tous les accès.
const isAdminName = (n) => ["syndicate", "new town", "ogaami", "las vegas", "tulsa", "brooklyn", "le nain"].includes(String(n ?? "").trim().toLowerCase());

// Code de sécurité demandé après la connexion (3 essais, puis blocage 10 minutes).
// Pour le changer sans toucher au code : variable d'environnement ACCESS_CODE sur Netlify.
const ACCESS_CODE = String(process.env.ACCESS_CODE || "190626");
const CODE_TRIES = 3;
const CODE_WAIT = 10 * 60 * 1000;

class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });

const keyOf = (name) =>
  crypto.createHash("sha256").update(String(name).toLowerCase()).digest("hex").slice(0, 40);

const clean = (s, max) =>
  String(s ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, max);

const safeEqual = (a, b) => {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
};

// Clé de signature des sessions : générée automatiquement au premier usage et stockée dans Netlify Blobs.
// (Si la variable TOKEN_SECRET existe, elle est utilisée à la place.)
let cachedSecret = null;
async function secret() {
  if (cachedSecret) return cachedSecret;
  const env = process.env.TOKEN_SECRET;
  if (env && env.length >= 16) return (cachedSecret = env);
  const store = getStore("config");
  let rec = await store.get("token-secret", { type: "json" });
  if (!rec || !rec.value) {
    rec = { value: crypto.randomBytes(48).toString("hex") };
    await store.setJSON("token-secret", rec);
    rec = (await store.get("token-secret", { type: "json" })) || rec;
  }
  return (cachedSecret = rec.value);
}

// ok = false : jeton « en attente » (10 min), il ne sert qu'à envoyer le code.
// ok = true  : session complète (12 h), délivrée uniquement après le bon code.
async function sign(name, ok) {
  const payload = Buffer.from(
    JSON.stringify({ n: name, v: ok ? 1 : 0, e: Date.now() + (ok ? 12 * 3600 * 1000 : 10 * 60 * 1000) })
  ).toString("base64url");
  const sig = crypto.createHmac("sha256", await secret()).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

async function verify(req, allowPending = false) {
  const h = req.headers.get("authorization") || "";
  const tok = h.startsWith("Bearer ") ? h.slice(7) : "";
  const [payload, sig] = tok.split(".");
  if (!payload || !sig) throw new HttpError(401, "Session expirée. Reconnectez-vous.");
  const expected = crypto.createHmac("sha256", await secret()).update(payload).digest("base64url");
  if (!safeEqual(sig, expected)) throw new HttpError(401, "Session invalide. Reconnectez-vous.");
  let data;
  try {
    data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    throw new HttpError(401, "Session invalide. Reconnectez-vous.");
  }
  if (!data.n || !(data.e > Date.now())) throw new HttpError(401, "Session expirée. Reconnectez-vous.");
  if (!allowPending && data.v !== 1) throw new HttpError(401, "Code de sécurité requis. Reconnectez-vous.");
  return data.n;
}

async function body(req, max = 10000) {
  const text = await req.text();
  if (text.length > max) throw new HttpError(413, "Requête trop grande.");
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    throw new HttpError(400, "Requête invalide.");
  }
}

async function hashPass(pass, salt) {
  return (await scrypt(pass, salt, 32)).toString("hex");
}

// Anti force brute : 8 échecs => blocage 10 minutes pour ce nom
async function checkLock(name) {
  const r = await getStore("locks").get(keyOf(name), { type: "json" });
  if (r && r.until > Date.now()) throw new HttpError(429, "Trop d’essais. Réessayez dans quelques minutes.");
}
async function addFail(name) {
  const s = getStore("locks");
  const k = keyOf(name);
  const r = (await s.get(k, { type: "json" })) || { c: 0 };
  const c = (r.until && r.until < Date.now() ? 0 : r.c || 0) + 1;
  await s.setJSON(k, c >= 8 ? { c: 0, until: Date.now() + 10 * 60 * 1000 } : { c });
}
async function clearFails(name) {
  await getStore("locks").delete(keyOf(name));
}

// Blocage du code à 6 chiffres : 3 erreurs => 10 minutes (ou déblocage par un admin)
async function codeState(name) {
  const s = getStore("codelocks");
  const k = keyOf(name);
  const r = (await s.get(k, { type: "json" })) || { c: 0 };
  if (r.until && r.until <= Date.now()) {
    await s.delete(k);
    return { c: 0, until: 0 };
  }
  return { c: r.c || 0, until: r.until || 0 };
}
const codeInfo = (st) =>
  st.until > Date.now() ? { wait: st.until - Date.now(), left: 0 } : { wait: 0, left: Math.max(0, CODE_TRIES - st.c) };

async function listAll(store) {
  const { blobs } = await store.list();
  const items = await Promise.all(blobs.map((b) => store.get(b.key, { type: "json" })));
  return items.filter(Boolean);
}

async function currentUser(req, allowPending = false) {
  const name = await verify(req, allowPending);
  const acc = await getStore("accounts").get(keyOf(name), { type: "json" });
  if (!acc) throw new HttpError(401, "Compte introuvable. Reconnectez-vous.");
  const admin = isAdminName(acc.name);
  return { name: acc.name, admin, access: admin || acc.access === true };
}

const view = async (u, withToken, ok = false) => ({
  ...(withToken ? { token: await sign(u.name, ok) } : {}),
  name: u.name,
  admin: u.admin,
  access: u.access,
});

export default async (req) => {
  try {
    const url = new URL(req.url);
    const path = url.pathname.replace(/^\/api/, "").replace(/\/+$/, "") || "/";
    const m = req.method;

    // ---------- Classement (public) ----------
    if (path === "/scores" && m === "GET") {
      const all = await listAll(getStore("scores"));
      all.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
      return json({ scores: all.slice(0, 50).map((x) => ({ name: x.name, score: x.score })) });
    }
    if (path === "/scores" && m === "POST") {
      const b = await body(req);
      const name = clean(b.name, 16) || "Anonyme";
      const score = Number(b.score);
      if (!Number.isInteger(score) || score < 1 || score > 400) throw new HttpError(400, "Score invalide.");
      const store = getStore("scores");
      const k = keyOf(name);
      const old = await store.get(k, { type: "json" });
      if (!old || old.score < score) await store.setJSON(k, { name, score, ts: Date.now() });
      return json({ ok: true });
    }

    // ---------- Comptes ----------
    if (path === "/signup" && m === "POST") {
      const b = await body(req);
      const name = clean(b.name, 20);
      const pass = String(b.pass ?? "");
      if (!/^[\p{L}\p{N} ._-]{3,20}$/u.test(name))
        throw new HttpError(400, "Nom d’utilisateur : 3 à 20 caractères (lettres, chiffres, espace, . _ -).");
      if (pass.length < 4 || pass.length > 100) throw new HttpError(400, "Le mot de passe doit contenir au moins 4 caractères.");
      const store = getStore("accounts");
      const k = keyOf(name);
      if (await store.get(k, { type: "json" })) throw new HttpError(409, "Ce nom d’utilisateur existe déjà.");
      const salt = crypto.randomBytes(16).toString("hex");
      const admin = isAdminName(name);
      await store.setJSON(k, { name, salt, hash: await hashPass(pass, salt), access: admin, ts: Date.now() });
      // Jeton « en attente » : le code à 6 chiffres reste obligatoire.
      return json({ ...(await view({ name, admin, access: admin }, true, false)), pending: true, ...codeInfo({ c: 0, until: 0 }) });
    }

    if (path === "/login" && m === "POST") {
      const b = await body(req);
      const name = clean(b.name, 20);
      const pass = String(b.pass ?? "");
      const bad = () => new HttpError(401, "Nom d’utilisateur ou mot de passe incorrect.");
      if (!name) throw bad();
      await checkLock(name);
      const acc = await getStore("accounts").get(keyOf(name), { type: "json" });
      const h = acc ? await hashPass(pass, acc.salt) : null;
      if (!acc || !safeEqual(h, acc.hash)) {
        await addFail(name);
        throw bad();
      }
      await clearFails(name);
      const admin = isAdminName(acc.name);
      const st = await codeState(acc.name);
      // Jeton « en attente » : il ne donne accès à rien tant que le code n'est pas validé.
      return json({
        ...(await view({ name: acc.name, admin, access: admin || acc.access === true }, true, false)),
        pending: true,
        ...codeInfo(st),
      });
    }

    // ---------- Code à 6 chiffres (jeton en attente accepté) ----------
    if (path === "/code" && m === "POST") {
      const user = await currentUser(req, true);
      const st = await codeState(user.name);
      if (st.until > Date.now())
        throw new HttpError(429, "Trop de tentatives. Réessayez plus tard ou demandez à un administrateur de vous débloquer.", codeInfo(st));
      const b = await body(req);
      const code = String(b.code ?? "").trim();
      if (!/^\d{6}$/.test(code)) throw new HttpError(400, "Le code contient 6 chiffres.", codeInfo(st));
      const s = getStore("codelocks");
      const k = keyOf(user.name);
      if (!safeEqual(code, ACCESS_CODE)) {
        const c = st.c + 1;
        const next = c >= CODE_TRIES ? { c: 0, until: Date.now() + CODE_WAIT } : { c };
        await s.setJSON(k, next);
        throw new HttpError(
          403,
          c >= CODE_TRIES ? "Code incorrect. Accès bloqué pendant 10 minutes." : "Code incorrect.",
          codeInfo({ c: next.c, until: next.until || 0 })
        );
      }
      await s.delete(k);
      return json(await view(user, true, true)); // session complète (12 h)
    }

    // ---------- Tout le reste demande d'être connecté (code validé) ----------
    const user = await currentUser(req);

    if (path === "/me" && m === "GET") return json(await view(user, false));

    if (path === "/accounts" && m === "GET") {
      if (!user.admin) throw new HttpError(403, "Réservé à Syndicate.");
      const all = await listAll(getStore("accounts"));
      all.sort((a, b) => (a.ts || 0) - (b.ts || 0));
      const states = await Promise.all(all.map((a) => codeState(a.name)));
      return json({
        accounts: all.map((a, i) => ({
          name: a.name,
          access: isAdminName(a.name) || a.access === true,
          admin: isAdminName(a.name),
          ts: a.ts,
          locked: states[i].until > Date.now(),
        })),
      });
    }

    if (path === "/accounts/access" && m === "POST") {
      if (!user.admin) throw new HttpError(403, "Réservé à Syndicate.");
      const b = await body(req);
      const store = getStore("accounts");
      const k = keyOf(clean(b.name, 20));
      const acc = await store.get(k, { type: "json" });
      if (!acc) throw new HttpError(404, "Compte introuvable.");
      acc.access = isAdminName(acc.name) ? true : b.access === true;
      await store.setJSON(k, acc);
      return json({ ok: true });
    }

    // Débloque un compte : remet à zéro le blocage du code (et celui du mot de passe)
    if (path === "/accounts/unlock" && m === "POST") {
      if (!user.admin) throw new HttpError(403, "Réservé à Syndicate.");
      const b = await body(req);
      const name = clean(b.name, 20);
      const k = keyOf(name);
      const acc = await getStore("accounts").get(k, { type: "json" });
      if (!acc) throw new HttpError(404, "Compte introuvable.");
      await getStore("codelocks").delete(k);
      await getStore("locks").delete(k);
      return json({ ok: true });
    }

    // ---------- Sauvegarde / restauration (Syndicate uniquement) ----------
    if (path === "/backup" && m === "GET") {
      if (!user.admin) throw new HttpError(403, "Réservé à Syndicate.");
      const accounts = await listAll(getStore("accounts"));
      const rentals = await listAll(getStore("rentals"));
      const scores = await listAll(getStore("scores"));
      return json({ format: "snake-backup", version: 1, date: new Date().toISOString(), accounts, rentals, scores });
    }

    if (path === "/restore" && m === "POST") {
      if (!user.admin) throw new HttpError(403, "Réservé à Syndicate.");
      const b = await body(req, 5_000_000);
      if (b.format !== "snake-backup" || !Array.isArray(b.accounts)) throw new HttpError(400, "Fichier de sauvegarde invalide.");
      const accStore = getStore("accounts");
      let n = 0;
      for (const a of b.accounts) {
        const name = clean(a && a.name, 20);
        if (!name || typeof a.salt !== "string" || typeof a.hash !== "string") continue;
        const k = keyOf(name);
        if (await accStore.get(k, { type: "json" })) continue; // ne jamais écraser un compte existant
        await accStore.setJSON(k, { name, salt: a.salt, hash: a.hash, access: isAdminName(name) || a.access === true, ts: Number(a.ts) || Date.now() });
        n++;
      }
      return json({ ok: true, restored: n });
    }

    if (path === "/rentals" && m === "GET") {
      if (!user.access) throw new HttpError(403, "Accès non accordé par Syndicate.");
      const all = await listAll(getStore("rentals"));
      all.sort((a, b) => (a.ts || 0) - (b.ts || 0));
      return json({ rentals: user.admin ? all : all.map((r) => ({ bien: r.bien })) });
    }

    if (path === "/rentals" && m === "POST") {
      if (!user.access) throw new HttpError(403, "Accès non accordé par Syndicate.");
      const b = await body(req);
      const bien = String(b.bien ?? "");
      const client = clean(b.client, 60);
      const tel = clean(b.tel, 30);
      const jours = Number(b.jours);
      if (!Object.prototype.hasOwnProperty.call(PRIX, bien)) throw new HttpError(400, "Bien inconnu.");
      if (!Number.isInteger(jours) || jours < 1 || jours > 365) throw new HttpError(400, "Nombre de jours invalide.");
      if (!client || tel.replace(/\D/g, "").length < 6)
        throw new HttpError(400, "Renseignez le nom du client et un numéro de téléphone valide.");
      const store = getStore("rentals");
      const existing = await listAll(store);
      if (existing.some((r) => r.bien === bien)) throw new HttpError(409, "Ce bien n’est pas disponible.");
      const ts = Date.now();
      const id = `r${ts}${crypto.randomBytes(3).toString("hex")}`;
      const date = new Date(ts).toLocaleDateString("fr-FR", { day: "numeric", month: "long", year: "numeric", timeZone: "Europe/Paris" });
      await store.setJSON(id, { id, bien, client, tel, jours, date, by: user.name, ts });
      return json({ ok: true, total: PRIX[bien] * jours });
    }

    if (path === "/rentals/return" && m === "POST") {
      if (!user.admin) throw new HttpError(403, "Réservé à Syndicate.");
      const b = await body(req);
      const id = String(b.id ?? "");
      if (!/^r[a-z0-9]+$/i.test(id)) throw new HttpError(400, "Identifiant invalide.");
      await getStore("rentals").delete(id);
      return json({ ok: true });
    }

    throw new HttpError(404, "Introuvable.");
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message, ...e.extra }, e.status);
    console.error(e);
    return json({ error: "Erreur serveur." }, 500);
  }
};

export const config = { path: "/api/*" };
