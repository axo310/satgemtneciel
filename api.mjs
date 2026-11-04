import { getDatabase } from "@netlify/database";
import { randomBytes, scryptSync, timingSafeEqual, createHash } from "node:crypto";

const db = getDatabase();
const STATUS = ["attente", "relance", "accepte", "refus"];
const json = (d, s = 200, h = {}) =>
  new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json", ...h } });
const sha = (t) => createHash("sha256").update(t).digest("hex");
const hash = (pw, salt) => scryptSync(pw, salt, 64).toString("hex");
const cookie = (v, max) => `session=${v}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${max}`;
const n = (v) => (v == null ? null : String(v).trim());
const site = (v) => { const w = n(v); return w && !/^https?:\/\//i.test(w) ? "https://" + w : w; };
const tokenOf = (req) => (req.headers.get("cookie") || "").match(/(?:^|;\s*)session=([a-f0-9]+)/)?.[1];

async function getUser(req) {
  const t = tokenOf(req);
  if (!t) return null;
  const r = await db.sql`SELECT u.id, u.username, u.role, u.approved FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ${sha(t)} AND s.expires_at > now()`;
  return r[0] || null;
}

export default async (req) => {
  const p = new URL(req.url).pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
  const m = req.method;
  let b = {};
  if (m === "POST" || m === "PUT") { try { b = await req.json(); } catch {} }

  try {
    // ---------- Comptes ----------
    if (p[0] === "register" && m === "POST") {
      const username = String(b.username || "").trim();
      const pw = String(b.password || "");
      if (!/^[\p{L}\p{N}_. -]{3,30}$/u.test(username)) return json({ error: "Nom : 3 à 30 caractères (lettres, chiffres, _ . -)." }, 400);
      if (pw.length < 6) return json({ error: "Mot de passe : 6 caractères minimum." }, 400);
      const first = (await db.sql`SELECT count(*)::int AS n FROM users`)[0].n === 0;
      const salt = randomBytes(16).toString("hex");
      try {
        await db.sql`INSERT INTO users (username, salt, password_hash, role, approved) VALUES (${username}, ${salt}, ${hash(pw, salt)}, ${first ? "admin" : "user"}, ${first})`;
      } catch { return json({ error: "Ce nom est déjà pris." }, 409); }
      return json({ ok: true, pending: !first });
    }

    if (p[0] === "login" && m === "POST") {
      const r = (await db.sql`SELECT * FROM users WHERE lower(username) = lower(${String(b.username || "").trim()})`)[0];
      const ok = r && timingSafeEqual(Buffer.from(hash(String(b.password || ""), r.salt), "hex"), Buffer.from(r.password_hash, "hex"));
      if (!ok) return json({ error: "Nom ou mot de passe incorrect." }, 401);
      if (!r.approved) return json({ error: "Ton compte attend la validation de l’admin." }, 403);
      const token = randomBytes(32).toString("hex");
      await db.sql`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (${sha(token)}, ${r.id}, now() + interval '30 days')`;
      return json({ username: r.username, role: r.role }, 200, { "set-cookie": cookie(token, 2592000) });
    }

    if (p[0] === "logout" && m === "POST") {
      const t = tokenOf(req);
      if (t) await db.sql`DELETE FROM sessions WHERE token_hash = ${sha(t)}`;
      return json({ ok: true }, 200, { "set-cookie": cookie("", 0) });
    }

    const u = await getUser(req);
    if (!u || !u.approved) return json({ error: "Non connecté." }, 401);

    if (p[0] === "me" && m === "GET") return json({ id: u.id, username: u.username, role: u.role });

    // ---------- Admin : gestion des comptes ----------
    if (p[0] === "users") {
      if (u.role !== "admin") return json({ error: "Réservé à l’admin." }, 403);
      if (m === "GET") return json(await db.sql`SELECT id, username, role, approved, created_at FROM users ORDER BY approved, id`);
      const id = Number(p[1]);
      if (p[2] === "approve" && m === "POST") {
        await db.sql`UPDATE users SET approved = true WHERE id = ${id}`;
        return json({ ok: true });
      }
      if (m === "DELETE") {
        if (id === u.id) return json({ error: "Tu ne peux pas supprimer ton propre compte." }, 400);
        await db.sql`DELETE FROM users WHERE id = ${id}`;
        return json({ ok: true });
      }
    }

    // ---------- Entreprises ----------
    if (p[0] === "companies") {
      if (m === "GET") return json(await db.sql`SELECT * FROM companies ORDER BY id`);
      if (m === "POST") {
        const name = n(b.name);
        if (!name) return json({ error: "Le nom est obligatoire." }, 400);
        const status = STATUS.includes(b.status) ? b.status : "attente";
        const r = await db.sql`INSERT INTO companies (name, address, activity, phone, website, note, status, created_by) VALUES (${name}, ${n(b.address) || ""}, ${n(b.activity) || ""}, ${n(b.phone) || ""}, ${site(b.website) || ""}, ${n(b.note) || ""}, ${status}, ${u.id}) RETURNING *`;
        return json(r[0], 201);
      }
      const id = Number(p[1]);
      if (m === "PUT") {
        const status = STATUS.includes(b.status) ? b.status : null;
        const r = await db.sql`UPDATE companies SET name = COALESCE(${n(b.name) || null}, name), address = COALESCE(${n(b.address)}, address), activity = COALESCE(${n(b.activity)}, activity), phone = COALESCE(${n(b.phone)}, phone), website = COALESCE(${site(b.website)}, website), note = COALESCE(${n(b.note)}, note), status = COALESCE(${status}, status), updated_at = now() WHERE id = ${id} RETURNING *`;
        return r[0] ? json(r[0]) : json({ error: "Introuvable." }, 404);
      }
      if (m === "DELETE") {
        const c = (await db.sql`SELECT created_by FROM companies WHERE id = ${id}`)[0];
        if (!c) return json({ error: "Introuvable." }, 404);
        if (u.role !== "admin" && c.created_by !== u.id) return json({ error: "Seul l’admin ou l’auteur peut supprimer." }, 403);
        await db.sql`DELETE FROM companies WHERE id = ${id}`;
        return json({ ok: true });
      }
    }
    return json({ error: "Route inconnue." }, 404);
  } catch (e) {
    console.error(e);
    return json({ error: "Erreur serveur." }, 500);
  }
};

export const config = { path: "/api/*" };
