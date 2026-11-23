import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

// === Admin login (edit these two lines to change it, then redeploy) ===
const ADMIN_USER = "yassine";
const ADMIN_PASS = "2004@";
// Private signing key for sessions. Put any long random text here.
const SECRET = "echovast-change-this-to-a-long-random-text-9f3k2";
const MAX_PROFILES = 5000;
const FIELDS = ["name", "role", "company", "wa", "ig", "email", "web", "li", "ac", "ph"];

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });

function clean(o) {
  const r = {};
  for (const k of FIELDS) {
    const v = o && typeof o[k] === "string" ? o[k] : "";
    r[k] = k === "ph" ? v.slice(0, 60000) : v.slice(0, 120);
  }
  if (!/^#[0-9a-f]{6}$/i.test(r.ac)) r.ac = "#d10a0a";
  if (!/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(r.ph)) r.ph = "";
  return r;
}

const sign = (s) => crypto.createHmac("sha256", SECRET).update(s).digest("hex");
function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function makeToken() {
  const exp = Date.now() + 1000 * 60 * 60 * 12; // 12h
  return exp + "." + sign("adm." + exp);
}
function isAdmin(req) {
  const h = req.headers.get("authorization") || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : "";
  const [exp, sig] = t.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEq(sig, sign("adm." + exp));
}

export default async (req) => {
  const url = new URL(req.url);
  const parts = url.pathname.replace(/^\/(api|\.netlify\/functions\/profiles)\/?/, "").split("/").filter(Boolean);
  const route = parts[0];
  const id = parts[1] ? decodeURIComponent(parts[1]) : null;

  try {
    // ---- Login (does not need the database) ----
    if (route === "login" && req.method === "POST") {
      const b = await req.json().catch(() => ({}));
      const okU = safeEq(String(b.username || "").trim().toLowerCase(), ADMIN_USER.toLowerCase());
      const okP = safeEq(String(b.password || "").trim(), ADMIN_PASS);
      if (okU && okP) return json({ token: makeToken() });
      return json({ error: "Incorrect username or password." }, 401);
    }

    if (route !== "profiles") return json({ error: "Not found" }, 404);

    const store = getStore("profiles");

    // ---- Create (public: any visitor who builds a card) ----
    if (!id && req.method === "POST") {
      const raw = await req.text();
      if (raw.length > 120000) return json({ error: "Too large" }, 413);
      let b; try { b = JSON.parse(raw); } catch { return json({ error: "Bad JSON" }, 400); }
      const { blobs } = await store.list();
      if (blobs.length >= MAX_PROFILES) return json({ error: "Storage full" }, 507);
      const newId = crypto.randomUUID();
      const key = crypto.randomBytes(16).toString("hex");
      const now = Date.now();
      await store.setJSON(newId, { id: newId, d: clean(b.d), createdAt: now, updatedAt: now, keyHash: sign("key." + key) });
      return json({ id: newId, key }, 201);
    }

    // ---- Update (admin token, or the owner's edit key) ----
    if (id && req.method === "PUT") {
      const rec = await store.get(id, { type: "json" });
      if (!rec) return json({ error: "Not found" }, 404);
      const raw = await req.text();
      if (raw.length > 120000) return json({ error: "Too large" }, 413);
      let b; try { b = JSON.parse(raw); } catch { return json({ error: "Bad JSON" }, 400); }
      const owner = typeof b.key === "string" && safeEq(sign("key." + b.key), rec.keyHash || "");
      if (!isAdmin(req) && !owner) return json({ error: "Not allowed" }, 403);
      rec.d = clean(b.d);
      rec.updatedAt = Date.now();
      await store.setJSON(id, rec);
      return json({ id });
    }

    // ---- Admin only: list + delete ----
    if (!isAdmin(req)) return json({ error: "Unauthorized" }, 401);

    if (!id && req.method === "GET") {
      const { blobs } = await store.list();
      const items = (await Promise.all(blobs.map((x) => store.get(x.key, { type: "json" }))))
        .filter(Boolean)
        .map(({ id, d, createdAt, updatedAt }) => ({ id, d, createdAt, updatedAt }))
        .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      return json({ items });
    }

    if (id && req.method === "DELETE") {
      await store.delete(id);
      return json({ ok: true });
    }

    return json({ error: "Method not allowed" }, 405);
  } catch (e) {
    return json({ error: "Server error" }, 500);
  }
};

export const config = { path: ["/api/login", "/api/profiles", "/api/profiles/:id"] };
