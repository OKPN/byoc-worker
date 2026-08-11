import { Hono } from "hono";
import { cors } from "hono/cors";

const app = new Hono();

// CORSを全面許可（あらゆるフロントエンドドメインからのAPIリクエストを受け付ける）
const corsMiddleware = cors({
  origin: "*",
  allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowHeaders: ["Content-Type", "Authorization"],
});
app.use("*", corsMiddleware);

function getExpectedToken(c) {
  return c.env.API_TOKEN || c.env.AUTH_TOKEN || c.env.TOKEN || c.env.SECRET_TOKEN || c.env.api_token || "";
}

// 認証チェックミドルウェア
app.use("/api/*", async (c, next) => {
  const expectedToken = getExpectedToken(c);
  if (!expectedToken) {
    return await next();
  }
  const authHeader = c.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return c.json({ error: "Unauthorized: Missing token" }, 401);
  }
  const token = authHeader.substring(7);
  if (token !== expectedToken) {
    return c.json({ error: "Unauthorized: Invalid token" }, 401);
  }
  await next();
});

// ルートアクセス（無害な404エラーに偽装）
app.get("/", (c) => {
  return c.text("404 Not Found", 404);
});

// 1. 一時共有アップロード受取 (POST /temp-upload)
app.post("/temp-upload", async (c) => {
  try {
    const expectedToken = getExpectedToken(c);
    if (expectedToken) {
      const authHeader = c.req.header("Authorization");
      const token = authHeader?.startsWith("Bearer ") ? authHeader.substring(7) : "";
      if (token !== expectedToken) {
        return c.json({ error: "Unauthorized: Invalid token" }, 401);
      }
    }

    const rawFilename = c.req.query("filename") || "file";
    const ttl = Math.max(60, parseInt(c.req.query("ttl") || "259200", 10));
    const password = c.req.query("password") || "";
    const contentType = c.req.header("Content-Type") || "application/octet-stream";

    const baseFilename = rawFilename.replace(/[\/\\]/g, "_");

    let shortKey = baseFilename;
    const existing = await c.env.TEMP_KV.get(`temp_${shortKey}`, "arrayBuffer");
    if (existing) {
      const randPrefix = Math.random().toString(36).substring(2, 6);
      shortKey = `${randPrefix}-${baseFilename}`;
    }
    const kvKey = `temp_${shortKey}`;

    const publicOrigin = new URL(c.req.url).origin;
    const targetUrl = `${publicOrigin}/${encodeURIComponent(shortKey)}`;

    const body = await c.req.raw.arrayBuffer();
    const MAX_KV_BYTES = 25 * 1024 * 1024; // 25MB
    if (body.byteLength > MAX_KV_BYTES) {
      return c.json({ error: "ファイルサイズがKV上限(25MB)を超えています。" }, 413);
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    const expiration = nowSeconds + ttl;

    await c.env.TEMP_KV.put(kvKey, body, {
      expirationTtl: ttl,
      metadata: {
        contentType,
        filename: shortKey,
        expiration,
        password,
        size: body.byteLength,
      },
    });

    return c.json({
      success: true,
      url: targetUrl,
      ttl: ttl,
      hasPassword: Boolean(password),
    });
  } catch (error) {
    console.error("KV Temp upload error:", error);
    return c.json({ error: error.message }, 500);
  }
});

const parseCookies = (cookieHeader) => {
  const list = {};
  if (!cookieHeader) return list;
  cookieHeader.split(";").forEach((cookie) => {
    const parts = cookie.split("=");
    if (parts.length >= 2) {
      list[parts.shift().trim()] = decodeURIComponent(parts.join("=").trim());
    }
  });
  return list;
};

// パスワード試行制限は、既定値を安全側に固定しつつ自己ホスト運用だけ調整できる。
// 不適切な設定値によって防御が無効化されないよう、変更可能な範囲も固定する。
const getBoundedInteger = (value, fallback, minimum, maximum) => {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(maximum, Math.max(minimum, parsed));
};

const getPasswordAttemptPolicy = (env) => ({
  maxFailures: getBoundedInteger(env.PASSWORD_MAX_FAILURES, 10, 3, 20),
  blockSeconds: getBoundedInteger(env.PASSWORD_BLOCK_SECONDS, 900, 60, 86400),
});

const getPasswordAttemptKey = async (shortKey, clientIp) => {
  // 接続元 IP をそのまま保存せず、ファイルごとに分離した不可逆な識別子を使う。
  const payload = new TextEncoder().encode(`${shortKey}\u0000${clientIp}`);
  const digest = await crypto.subtle.digest("SHA-256", payload);
  const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `auth_attempt_${hash}`;
};

const getPasswordAttempt = async (kv, attemptKey) => {
  const attempt = await kv.get(attemptKey, "json");
  return attempt && typeof attempt === "object" ? attempt : null;
};

const recordPasswordFailure = async (kv, attemptKey, currentAttempt, policy) => {
  const now = Math.floor(Date.now() / 1000);
  const isCurrentWindow = currentAttempt
    && Number.isFinite(currentAttempt.windowStartedAt)
    && now - currentAttempt.windowStartedAt < policy.blockSeconds;
  const windowStartedAt = isCurrentWindow ? currentAttempt.windowStartedAt : now;
  const failures = isCurrentWindow ? (currentAttempt.failures || 0) + 1 : 1;
  const blockedUntil = failures >= policy.maxFailures ? now + policy.blockSeconds : 0;
  const expiresIn = blockedUntil
    ? policy.blockSeconds
    : Math.max(60, policy.blockSeconds - (now - windowStartedAt));

  await kv.put(attemptKey, JSON.stringify({ windowStartedAt, failures, blockedUntil }), {
    expirationTtl: expiresIn,
  });

  return blockedUntil;
};

const renderPasswordPromptHtml = (filename, errorMsg = "") => {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>🔒 パスワード保護されたファイル</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #121316; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
    .card { background: #1e2025; border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 32px 24px; width: 100%; max-width: 400px; text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
    .icon { font-size: 48px; margin-bottom: 12px; }
    h1 { font-size: 18px; margin-bottom: 8px; color: #ffffff; }
    p { font-size: 13px; color: #94a3b8; margin-bottom: 24px; line-height: 1.5; }
    input[type="password"] { width: 100%; height: 44px; background: #121316; border: 1px solid rgba(255,255,255,0.15); border-radius: 8px; color: #ffffff; padding: 0 16px; font-size: 16px; outline: none; margin-bottom: 12px; text-align: center; letter-spacing: 2px; }
    input[type="password"]:focus { border-color: #6366f1; }
    button { width: 100%; height: 44px; background: #6366f1; color: #ffffff; border: none; border-radius: 8px; font-size: 14px; font-weight: bold; cursor: pointer; transition: background 0.2s; }
    button:hover { background: #4f46e5; }
    .error { color: #f43f5e; font-size: 12px; margin-top: 10px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🔒</div>
    <h1>保護されたファイル</h1>
    <p>このファイルを閲覧するにはパスワードが必要です。</p>
    <form method="POST" action="">
      <input type="password" name="pwd" placeholder="🔑 パスワードを入力" autofocus required autocomplete="off">
      <button type="submit">閲覧する</button>
    </form>
    ${errorMsg ? `<div class="error">${errorMsg}</div>` : ""}
  </div>
</body>
</html>`;
};

const getContentTypeFromFilename = (filename, fallback = "application/octet-stream") => {
  const ext = filename.split(".").pop().toLowerCase();
  const mimeTypes = {
    mp4: "video/mp4",
    webm: "video/webm",
    mov: "video/quicktime",
    m4v: "video/mp4",
    avi: "video/x-msvideo",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    png: "image/png",
    webp: "image/webp",
    gif: "image/gif",
    svg: "image/svg+xml",
  };
  return mimeTypes[ext] || fallback;
};

// 2. 一時共有ファイル配信ハンドラ
const handleTempFetch = async (c, rawShortKey) => {
  try {
    const shortKey = decodeURIComponent(rawShortKey);
    const kvKey = `temp_${shortKey}`;
    const { value, metadata } = await c.env.TEMP_KV.getWithMetadata(kvKey, "arrayBuffer");

    if (!value) {
      // ブラウザには保存させず、Cloudflare エッジだけで 30 日間キャッシュする。
      // これにより同じ消滅済み URL への再アクセスは Worker/KV を実行しない。
      return c.text("404 Not Found - この一時ファイルは指定された保持期限が切れたため完全自動消滅しました。", 404, {
        "Cache-Control": "no-store",
        "Cloudflare-CDN-Cache-Control": "public, max-age=2592000",
      });
    }

    // パスワード保護の判定 (POST ＋ Cookie 認証方式)
    if (metadata && metadata.password) {
      const cookies = parseCookies(c.req.header("Cookie"));
      const cookieKey = `file_auth_${encodeURIComponent(shortKey)}`;
      const isCookieAuthed = cookies[cookieKey] === metadata.password;

      let inputPwd = "";
      if (c.req.method === "POST") {
        try {
          const body = await c.req.parseBody();
          inputPwd = body.pwd || "";
        } catch (e) {}
      }
      if (!inputPwd) {
        inputPwd = c.req.query("pwd") || c.req.header("X-File-Password") || "";
      }

      const isPasswordPost = c.req.method === "POST" && !isCookieAuthed;
      const policy = getPasswordAttemptPolicy(c.env);
      const clientIp = c.req.header("CF-Connecting-IP") || "unknown";
      const attemptKey = isPasswordPost ? await getPasswordAttemptKey(shortKey, clientIp) : null;
      const currentAttempt = attemptKey ? await getPasswordAttempt(c.env.TEMP_KV, attemptKey) : null;
      const now = Math.floor(Date.now() / 1000);

      if (currentAttempt?.blockedUntil > now) {
        const retryAfter = currentAttempt.blockedUntil - now;
        return c.text("Too Many Requests - パスワード試行回数の上限に達しました。しばらくしてから再試行してください。", 429, {
          "Cache-Control": "no-store",
          "Retry-After": String(retryAfter),
        });
      }

      // 未認証かつ不一致の場合
      if (!isCookieAuthed && inputPwd !== metadata.password) {
        // Botやプログラムによる高速なパスワード試行・総当たり攻撃を遅延（1秒）させて完全に鈍化・無効化
        if (c.req.method === "POST" || inputPwd) {
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
        if (attemptKey) {
          const blockedUntil = await recordPasswordFailure(c.env.TEMP_KV, attemptKey, currentAttempt, policy);
          if (blockedUntil) {
            return c.text("Too Many Requests - パスワード試行回数の上限に達しました。しばらくしてから再試行してください。", 429, {
              "Cache-Control": "no-store",
              "Retry-After": String(policy.blockSeconds),
            });
          }
        }
        const errorNotice = (c.req.method === "POST" || inputPwd) ? "⚠️ パスワードが正しくありません" : "";
        return c.html(renderPasswordPromptHtml(shortKey, errorNotice), 200);
      }

      // POST送信で成功した場合: CookieをセットしてクリーンなGET URLへ303リダイレクト！
      if (c.req.method === "POST" && inputPwd === metadata.password) {
        if (attemptKey) {
          await c.env.TEMP_KV.delete(attemptKey);
        }
        const publicOrigin = new URL(c.req.url).origin;
        const cleanUrl = `${publicOrigin}/${encodeURIComponent(shortKey)}`;
        return new Response(null, {
          status: 303,
          headers: {
            "Location": cleanUrl,
            "Set-Cookie": `${cookieKey}=${encodeURIComponent(metadata.password)}; Path=/; Max-Age=86400; Secure; SameSite=Lax`,
          },
        });
      }
    }

    let contentType = (metadata && metadata.contentType && metadata.contentType !== "application/octet-stream")
      ? metadata.contentType
      : getContentTypeFromFilename(shortKey);

    const totalBytes = value.byteLength;
    const rangeHeader = c.req.header("Range");

    const hasPassword = Boolean(metadata && metadata.password);
    const cacheControlHeader = hasPassword ? "private, no-transform, max-age=86400" : "public, max-age=86400";
    const varyHeader = hasPassword ? "Cookie, Accept-Encoding" : "Accept-Encoding";

    // Rangeリクエスト対応
    if (rangeHeader && rangeHeader.startsWith("bytes=")) {
      const parts = rangeHeader.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10) || 0;
      const end = parts[1] ? parseInt(parts[1], 10) : totalBytes - 1;

      if (start >= totalBytes || end >= totalBytes || start > end) {
        return new Response("Requested Range Not Satisfiable", {
          status: 416,
          headers: { "Content-Range": `bytes */${totalBytes}` },
        });
      }

      const chunk = value.slice(start, end + 1);
      return new Response(chunk, {
        status: 206,
        headers: {
          "Content-Type": contentType,
          "Content-Range": `bytes ${start}-${end}/${totalBytes}`,
          "Content-Length": String(chunk.byteLength),
          "Accept-Ranges": "bytes",
          "Cache-Control": cacheControlHeader,
          "Vary": varyHeader,
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    return new Response(value, {
      status: 200,
      headers: {
        "Content-Type": contentType,
        "Content-Length": String(totalBytes),
        "Accept-Ranges": "bytes",
        "Cache-Control": cacheControlHeader,
        "Vary": varyHeader,
        "Access-Control-Allow-Origin": "*",
      },
    });
  } catch (error) {
    console.error("KV Temp fetch error:", error);
    return c.text("500 Internal Server Error", 500);
  }
};

// /d/ プレフィックスルートは未使用のため削除済み
app.get("/:shortKey", async (c) => {
  const shortKey = c.req.param("shortKey");
  if (shortKey === "favicon.ico" || shortKey === "sw.js" || shortKey === "manifest.json" || shortKey.startsWith("api")) {
    return c.notFound();
  }
  return handleTempFetch(c, shortKey);
});
app.post("/:shortKey", async (c) => {
  const shortKey = c.req.param("shortKey");
  if (shortKey === "favicon.ico" || shortKey === "sw.js" || shortKey === "manifest.json" || shortKey.startsWith("api")) {
    return c.notFound();
  }
  return handleTempFetch(c, shortKey);
});

// 3. 一時共有ファイル一覧取得 API (GET /api/temp-files)
// メタデータに size を保存済みのため、ファイル実体を読まずに一覧を返せる（KV読み込み N 回削減）
app.get("/api/temp-files", async (c) => {
  try {
    const list = await c.env.TEMP_KV.list({ prefix: "temp_" });
    const nowSeconds = Math.floor(Date.now() / 1000);
    const publicOrigin = new URL(c.req.url).origin;

    const files = list.keys.map((k) => {
      const shortKey = k.name.replace(/^temp_/, "");
      const metadata = k.metadata || {};
      const expiration = k.expiration || 0;
      const remaining = Math.max(0, expiration - nowSeconds);
      return {
        key: shortKey,
        filename: metadata.filename || shortKey,
        contentType: metadata.contentType || "application/octet-stream",
        url: `${publicOrigin}/${shortKey}`,
        size: metadata.size || 0,
        expiration,
        remaining,
        hasPassword: Boolean(metadata.password),
      };
    });

    return c.json({ success: true, files });
  } catch (error) {
    console.error("Fetch temp files error:", error);
    return c.json({ error: error.message }, 500);
  }
});

// 4. 一時共有ファイル手動削除 API (POST /api/temp-delete)
app.post("/api/temp-delete", async (c) => {
  try {
    const { key } = await c.req.json();
    if (!key) return c.json({ error: "No key provided" }, 400);
    await c.env.TEMP_KV.delete(`temp_${key}`);
    return c.json({ success: true });
  } catch (error) {
    console.error("Delete temp file error:", error);
    return c.json({ error: error.message }, 500);
  }
});

// 5. 一時共有ファイル有効期限24時間延長 API (POST /api/temp-extend)
// stream 型で読み込むことでメモリ使用量を削減（arrayBuffer は 25MB を一度に展開するため）
app.post("/api/temp-extend", async (c) => {
  try {
    const { key } = await c.req.json();
    if (!key) return c.json({ error: "No key provided" }, 400);

    const kvKey = `temp_${key}`;
    const { value, metadata } = await c.env.TEMP_KV.getWithMetadata(kvKey, "stream");
    if (!value) {
      return c.json({ error: "ファイルが見つかりません（すでに期限切れ消滅しています）" }, 404);
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    const currentExp = (metadata && metadata.expiration) ? metadata.expiration : (nowSeconds + 86400);
    const newExp = Math.max(nowSeconds + 60, currentExp + 86400);
    const newTtl = newExp - nowSeconds;

    await c.env.TEMP_KV.put(kvKey, value, {
      expirationTtl: newTtl,
      metadata: {
        ...metadata,
        expiration: newExp,
      },
    });

    return c.json({ success: true, newRemaining: newTtl });
  } catch (error) {
    console.error("Extend temp file error:", error);
    return c.json({ error: error.message }, 500);
  }
});

// 6. 一時共有ファイルパスワード設定・変更 API (POST /api/temp-set-password)
// stream 型で読み込むことでメモリ使用量を削減
app.post("/api/temp-set-password", async (c) => {
  try {
    const { key, password } = await c.req.json();
    if (!key) return c.json({ error: "No key provided" }, 400);

    const kvKey = `temp_${key}`;
    const { value, metadata } = await c.env.TEMP_KV.getWithMetadata(kvKey, "stream");
    if (!value) {
      return c.json({ error: "ファイルが見つかりません" }, 404);
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    const currentExp = (metadata && metadata.expiration) ? metadata.expiration : (nowSeconds + 86400);
    const newTtl = Math.max(60, currentExp - nowSeconds);

    await c.env.TEMP_KV.put(kvKey, value, {
      expirationTtl: newTtl,
      metadata: {
        ...metadata,
        password: password || "",
      },
    });

    return c.json({ success: true, hasPassword: Boolean(password) });
  } catch (error) {
    console.error("Set password error:", error);
    return c.json({ error: error.message }, 500);
  }
});

// 7. 一時共有ファイルリネーム API (POST /api/temp-rename)
// stream 型で読み込むことでメモリ使用量を削減
app.post("/api/temp-rename", async (c) => {
  try {
    const { oldKey, newName } = await c.req.json();
    if (!oldKey || !newName) {
      return c.json({ error: "Missing oldKey or newName" }, 400);
    }

    const oldKvKey = `temp_${oldKey}`;
    const { value, metadata } = await c.env.TEMP_KV.getWithMetadata(oldKvKey, "stream");
    if (!value) {
      return c.json({ error: "ファイルが見つかりません" }, 404);
    }

    // 拡張子を分離・保持
    const oldExt = oldKey.includes(".") ? "." + oldKey.split(".").pop() : "";
    let cleanNewName = newName.replace(/[\/\\]/g, "_");

    if (oldExt && !cleanNewName.toLowerCase().endsWith(oldExt.toLowerCase())) {
      cleanNewName += oldExt;
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    const expTime = (metadata && metadata.expiration) ? metadata.expiration : (nowSeconds + 259200);
    const ttlSeconds = Math.max(60, expTime - nowSeconds);

    const newKvKey = `temp_${cleanNewName}`;
    await c.env.TEMP_KV.put(newKvKey, value, {
      expirationTtl: ttlSeconds,
      metadata: {
        ...(metadata || {}),
        filename: cleanNewName,
      },
    });

    if (oldKvKey !== newKvKey) {
      await c.env.TEMP_KV.delete(oldKvKey);
    }

    return c.json({ success: true, newKey: cleanNewName });
  } catch (error) {
    console.error("Rename temp file error:", error);
    return c.json({ error: error.message }, 500);
  }
});

export default app;
