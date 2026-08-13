# ⚙️ BYOC Worker (Cloudflare Workers Backend)

Lightweight, secure, and self-hosted temporary storage backend (Cloudflare Workers + KV) designed for [BYOC Converter](https://okpn.github.io/byoc-converter/).

Built with a **Bring Your Own Key (BYOK) / Bring Your Own Infrastructure (BYOI)** architecture. Users deploy this worker to their own free Cloudflare accounts to unlock private temporary file storage without any maintainer costs.

---

## 🚀 Setup & Deployment Guide

### 1. Clone Repository & Install Dependencies

```bash
git clone https://github.com/OKPN/byoc-worker.git
cd byoc-worker
npm install
```

---

### 2. Create Cloudflare KV Namespace

Create a KV Namespace via Wrangler CLI or Cloudflare Dashboard:

```bash
npx wrangler kv namespace create TEMP_KV
```

Copy the generated `id` into your `wrangler.toml` file:

```toml
name = "byoc-worker"
main = "server.js"
compatibility_date = "2026-06-28"
workers_dev = true

routes = [
  { pattern = "your-custom-domain.com", custom_domain = true }
]

[[kv_namespaces]]
binding = "TEMP_KV"
id = "YOUR_KV_NAMESPACE_ID_HERE"
```

---

### 3. Configure API Authentication Token 🔐

To prevent unauthorized uploads, configure a secret bearer token.

#### 💡 Supported Variable Names
This worker automatically recognizes any of the following environment variable names:
- **`API_TOKEN`** *(Recommended)*
- `AUTH_TOKEN`
- `TOKEN`
- `SECRET_TOKEN`
- `api_token`

#### Method A) Via CLI (Wrangler)
```bash
npx wrangler secret put API_TOKEN
```
When prompted, enter your desired secret token string (e.g., `my-secret-token-12345`).

#### Method B) Via Cloudflare Dashboard
1. Log into [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Navigate to **Workers & Pages** ➔ Select your Worker (`byoc-worker`)
3. Go to **Settings** ➔ **Variables and Secrets**
4. Click **Add**:
   - **Variable Name**: `API_TOKEN` *(or `AUTH_TOKEN`, `TOKEN`, `SECRET_TOKEN`)*
   - **Type**: `Secret` or `Text`
   - **Value**: Your secret token string
5. Click **Save and Deploy**

---

### 4. Deploy Worker

```bash
npx wrangler deploy
```

Upon successful deployment, your Worker endpoint URL (e.g., `https://byoc-worker.xxx.workers.dev`) will be generated.

---

### 🌐 Custom Domain Setup (Optional)

If you want to serve your uploaded files using your own custom domain (e.g., `img.yourdomain.com`) instead of the default `.workers.dev` subdomain:

1. Open [Cloudflare Dashboard](https://dash.cloudflare.com/) ➔ **Workers & Pages**
2. Select your Worker (`byoc-worker`)
3. Go to **Settings** ➔ **Triggers** ➔ **Custom Domains**
4. Click **Add Custom Domain** and enter your domain name (e.g., `img.yourdomain.com`).

*(Cloudflare will automatically configure DNS records and manage free SSL certificates for your domain.)*

---

## 🌐 Connecting to BYOC Converter

1. Open [BYOC Converter](https://okpn.github.io/byoc-converter/)
2. Expand the **`☁️ Cloudflare Information`** accordion at the bottom of the settings panel
3. Enter your credentials and click **"Save Settings"**:
   - **Worker Endpoint URL**: `https://byoc-worker.xxx.workers.dev` *(or custom domain)*
   - **API Token**: The secret token string configured above
4. Once verified, `✅ Configured` will appear, enabling temporary cloud storage actions.

---

## 📡 Dedicated Upload API (`POST /api/upload`)

A lightweight REST endpoint designed to directly upload images and videos from external applications, CLI tools, 5ch browsers, or custom scripts and receive a direct shareable URL.

### 🛡️ Key Features & Security Design

- **Granular Privilege Separation (`UPLOAD_TOKEN`)**: Configure an optional `UPLOAD_TOKEN` via `npx wrangler secret put UPLOAD_TOKEN`. Requests using `UPLOAD_TOKEN` can **only** upload files. Attempts to list or delete files with this token are strictly rejected (`401 Unauthorized`).
- **Privacy Protection (Automatic Key Randomization)**: Original file names (e.g., `Screenshot_2026_LINE.jpg`) are stripped to prevent privacy leaks (doxxing) and key collisions. Files are assigned a cryptographically secure 8-character random string (e.g., `3c5e5f2q.jpg`).
- **Rate Limiting**: Built-in edge rate limiter restricts uploads to a maximum of 10 requests per minute per IP to prevent spam attacks and quota exhaustion.
- **Format Validation**: Accepts image and video files (`jpg`, `jpeg`, `png`, `webp`, `gif`, `avif`, `mp4`, `webm`, `mov`, etc.) up to 25MB per file.

### 📥 Endpoint Specification

```http
POST /api/upload
Authorization: Bearer <UPLOAD_TOKEN or API_TOKEN>
Content-Type: multipart/form-data
```

#### Request Parameters (`multipart/form-data`)

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `file` (or `image`) | File | **Yes** | Image or video file to upload (max 25MB). |
| `password` | String | Optional | Set a viewing password for authorization. |
| `ttl` | Integer | Optional | Expiration time in seconds (default: `259200` = 3 days). |

#### 💻 cURL Example

```bash
curl -X POST "https://your-worker-domain.com/api/upload" \
  -H "Authorization: Bearer YOUR_UPLOAD_TOKEN" \
  -F "file=@/path/to/image.jpg"
```

#### 📤 Response Example (`200 OK`)

```json
{
  "success": true,
  "url": "https://kv.k7m.f5.si/3c5e5f2q.jpg",
  "key": "3c5e5f2q.jpg",
  "ttl": 259200,
  "hasPassword": false
}
```

---

## 🛡️ Security & Privacy Features

- **Root & Expired 404 Gacha Asset**: Direct requests to `GET /` or expired files serve dynamic random 404 pixel art images (`404.webp`, `404-cat.jpg`, `404-robot.jpg`) cached for 30 days on Cloudflare Edge.
- **Non-Blocking Background Purge Cache**: Immediate Cloudflare CDN Edge Cache purge via `ctx.waitUntil` (Pattern B) upon file upload and delete.
- **Bearer Token Authorization**: Protected endpoints require `API_TOKEN` or `UPLOAD_TOKEN`. Unauthorized requests return `401 Unauthorized`.
- **Automatic Expiration (TTL)**: Files automatically expire and are permanently purged from KV storage based on the selected TTL (1 to 7 days).
