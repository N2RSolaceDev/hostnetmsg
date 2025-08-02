
---

## ✅ `docs/SECURITY.md`

```markdown
# Security Model – HostNet.wiki

> _"I spent 72 hours reading RFCs so you wouldn’t have to."_

HostNet is built with **defense-in-depth** principles. Every layer is hardened.

---

## 🔐 Authentication

- **JWT** with 7-day expiry
- **Bcrypt** (salt rounds: 10)
- **Rate limiting** on login/register
- **No password recovery** (by design — ephemeral identity)

---

## 🛡️ Server Hardening

- **Helmet.js** for HTTP security headers
- **CORS** restricted to `hostnet.wiki` and localhost
- **Rate limiting** on all endpoints
- **Input sanitization** using `xss` library
- **No eval, no dynamic require, no shell exec**

---

## 🧠 In-Memory Architecture

- **No MongoDB for messages**
- All messages stored in `Map()` (RAM only)
- Deleted on read or by user
- Server restart = total message wipe

> This is **not a bug**. It’s a feature.  
> Like Snapchat, but for everything.

---

## 🔒 Data Minimization

- No logs stored
- No IP tracking
- No analytics
- No third-party scripts
- No cookies (except JWT in localStorage)

---

## 🚫 Abuse Prevention

- **Report system** with audit trail
- **Admin panel** for moderation
- **Ban & mute** with duration
- **API key system** with expiry and revocation
- **Owner control** (`solace@unfiltereduk.co.uk` only)

---

## 📡 Real-Time Security

- **WebSocket authentication** required
- **Message ownership check** on delete
- **Admin-only routes** enforced
- **No message forwarding** outside intended recipient

---

## 🏁 Deployment Security

- **Free on Render** (no SSH, no shell)
- **Environment variables** never exposed
- **No /admin UI** — all actions via API
- **No backups** — by design

---

## 📝 Final Note

> I built this alone.  
> I reviewed every dependency.  
> I wrote every line of security logic.  
> 
> This is not corporate software.  
> This is **personal software** — built for trust, not profit.
> 
> — **solace@unfiltereduk.co.uk**
