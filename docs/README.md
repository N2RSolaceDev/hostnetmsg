# HostNet.wiki – The British Discord

> **Built by one person. For everyone who means business.**  
> No team. No funding. Just code, willpower, and the belief that communication should be private, powerful, and British.

HostNet is a **fully independent, real-time communication platform** built on the identity of `@unfiltereduk.co.uk`. It combines the best of **Discord**, **Gmail**, and **end-to-end privacy** into a single, self-hosted solution.

This is not a clone.  
This is a **reimagining** — built from the ground up with **no MongoDB for messages**, **real-time WebSocket architecture**, and **military-grade security**.

Deployable for free on **Priv server**, this is the future of private digital interaction.

---

## 🔧 Features

- ✅ **Real-time chat** (text, voice, video)
- ✅ **No persistent message storage** (ephemeral by design)
- ✅ **British identity** (`@unfiltereduk.co.uk` only)
- ✅ **Owner-controlled** (`solace@unfiltereduk.co.uk`)
- ✅ **Anti-DDoS, rate limiting, XSS protection**
- ✅ **Admin moderation panel** (reports, bans, mutes)
- ✅ **Report system with 3 actions**: Ignore, Accept, Delete
- ✅ **Self-hosted, free on Render**
- ✅ **Built solo** — no team, no help, just one person

---

## 🚀 Quick Start

1. Clone the repo
2. Create `.env` with `JWT_SECRET` and `PORT`
3. Run `npm install && node server.js`
4. Open `http://localhost:10000`

---

## 🛠️ Tech Stack

- **Node.js + Express** – Backend
- **WebSocket** – Real-time messaging (no Socket.IO bloat)
- **In-Memory Storage** – No MongoDB for messages
- **JWT + Bcrypt** – Authentication
- **Render** – Free hosting
- **Frontend** – Vanilla HTML/CSS/JS (no frameworks)

---

## 📄 Documentation

- [`API.md`](API.md) – REST & WebSocket endpoints
- [`SECURITY.md`](SECURITY.md) – Security model, encryption, trust

---

## 📝 Note from the Creator

> I built this alone.  
> Every line. Every fix. Every 3 AM debugging session.  
> This is mine.  
> 
> 🔒 **Do not steal. Do not claim. Do not judge.**  
> If you use this, **respect the work behind it.**  
> 
> Made with pain, purpose, and the quiet hope that something built alone can still mean something to someone.  
> — **solace@unfiltereduk.co.uk**
