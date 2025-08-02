# HostNet API Reference

All endpoints are prefixed with `/api/`.  
Authentication required unless noted.

---

## 🔐 Authentication

### `POST /api/register`
Register a new user.

**Body:**
```json
{
  "email": "you@unfiltereduk.co.uk",
  "password": "secure123",
  "fullName": "John Doe"
}
