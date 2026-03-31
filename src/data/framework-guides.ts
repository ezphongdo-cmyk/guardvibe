export interface SecurityGuide {
  topic: string;
  keywords: string[];
  title: string;
  content: string;
}

// NOTE: Code examples below intentionally show BOTH vulnerable and safe patterns
// for educational purposes. This is security documentation, not application code.

export const frameworkGuides: SecurityGuide[] = [
  {
    topic: "owasp",
    keywords: ["owasp", "top 10", "top10", "web security", "common vulnerabilities"],
    title: "OWASP Top 10:2025 - Quick Reference",
    content: `# OWASP Top 10:2025

| # | Risk | Description |
|---|------|-------------|
| A01 | **Broken Access Control** | Users act outside intended permissions |
| A02 | **Injection** | SQL, NoSQL, OS, LDAP injection via untrusted data |
| A03 | **Software Supply Chain Failures** | Compromised dependencies, build pipelines |
| A04 | **Insecure Design** | Missing security controls in architecture |
| A05 | **Security Misconfiguration** | Default configs, open cloud storage, verbose errors |
| A06 | **Vulnerable and Outdated Components** | Components with known vulnerabilities |
| A07 | **Identification & Auth Failures** | Weak authentication, session management |
| A08 | **Software & Data Integrity Failures** | Insecure deserialization, unsigned updates |
| A09 | **Security Logging & Monitoring Failures** | Insufficient logging and alerting |
| A10 | **Server-Side Request Forgery (SSRF)** | Server fetches attacker-controlled URLs |

## Quick Wins for Vibe-Coders

1. **Always use parameterized queries** - never concatenate user input into SQL
2. **Use helmet** for Express apps - one line adds 11 security headers
3. **Hash passwords with bcrypt** - never MD5 or SHA-1
4. **Validate all input** - use zod, joi, or yup schemas
5. **Set cookie flags** - secure, httpOnly, sameSite: 'strict'
6. **Add rate limiting** - especially on auth endpoints
7. **Keep dependencies updated** - run npm audit weekly
8. **Never expose secrets** - use environment variables`,
  },

  {
    topic: "express",
    keywords: ["express", "expressjs", "node", "nodejs", "api", "rest", "backend"],
    title: "Express.js Security Best Practices",
    content: `# Express.js Security Best Practices

## 1. Use Helmet (Security Headers)
\`\`\`
npm install helmet
\`\`\`
\`\`\`javascript
import helmet from 'helmet';
app.use(helmet());
// Sets: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and more.
\`\`\`

## 2. Rate Limiting
\`\`\`javascript
import rateLimit from 'express-rate-limit';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
});
app.use('/api/', limiter);

// Stricter for auth endpoints
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
app.use('/api/login', authLimiter);
\`\`\`

## 3. Input Validation with Zod
\`\`\`javascript
import { z } from 'zod';

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(128),
});

app.post('/api/login', (req, res) => {
  const result = loginSchema.safeParse(req.body);
  if (!result.success) return res.status(400).json({ error: result.error });
  // proceed with validated data: result.data
});
\`\`\`

## 4. CORS Configuration
\`\`\`javascript
import cors from 'cors';
// GOOD: specific origins
app.use(cors({
  origin: ['https://myapp.com'],
  methods: ['GET', 'POST'],
  credentials: true,
}));
// BAD: cors({ origin: '*' }) with authentication
\`\`\`

## 5. Secure Session/Cookie Config
\`\`\`javascript
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,       // HTTPS only
    httpOnly: true,      // no JS access
    sameSite: 'strict',  // CSRF protection
    maxAge: 3600000,     // 1 hour
  },
  resave: false,
  saveUninitialized: false,
}));
\`\`\`

## 6. Error Handling (Don't Leak Info)
\`\`\`javascript
// GOOD: generic error to user, detailed log internally
app.use((err, req, res, next) => {
  console.error(err); // log internally
  res.status(500).json({ error: 'Internal server error' });
});
\`\`\``,
  },

  {
    topic: "nextjs",
    keywords: ["next", "nextjs", "next.js", "react", "ssr", "server components", "app router"],
    title: "Next.js Security Best Practices",
    content: `# Next.js Security Best Practices

## 1. Server Components: Don't Leak Secrets
Server Components run on the server but be careful not to pass secrets to Client Components.

\`\`\`typescript
// SAFE: use server action, only data reaches client
'use server'
export async function fetchData() {
  const res = await fetch(url, {
    headers: { Authorization: process.env.SECRET_KEY }
  });
  return res.json();
}
\`\`\`

## 2. Server Actions: Validate Everything
\`\`\`typescript
'use server'
import { z } from 'zod';

const schema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().max(10000),
});

export async function createPost(formData: FormData) {
  const result = schema.safeParse({
    title: formData.get('title'),
    content: formData.get('content'),
  });
  if (!result.success) throw new Error('Invalid input');
  // proceed with result.data
}
\`\`\`

## 3. CSRF Protection
Next.js Server Actions include built-in CSRF protection via Origin header checking.
For Route Handlers with cookie-based auth, add manual CSRF tokens.

## 4. Authentication with Proxy (Next.js 16+)
\`\`\`typescript
// proxy.ts (Next.js 16+)
import { auth } from './lib/auth';

export default async function proxy(request: Request) {
  const session = await auth();
  const { pathname } = new URL(request.url);
  if (pathname.startsWith('/dashboard') && !session) {
    return Response.redirect(new URL('/login', request.url));
  }
}
\`\`\`

## 5. Security Headers
\`\`\`typescript
// next.config.ts
const securityHeaders = [
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
];
export default {
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }];
  },
};
\`\`\`

## 6. Environment Variables
- Prefix with NEXT_PUBLIC_ ONLY for truly public values
- Never put secrets in NEXT_PUBLIC_ variables
- Use .env.local for local secrets (gitignored by default)`,
  },

  {
    topic: "sql-injection",
    keywords: ["sql", "injection", "database", "query", "postgres", "mysql", "sqlite", "prisma", "drizzle"],
    title: "SQL Injection Prevention Guide",
    content: `# SQL Injection Prevention

SQL injection allows attackers to read, modify, or delete your entire database.

## The Fix: Parameterized Queries

### Node.js (pg)
\`\`\`javascript
// SAFE: parameterized query
const { rows } = await db.query(
  'SELECT * FROM users WHERE id = $1',
  [userId]
);
\`\`\`

### Prisma (Recommended ORM)
\`\`\`javascript
const user = await prisma.user.findUnique({
  where: { id: userId },
});
\`\`\`

### Drizzle ORM
\`\`\`javascript
const user = await db.select()
  .from(users)
  .where(eq(users.id, userId));
\`\`\`

### Python (psycopg2)
\`\`\`python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
\`\`\`

## Key Rules
1. **Never concatenate** user input into SQL strings
2. **Always use parameterized queries** or an ORM
3. **Apply least privilege** - DB user should only have needed permissions
4. **Validate input types** - if expecting a number, parse it first`,
  },

  {
    topic: "xss",
    keywords: ["xss", "cross-site scripting", "script injection", "sanitize", "html"],
    title: "XSS (Cross-Site Scripting) Prevention",
    content: `# XSS Prevention Guide

XSS allows attackers to inject malicious scripts into pages viewed by other users.

## Types
1. **Reflected** - malicious script in URL parameters
2. **Stored** - malicious script saved in database
3. **DOM-based** - script manipulates the DOM directly

## React / Next.js
React escapes content by default, which is the safest approach:
\`\`\`jsx
// SAFE - React auto-escapes
<div>{userContent}</div>
\`\`\`

If you MUST render HTML, sanitize it first:
\`\`\`javascript
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(dirtyHtml);
\`\`\`

## Vanilla JavaScript
\`\`\`javascript
// SAFE: use textContent for user-supplied data
element.textContent = userInput;
\`\`\`

## Content Security Policy
Add CSP headers to block inline scripts:
\`\`\`
Content-Security-Policy: default-src 'self'; script-src 'self';
\`\`\`

## Key Rules
1. Use **textContent** instead of innerHTML where possible
2. **Sanitize HTML** with DOMPurify if rendering is needed
3. **Set CSP headers** to prevent inline script execution
4. **Encode output** based on context (HTML, URL, JS, CSS)`,
  },

  {
    topic: "authentication",
    keywords: ["auth", "authentication", "login", "password", "jwt", "session", "bcrypt", "oauth", "clerk"],
    title: "Authentication Security Guide",
    content: `# Authentication Security Guide

## Password Hashing
\`\`\`javascript
import bcrypt from 'bcrypt';

// Hash password (registration) - use 12+ salt rounds
const hash = await bcrypt.hash(password, 12);

// Verify password (login)
const isValid = await bcrypt.compare(password, hash);
\`\`\`

**Never use:** MD5, SHA-1, SHA-256 for passwords. They're too fast to brute-force.

## JWT Best Practices
\`\`\`javascript
import jwt from 'jsonwebtoken';

// Always set expiration
const token = jwt.sign(
  { userId: user.id, role: user.role },
  process.env.JWT_SECRET,
  { expiresIn: '15m' }
);

const payload = jwt.verify(token, process.env.JWT_SECRET);
\`\`\`

**Rules:**
- Always set expiresIn
- Use strong secrets (256+ bits)
- Store refresh tokens in httpOnly cookies
- Never store JWTs in localStorage (XSS risk)

## OAuth / Third-Party Auth (Recommended)
For most apps, use a managed auth provider:
- **Clerk** - best for Next.js/Vercel
- **Auth0** - enterprise-grade
- **Supabase Auth** - if using Supabase

This eliminates password storage, MFA implementation, and session management.

## Session Security
\`\`\`javascript
// Always set all security flags on session cookies
{
  secure: true,        // HTTPS only
  httpOnly: true,       // no JavaScript access
  sameSite: 'strict',   // CSRF protection
  maxAge: 3600000,      // 1 hour
}
\`\`\``,
  },

  {
    topic: "fastapi",
    keywords: ["fastapi", "python", "api", "pydantic", "starlette"],
    title: "FastAPI Security Best Practices",
    content: `# FastAPI Security Best Practices

## 1. Input Validation with Pydantic
\`\`\`python
from pydantic import BaseModel, EmailStr, Field

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: str = Field(min_length=1, max_length=100)

@app.post("/users")
async def create_user(user: UserCreate):
    # user is already validated by Pydantic
    pass
\`\`\`

## 2. CORS Configuration
\`\`\`python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://myapp.com"],  # never use "*"
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization"],
)
\`\`\`

## 3. Rate Limiting
\`\`\`python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request):
    pass
\`\`\`

## 4. SQL Injection Prevention
\`\`\`python
# Use SQLAlchemy ORM - never raw SQL with f-strings
from sqlalchemy.orm import Session

def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()
\`\`\`

## 5. Environment Variables
\`\`\`python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    secret_key: str
    database_url: str
    class Config:
        env_file = ".env"
\`\`\``,
  },

  {
    topic: "react",
    keywords: ["react", "reactjs", "component", "hook", "jsx", "tsx", "frontend", "client"],
    title: "React Security Best Practices",
    content: `# React Security Best Practices

## 1. React Auto-Escapes by Default (Use This!)
\`\`\`jsx
// SAFE - React auto-escapes content
<div>{userContent}</div>
\`\`\`

If HTML rendering is needed, always sanitize:
\`\`\`javascript
import DOMPurify from 'dompurify';
const cleanHtml = DOMPurify.sanitize(untrustedContent);
\`\`\`

## 2. Validate URL Parameters
\`\`\`jsx
// SAFE: validate before using
const redirect = searchParams.get('redirect');
const safeUrl = redirect?.startsWith('/') ? redirect : '/';
<a href={safeUrl}>Click</a>
\`\`\`

## 3. Secure API Calls
\`\`\`javascript
const res = await fetch('/api/data', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken,
  },
  credentials: 'same-origin',
  body: JSON.stringify(data),
});
\`\`\`

## 4. Secure State Management
- Never store sensitive data (tokens, passwords) in React state
- Use httpOnly cookies for auth tokens
- Clear sensitive data on logout

## 5. Dependency Security
\`\`\`
npm audit        # check for known vulnerabilities
npm audit fix    # auto-fix where possible
\`\`\``,
  },

  {
    topic: "env",
    keywords: ["env", "environment", "variables", "secrets", "dotenv", ".env", "api key", "credentials"],
    title: "Environment Variables & Secrets Management",
    content: `# Environment Variables & Secrets Management

## Golden Rules
1. **Never commit .env files** to git
2. **Never prefix secrets** with NEXT_PUBLIC_ or VITE_
3. **Use different secrets** per environment (dev/staging/prod)
4. **Rotate secrets regularly**

## .gitignore (Must Have)
\`\`\`
.env
.env.local
.env.*.local
\`\`\`

## Access Patterns
\`\`\`javascript
// Validate at startup - fail fast if missing
const secret = process.env.DATABASE_URL;
if (!secret) {
  throw new Error('DATABASE_URL is required');
}
\`\`\`

## Vercel / Production
\`\`\`
vercel env pull .env.local   # Pull env vars from Vercel
vercel env add SECRET_NAME   # Add a secret
\`\`\`

## For Vibe-Coders
When your AI generates code with hardcoded secrets:
1. **Stop and move them to .env**
2. Replace with process.env.VARIABLE_NAME
3. Add .env to .gitignore
4. Tell your AI: "Use environment variables for secrets"`,
  },

  {
    topic: "django",
    title: "Django Security Best Practices",
    keywords: ["django", "python", "csrf", "orm", "settings", "allowed_hosts"],
    content: `# Django Security Best Practices

## Critical Settings
\`\`\`python
# settings.py
DEBUG = False  # NEVER True in production
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']  # Never hardcode
ALLOWED_HOSTS = ['myapp.com']  # Never use ['*']
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
\`\`\`

## CSRF Protection
Django includes CSRF middleware by default. Never disable it.
\`\`\`python
# Views that modify data need @csrf_protect or use CsrfViewMiddleware
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def update_profile(request):
    pass
\`\`\`

## ORM Injection Prevention
Always use Django ORM — avoid raw SQL:
\`\`\`python
# Safe - ORM parameterizes automatically
User.objects.filter(name=user_input)

# Dangerous - raw SQL with interpolation
User.objects.raw(f"SELECT * FROM users WHERE name = '{user_input}'")

# If raw SQL needed, use params:
User.objects.raw("SELECT * FROM users WHERE name = %s", [user_input])
\`\`\`

## Authentication
\`\`\`python
from django.contrib.auth.decorators import login_required

@login_required
def dashboard(request):
    pass
\`\`\`

## Password Hashing
Django uses PBKDF2 by default. Upgrade to Argon2:
\`\`\`python
# settings.py
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
]
\`\`\`
`,
  },

  {
    topic: "nestjs",
    title: "NestJS Security Best Practices",
    keywords: ["nestjs", "nest", "guard", "pipe", "helmet", "validation"],
    content: `# NestJS Security Best Practices

## Helmet
\`\`\`typescript
import helmet from 'helmet';
app.use(helmet());
\`\`\`

## CORS
\`\`\`typescript
app.enableCors({
  origin: ['https://myapp.com'],
  credentials: true,
});
\`\`\`

## Validation Pipe (Global)
\`\`\`typescript
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,       // Strip unknown properties
  forbidNonWhitelisted: true,
  transform: true,
}));
\`\`\`

## Auth Guard
\`\`\`typescript
@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    return validateToken(request.headers.authorization);
  }
}

// Apply globally or per-route
@UseGuards(AuthGuard)
@Controller('api')
export class ApiController {}
\`\`\`

## Rate Limiting
\`\`\`typescript
import { ThrottlerModule } from '@nestjs/throttler';
@Module({
  imports: [ThrottlerModule.forRoot({ ttl: 60, limit: 10 })],
})
\`\`\`

## Environment Variables
\`\`\`typescript
import { ConfigModule } from '@nestjs/config';
@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true })],
})
// Use: configService.get('DATABASE_URL')
\`\`\`
`,
  },

  {
    topic: "hono",
    title: "Hono Security Best Practices",
    keywords: ["hono", "edge", "middleware", "cloudflare", "bun"],
    content: `# Hono Security Best Practices

## CORS
\`\`\`typescript
import { cors } from 'hono/cors';
app.use('*', cors({
  origin: ['https://myapp.com'],
  credentials: true,
}));
\`\`\`

## Auth Middleware
\`\`\`typescript
import { bearerAuth } from 'hono/bearer-auth';
app.use('/api/*', bearerAuth({ token: process.env.API_TOKEN! }));

// Or custom JWT auth:
app.use('/api/*', async (c, next) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '');
  if (!token || !verifyJwt(token)) return c.json({ error: 'Unauthorized' }, 401);
  await next();
});
\`\`\`

## Input Validation
\`\`\`typescript
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';

app.post('/api/users', zValidator('json', z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100),
})), async (c) => {
  const data = c.req.valid('json');
});
\`\`\`

## Rate Limiting
\`\`\`typescript
import { rateLimiter } from 'hono-rate-limiter';
app.use(rateLimiter({ windowMs: 15 * 60 * 1000, limit: 100 }));
\`\`\`

## Secure Headers
\`\`\`typescript
import { secureHeaders } from 'hono/secure-headers';
app.use('*', secureHeaders());
\`\`\`
`,
  },

  {
    topic: "supabase",
    title: "Supabase Security Best Practices",
    keywords: ["supabase", "rls", "row level security", "postgres", "auth"],
    content: `# Supabase Security Best Practices

## Row Level Security (RLS) — CRITICAL
Always enable RLS on every table:
\`\`\`sql
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Users can only read their own profile
CREATE POLICY "Users read own profile"
  ON profiles FOR SELECT
  USING (auth.uid() = user_id);

-- Users can only update their own profile
CREATE POLICY "Users update own profile"
  ON profiles FOR UPDATE
  USING (auth.uid() = user_id);
\`\`\`

## Anon Key vs Service Key
\`\`\`typescript
// Client-side: use anon key (safe to expose, RLS enforced)
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

// Server-side only: service key (bypasses RLS!)
const admin = createClient(url, process.env.SUPABASE_SERVICE_KEY!);
// NEVER expose service key to the client
\`\`\`

## Auth
\`\`\`typescript
// Always check auth on server
const { data: { user } } = await supabase.auth.getUser();
if (!user) throw new Error('Unauthorized');
\`\`\`

## API Security
\`\`\`typescript
// Validate input before database operations
const schema = z.object({ title: z.string().max(200) });
const input = schema.parse(body);
await supabase.from('posts').insert(input);
\`\`\`
`,
  },

  {
    topic: "trpc",
    title: "tRPC Security Best Practices",
    keywords: ["trpc", "procedure", "middleware", "zod", "typesafe"],
    content: `# tRPC Security Best Practices

## Input Validation
Always validate with zod:
\`\`\`typescript
export const appRouter = router({
  createUser: publicProcedure
    .input(z.object({
      email: z.string().email(),
      name: z.string().min(1).max(100),
    }))
    .mutation(async ({ input }) => {
      // input is validated and typed
    }),
});
\`\`\`

## Auth Middleware
\`\`\`typescript
const isAuthed = t.middleware(({ ctx, next }) => {
  if (!ctx.session?.user) {
    throw new TRPCError({ code: 'UNAUTHORIZED' });
  }
  return next({ ctx: { user: ctx.session.user } });
});

const protectedProcedure = t.procedure.use(isAuthed);

// Use for protected routes
export const appRouter = router({
  getProfile: protectedProcedure.query(({ ctx }) => {
    return db.user.findUnique({ where: { id: ctx.user.id } });
  }),
});
\`\`\`

## Rate Limiting
\`\`\`typescript
const rateLimiter = t.middleware(async ({ ctx, next }) => {
  const ip = ctx.req.headers['x-forwarded-for'] || 'unknown';
  const { success } = await ratelimit.limit(ip);
  if (!success) throw new TRPCError({ code: 'TOO_MANY_REQUESTS' });
  return next();
});
\`\`\`

## Error Handling
Never expose internal errors:
\`\`\`typescript
// tRPC automatically masks internal errors in production
// Only TRPCError messages are sent to client
throw new TRPCError({
  code: 'BAD_REQUEST',
  message: 'Invalid input', // Safe user-facing message
});
\`\`\`
`,
  },
];
