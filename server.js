const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");

const app = express();
const PORT = Number(process.env.PORT || 5000);
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : __dirname;
const DB_FILE = path.join(DATA_DIR, "resido-db.json");
const BCRYPT_ROUNDS = 10;
const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || "";
const USE_POSTGRES = Boolean(DATABASE_URL);
const APP_STATE_KEY = "main";
const DEFAULT_SERVICE_FEE_PER_APARTMENT = 1.20;

let pgPool = null;
let saveDbQueue = Promise.resolve();

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

app.set("trust proxy", 1);
app.disable("x-powered-by");

const generalRateLimit = createRateLimiter({
  name: "general",
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_GENERAL_PER_MINUTE || 240),
  message: "Too many requests. Please wait a moment and try again."
});

const authRateLimit = createRateLimiter({
  name: "auth",
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_AUTH_PER_15_MINUTES || 8),
  getKey: (req) => `${clientIp(req)}:${norm(req.body?.email)}`,
  message: "Too many login attempts. Please wait before trying again."
});

const passwordResetRateLimit = createRateLimiter({
  name: "password-reset",
  windowMs: 60 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_PASSWORD_RESET_PER_HOUR || 5),
  getKey: (req) => `${clientIp(req)}:${norm(req.body?.email)}`,
  message: "Too many password reset attempts. Please wait before trying again."
});

const sensitiveAccountRateLimit = createRateLimiter({
  name: "sensitive-account",
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_SENSITIVE_PER_15_MINUTES || 20),
  getKey: (req) => `${clientIp(req)}:${req.user?.id || norm(req.body?.email)}`,
  message: "Too many sensitive account changes. Please wait before trying again."
});

const paymentRateLimit = createRateLimiter({
  name: "payment",
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_PAYMENTS_PER_MINUTE || 10),
  getKey: (req) => `${clientIp(req)}:${req.user?.id || "anonymous"}`,
  message: "Too many payment attempts. Please wait before trying again."
});

const writeRateLimit = createRateLimiter({
  name: "write",
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_WRITES_PER_MINUTE || 60),
  getKey: (req) => `${clientIp(req)}:${req.user?.id || "anonymous"}`,
  message: "Too many changes. Please wait before trying again."
});

app.use(securityHeaders);
app.use(generalRateLimit);

app.use(cors({
  origin: ["http://127.0.0.1:5500", "http://localhost:5500", process.env.FRONTEND_ORIGIN].filter(Boolean),
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.post("/stripe/webhook", express.raw({ type: "application/json" }), handleStripeWebhook);

app.use(express.json({ limit: "15mb" }));

const norm = (v) => String(v || "").trim().toLowerCase();
const cleanText = (v) => String(v || "").trim();
const today = () => new Date().toISOString().slice(0, 10);
const nextId = (arr) => arr.length ? Math.max(...arr.map(x => Number(x.id) || 0)) + 1 : 1;
const digitsOnly = (v) => String(v || "").replace(/\D/g, "");
const RESET_TOKEN_TTL_MS = Math.max(5, Number(process.env.RESET_TOKEN_TTL_MINUTES || 30)) * 60 * 1000;
const EMAIL_CHANGE_TOKEN_TTL_MS = Math.max(5, Number(process.env.EMAIL_CHANGE_TOKEN_TTL_MINUTES || 30)) * 60 * 1000;
const AUTH_SECRET = cleanText(process.env.AUTH_SECRET || process.env.SESSION_SECRET);
const AUTH_TOKEN_TTL_MS = Math.max(1, Number(process.env.AUTH_TOKEN_TTL_DAYS || 30)) * 24 * 60 * 60 * 1000;
const STRIPE_SECRET_KEY = cleanText(process.env.STRIPE_SECRET_KEY);
const STRIPE_WEBHOOK_SECRET = cleanText(process.env.STRIPE_WEBHOOK_SECRET);
const STRIPE_REQUIRE_CONNECT = String(process.env.STRIPE_REQUIRE_CONNECT || "true").toLowerCase() !== "false";
const CARD_PROCESSING_PERCENT = Math.max(0, Number(process.env.CARD_PROCESSING_PERCENT || 1.5));
const CARD_PROCESSING_FIXED_CENTS = Math.max(0, Math.round(Number(process.env.CARD_PROCESSING_FIXED_CENTS || 26)));
const PASS_CARD_FEES_TO_RESIDENT = String(process.env.PASS_CARD_FEES_TO_RESIDENT || "true").toLowerCase() !== "false";
const ALLOW_DEMO_CARD_PAYMENTS = String(process.env.ALLOW_DEMO_CARD_PAYMENTS || "false").toLowerCase() === "true";
const ALLOW_WEAK_PASSWORDS = String(process.env.ALLOW_WEAK_PASSWORDS || "false").toLowerCase() === "true";
const COMMON_WEAK_PASSWORDS = new Set([
  "1234",
  "password",
  "password123",
  "qwerty",
  "admin",
  "admin123",
  "resido",
  "resido123",
  "resido1234"
]);

function isProductionLike() {
  return process.env.NODE_ENV === "production" || process.env.RENDER === "true";
}

function allowDevEmailDetails() {
  if (String(process.env.ALLOW_DEV_EMAIL_LINKS || "").toLowerCase() === "true") return true;
  return !isProductionLike();
}

function securityHeaders(req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

  if (req.secure || req.headers["x-forwarded-proto"] === "https") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }

  next();
}

const rateLimitBuckets = new Map();

function clientIp(req) {
  const forwarded = cleanText(req.headers["x-forwarded-for"]).split(",")[0].trim();
  return forwarded || req.ip || req.socket?.remoteAddress || "unknown";
}

function createRateLimiter({ name, windowMs, max, getKey, message }) {
  return (req, res, next) => {
    if (String(process.env.DISABLE_RATE_LIMITS || "").toLowerCase() === "true") return next();

    const now = Date.now();
    const safeWindowMs = Math.max(1000, Number(windowMs || 60000));
    const safeMax = Math.max(1, Number(max || 60));
    const bucketKey = `${name}:${getKey ? getKey(req) : clientIp(req)}`;
    const existing = rateLimitBuckets.get(bucketKey);
    const bucket = existing && existing.resetAt > now
      ? existing
      : { count: 0, resetAt: now + safeWindowMs };

    bucket.count += 1;
    rateLimitBuckets.set(bucketKey, bucket);

    if (rateLimitBuckets.size > 5000) {
      for (const [key, value] of rateLimitBuckets.entries()) {
        if (value.resetAt <= now) rateLimitBuckets.delete(key);
      }
    }

    const retryAfter = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
    res.setHeader("X-RateLimit-Limit", String(safeMax));
    res.setHeader("X-RateLimit-Remaining", String(Math.max(0, safeMax - bucket.count)));
    res.setHeader("X-RateLimit-Reset", String(Math.ceil(bucket.resetAt / 1000)));

    if (bucket.count > safeMax) {
      res.setHeader("Retry-After", String(retryAfter));
      return res.status(429).json({ message });
    }

    next();
  };
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanText(value));
}

function passwordPolicyError(password) {
  const value = String(password || "");

  if (value.length < 4) return "Password must be at least 4 characters";
  if (value.length > 128) return "Password must be 128 characters or fewer";
  if (!isProductionLike() || ALLOW_WEAK_PASSWORDS) return "";

  if (value.length < 12) return "Production passwords must be at least 12 characters";
  if (COMMON_WEAK_PASSWORDS.has(norm(value))) return "Choose a stronger password";

  return "";
}

function configuredEmail(...names) {
  for (const name of names) {
    const value = norm(process.env[name]);
    if (isValidEmail(value)) return value;
  }
  return "";
}

function htmlEscape(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function normalizeCardBrand(value) {
  const brand = norm(value).replace(/[\s_-]+/g, "");
  if (brand === "master" || brand === "mc" || brand === "mastercard") return "mastercard";
  if (brand === "americanexpress" || brand === "amex") return "amex";
  if (brand === "visaelectron") return "visa-electron";
  if (brand === "vpay") return "vpay";
  if (brand === "discover") return "discover";
  if (brand === "unionpay") return "unionpay";
  if (brand === "maestro") return "maestro";
  if (brand === "jcb") return "jcb";
  if (brand === "samsungpay") return "samsungpay";
  if (brand === "googlepay" || brand === "gpay") return "googlepay";
  if (brand === "applepay") return "applepay";
  if (brand === "borica") return "borica";
  if (brand === "visa") return "visa";
  return brand || "";
}

function detectCardBrand(cardNumber) {
  const digits = digitsOnly(cardNumber);
  const firstTwo = Number(digits.slice(0, 2));
  const firstFour = Number(digits.slice(0, 4));
  const firstSix = Number(digits.slice(0, 6));

  if (/^4/.test(digits)) return "visa";
  if (/^3[47]/.test(digits)) return "amex";
  if ((firstTwo >= 51 && firstTwo <= 55) || (firstFour >= 2221 && firstFour <= 2720)) return "mastercard";
  if (/^35/.test(digits)) return "jcb";
  if (digits.startsWith("6011") || digits.startsWith("65") || (firstSix >= 622126 && firstSix <= 622925) || (firstFour >= 6440 && firstFour <= 6499)) return "discover";
  if (digits.startsWith("62")) return "unionpay";
  if (/^(2205|2200|6761)/.test(digits)) return "borica";
  if (/^(50|5[6-9]|6[0-9])/.test(digits)) return "maestro";
  return "";
}

function maskCardNumber(cardNumber) {
  const digits = digitsOnly(cardNumber).slice(0, 19);
  if (digits.length < 10) return "";
  return `${digits.slice(0, 4)} **** ${digits.slice(-6)}`;
}

function cleanCardMask(value) {
  const text = cleanText(value);
  return /^[0-9]{4}\s\*{4}\s[0-9]{6}$/.test(text) ? text : "";
}

function normalizeIban(value) {
  return cleanText(value).toUpperCase().replace(/\s+/g, "");
}

function isValidIban(value) {
  const iban = normalizeIban(value);
  if (!iban) return true;
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(iban)) return false;

  const rearranged = `${iban.slice(4)}${iban.slice(0, 4)}`;
  let remainder = 0;

  for (const char of rearranged) {
    const chunk = char >= "A" && char <= "Z"
      ? String(char.charCodeAt(0) - 55)
      : char;

    for (const digit of chunk) {
      remainder = (remainder * 10 + Number(digit)) % 97;
    }
  }

  return remainder === 1;
}

function amountToCents(value) {
  const amount = Number(value || 0);
  if (!Number.isFinite(amount) || amount < 0) return 0;
  return Math.round(amount * 100);
}

function centsToAmount(cents) {
  return Math.round(Number(cents || 0)) / 100;
}

function cardProcessingFeeCents(baseCents) {
  if (!PASS_CARD_FEES_TO_RESIDENT) return 0;
  const percent = CARD_PROCESSING_PERCENT / 100;
  if (percent >= 1) return 0;
  const total = Math.ceil((baseCents + CARD_PROCESSING_FIXED_CENTS) / (1 - percent));
  return Math.max(0, total - baseCents);
}

function stripeConfigured() {
  return /^sk_(test|live)_/.test(STRIPE_SECRET_KEY) && /^whsec_/.test(STRIPE_WEBHOOK_SECRET);
}

function stripeConnectAccountId(building) {
  const id = cleanText(building?.stripe_account_id || building?.stripeAccountId);
  return /^acct_[A-Za-z0-9]+$/.test(id) ? id : "";
}

function currentBillingMonth() {
  return today().slice(0, 7);
}

function normalizeServiceBillingCycle(value) {
  const cycle = norm(value).replace(/[\s_-]+/g, "_");
  if (["monthly", "month", "1", "1_month"].includes(cycle)) return "monthly";
  if (["quarterly", "quarter", "3", "3_months"].includes(cycle)) return "quarterly";
  if (["semiannual", "semi_annual", "half_year", "6", "6_months"].includes(cycle)) return "semiannual";
  if (["yearly", "annual", "year", "12", "12_months"].includes(cycle)) return "yearly";
  return "monthly";
}

function serviceCycleMonths(value) {
  return {
    monthly: 1,
    quarterly: 3,
    semiannual: 6,
    yearly: 12
  }[normalizeServiceBillingCycle(value)] || 1;
}

function addMonthsDate(dateText, months) {
  const base = /^\d{4}-\d{2}-\d{2}$/.test(cleanText(dateText))
    ? new Date(`${dateText}T00:00:00Z`)
    : new Date(`${today()}T00:00:00Z`);
  base.setUTCMonth(base.getUTCMonth() + Math.max(1, Number(months || 1)));
  return base.toISOString().slice(0, 10);
}

function normalizeServiceFeeMode(value) {
  const mode = norm(value);
  if (["fixed", "stable", "flat"].includes(mode)) return "fixed";
  return "proportional";
}

function serviceFeePerApartment(building) {
  const rate = Number(building?.service_fee_per_apartment ?? building?.resido_fee_per_apartment ?? DEFAULT_SERVICE_FEE_PER_APARTMENT);
  return Number.isFinite(rate) && rate >= 0 ? rate : DEFAULT_SERVICE_FEE_PER_APARTMENT;
}

function serviceFixedFeeAmount(building) {
  const amount = Number(building?.service_fixed_fee_amount ?? building?.service_fee_amount ?? building?.resido_service_fee ?? 0);
  return Number.isFinite(amount) && amount >= 0 ? amount : 0;
}

function buildingApartmentCount(buildingId, state = db) {
  const ids = new Set();
  (state?.users || []).forEach((user) => {
    if (String(user?.role || "").toLowerCase() !== "resident") return;
    if (String(user?.building_id) !== String(buildingId)) return;
    const apartment = cleanText(user.apartment);
    const floor = cleanText(user.floor);
    ids.add(apartment ? `${floor}:${apartment}` : `resident:${user.id}`);
  });
  return ids.size;
}

function buildingServiceFeeAmount(building, state = db) {
  if (!building || String(building.id) === "all" || building.status === "cancelled") return 0;
  const mode = normalizeServiceFeeMode(building.service_fee_mode);
  if (mode === "fixed") return serviceFixedFeeAmount(building);
  return Math.round((buildingApartmentCount(building.id, state) * serviceFeePerApartment(building)) * 100) / 100;
}

function servicePaidUntil(building) {
  const value = cleanText(building?.service_paid_until || building?.resido_paid_until);
  return /^\d{4}-\d{2}-\d{2}$/.test(value) ? value : "";
}

function platformBankIban() {
  return normalizeIban(db?.platform_settings?.resido_bank_iban || db?.platform_settings?.platform_bank_iban);
}

function isServiceSuspended(buildingId) {
  if (String(buildingId) === "all") return false;
  const building = db?.buildings?.[String(buildingId)];
  if (!building || building.status === "cancelled") return false;
  if (buildingServiceFeeAmount(building) <= 0) return false;
  const paidUntil = servicePaidUntil(building);
  return !paidUntil || paidUntil < today();
}

function servicePaymentSummary(building) {
  const serviceFee = buildingServiceFeeAmount(building);
  const paidUntil = servicePaidUntil(building);
  const mode = normalizeServiceFeeMode(building?.service_fee_mode);

  return {
    service_fee_mode: mode,
    service_fee_per_apartment: serviceFeePerApartment(building),
    service_fixed_fee_amount: serviceFixedFeeAmount(building),
    service_apartment_count: buildingApartmentCount(building?.id),
    service_fee_amount: Number.isFinite(serviceFee) && serviceFee > 0 ? serviceFee : 0,
    service_billing_cycle: normalizeServiceBillingCycle(building?.service_billing_cycle),
    service_paid_until: paidUntil,
    service_currency: "EUR",
    service_payment_required: Boolean(
      building &&
      String(building.id) !== "all" &&
      serviceFee > 0 &&
      (!paidUntil || paidUntil < today())
    )
  };
}

function normalizeBillingMonth(value) {
  const raw = cleanText(value);
  return /^\d{4}-\d{2}$/.test(raw) ? raw : currentBillingMonth();
}

function paymentMonthKey(payment) {
  return cleanText(payment?.billing_month || payment?.payment_month || payment?.date).slice(0, 7);
}

function isPaidPayment(payment) {
  return norm(payment?.status) === "paid";
}

function paymentRecordType(payment) {
  return norm(payment?.payment_type || payment?.method) === "resido_service" ? "resido_service" : "building_fee";
}

function lastDayOfBillingMonth(monthKey) {
  const [yearRaw, monthRaw] = normalizeBillingMonth(monthKey).split("-");
  const year = Number(yearRaw) || new Date().getFullYear();
  const month = Number(monthRaw) || (new Date().getMonth() + 1);
  return new Date(Date.UTC(year, month, 0)).toISOString().slice(0, 10);
}

function paidBuildingFeeExists({ buildingId, email, billingMonth }) {
  const month = normalizeBillingMonth(billingMonth);
  const normalizedEmail = norm(email);
  return db.payments.some((payment) => (
    isPaidPayment(payment) &&
    paymentRecordType(payment) === "building_fee" &&
    String(payment.building_id) === String(buildingId) &&
    norm(payment.resident_email) === normalizedEmail &&
    paymentMonthKey(payment) === month
  ));
}

function paidServiceFeeExists(building, billingMonth) {
  const month = normalizeBillingMonth(billingMonth);
  const buildingId = String(building?.id || "");
  if (!buildingId || buildingId === "all") return false;

  const paidRecord = db.payments.some((payment) => (
    isPaidPayment(payment) &&
    paymentRecordType(payment) === "resido_service" &&
    String(payment.building_id) === buildingId &&
    paymentMonthKey(payment) === month
  ));

  if (paidRecord) return true;
  const paidUntil = servicePaidUntil(building);
  return Boolean(paidUntil && paidUntil >= lastDayOfBillingMonth(month));
}

function serviceAccessMessage() {
  return "Resido service payment is overdue. The building administrator must renew access from the Payments tab.";
}

function serviceRestrictedRequestAllowed(req) {
  if (req.method === "GET" && req.path === "/buildings") return true;
  if (req.method === "GET" && /^\/payments\/[^/]+$/.test(req.path)) return true;
  if (req.method === "POST" && req.path === "/stripe/create-checkout-session") return true;
  return false;
}

function stripeSignaturePayload(header) {
  return String(header || "")
    .split(",")
    .map(part => part.trim().split("="))
    .reduce((acc, [key, value]) => {
      if (key && value) acc[key] = value;
      return acc;
    }, {});
}

function verifyStripeWebhookSignature(rawBody, signatureHeader) {
  if (!/^whsec_/.test(STRIPE_WEBHOOK_SECRET)) return false;

  const signature = stripeSignaturePayload(signatureHeader);
  const timestamp = signature.t;
  const v1 = signature.v1;

  if (!timestamp || !v1) return false;

  const expected = crypto
    .createHmac("sha256", STRIPE_WEBHOOK_SECRET)
    .update(`${timestamp}.${rawBody.toString("utf8")}`)
    .digest("hex");

  const a = Buffer.from(expected);
  const b = Buffer.from(v1);

  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function stripeApiRequest(pathname, params) {
  const response = await fetch(`https://api.stripe.com/v1/${pathname.replace(/^\/+/, "")}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams(params)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data?.error?.message || "Stripe request failed");
  }

  return data;
}

function defaultDb() {
  return {
    buildings: {
      all: {
        id: "all",
        name: "Resido Super Admin",
        address: "Всички сгради / All buildings",
        monthly_fee: 0,
        payment_due_day: 10,
        currency: "EUR",
        bank_iban: "",
        stripe_account_id: "",
        service_fee_mode: "proportional",
        service_fee_per_apartment: DEFAULT_SERVICE_FEE_PER_APARTMENT,
        service_fixed_fee_amount: 0,
        service_fee_amount: 0,
        service_billing_cycle: "monthly",
        service_paid_until: "",
        admin_user_id: null,
        status: "active",
        image: "https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?auto=format&fit=crop&w=1600&q=80"
      },
      1: {
        id: 1,
        name: "Condo A",
        address: "бул. Витоша 32, София",
        monthly_fee: 45,
        payment_due_day: 10,
        currency: "EUR",
        bank_iban: "",
        stripe_account_id: "",
        service_fee_mode: "proportional",
        service_fee_per_apartment: DEFAULT_SERVICE_FEE_PER_APARTMENT,
        service_fixed_fee_amount: 0,
        service_fee_amount: 0,
        service_billing_cycle: "monthly",
        service_paid_until: "",
        admin_user_id: 2,
        status: "active",
        image: "https://images.unsplash.com/photo-1460317442991-0ec209397118?auto=format&fit=crop&w=1600&q=80"
      },
      2: {
        id: 2,
        name: "Condo B",
        address: "бул. Цариградско шосе 89, София",
        monthly_fee: 55,
        payment_due_day: 10,
        currency: "EUR",
        bank_iban: "",
        stripe_account_id: "",
        service_fee_mode: "proportional",
        service_fee_per_apartment: DEFAULT_SERVICE_FEE_PER_APARTMENT,
        service_fixed_fee_amount: 0,
        service_fee_amount: 0,
        service_billing_cycle: "monthly",
        service_paid_until: "",
        admin_user_id: 4,
        status: "active",
        image: "https://images.unsplash.com/photo-1505693416388-ac5ce068fe85?auto=format&fit=crop&w=1600&q=80"
      }
    },

    platform_settings: {
      resido_bank_iban: "",
      currency: "EUR"
    },

    users: [
      {
        id: 1,
        full_name: "Resido Super Admin",
        email: "superadmin@resido.com",
        password: "1234",
        apartment: "ALL",
        floor: "",
        phone: "+359 888 000 000",
        role: "super_admin",
        building_id: "all",
        created_at: "2026-04-01T09:00:00.000Z"
      },
      {
        id: 2,
        full_name: "Admin Condo A",
        email: "admin-a@resido.com",
        password: "1234",
        apartment: "Admin",
        floor: "",
        phone: "+359 888 111 111",
        role: "admin",
        building_id: 1,
        created_at: "2026-04-02T09:00:00.000Z"
      },
      {
        id: 3,
        full_name: "Resident Condo A",
        email: "user@condo-a.bg",
        password: "1234",
        apartment: "12",
        floor: "4",
        phone: "+359 888 222 222",
        role: "resident",
        building_id: 1,
        created_at: "2026-04-12T10:15:00.000Z"
      },
      {
        id: 4,
        full_name: "Admin Condo B",
        email: "admin-b@resido.com",
        password: "1234",
        apartment: "Admin",
        floor: "",
        phone: "+359 888 333 333",
        role: "admin",
        building_id: 2,
        created_at: "2026-04-03T09:00:00.000Z"
      },
      {
        id: 5,
        full_name: "Resident Condo B",
        email: "user@condo-b.bg",
        password: "1234",
        apartment: "8",
        floor: "2",
        phone: "+359 888 444 444",
        role: "resident",
        building_id: 2,
        created_at: "2026-04-14T11:30:00.000Z"
      }
    ],

    notices: [
      {
        id: 1,
        building_id: 1,
        date: "2026-04-24",
        title_bg: "Почистване на входа",
        title_en: "Entrance cleaning",
        description_bg: "Общите части ще бъдат почистени между 08:00 и 12:00 ч.",
        description_en: "Common areas will be cleaned between 08:00 and 12:00."
      },
      {
        id: 2,
        building_id: 2,
        date: "2026-04-26",
        title_bg: "Общо събрание",
        title_en: "General meeting",
        description_bg: "Покана за общо събрание на живущите.",
        description_en: "Invitation for a general meeting of the residents."
      }
    ],

    warnings: [
      {
        id: 1,
        building_id: 1,
        date: "2026-04-24",
        level: "medium",
        title_bg: "Теч в мазето",
        title_en: "Basement leak",
        description_bg: "Избягвайте зона M-2. Екипът по поддръжка работи по проблема.",
        description_en: "Avoid area M-2. The maintenance team is working on the issue."
      },
      {
        id: 2,
        building_id: 2,
        date: "2026-04-23",
        level: "critical",
        title_bg: "Неработещ асансьор 2",
        title_en: "Elevator 2 out of service",
        description_bg: "Използвайте асансьор 1 или стълбите до приключване на ремонта.",
        description_en: "Use elevator 1 or the stairs until the repair is complete."
      }
    ],

    payments: [
      {
        id: 1,
        building_id: 1,
        date: "2026-04-01",
        apartment: "12",
        resident_email: "user@condo-a.bg",
        amount: 45,
        currency: "EUR",
        method: "card",
        card_brand: "visa",
        card_mask: "4111 **** 111111",
        status: "paid",
        billing_month: "2026-04"
      },
      {
        id: 2,
        building_id: 2,
        date: "2026-04-02",
        apartment: "8",
        resident_email: "user@condo-b.bg",
        amount: 55,
        currency: "EUR",
        method: "bank",
        status: "unpaid",
        billing_month: "2026-04"
      }
    ],

    requests: [
      {
        id: 1,
        building_id: 1,
        date: "2026-04-20",
        title_bg: "Счупена лампа на етаж 3",
        title_en: "Broken light on floor 3",
        description_bg: "Лампата не работи.",
        description_en: "The light is not working.",
        resident_email: "user@condo-a.bg",
        status: "new"
      },
      {
        id: 2,
        building_id: 2,
        date: "2026-04-21",
        title_bg: "Проверка на входна врата",
        title_en: "Entrance door inspection",
        description_bg: "Вратата не се затваря добре.",
        description_en: "The door does not close properly.",
        resident_email: "user@condo-b.bg",
        status: "in_process"
      }
    ],

    documents: [
      {
        id: 1,
        building_id: 1,
        title_bg: "Правила за поддръжка",
        title_en: "Maintenance rules",
        category_bg: "Правила",
        category_en: "Rules",
        updated_at: "2026-04-01"
      },
      {
        id: 2,
        building_id: 2,
        title_bg: "Финансов отчет",
        title_en: "Financial report",
        category_bg: "Отчети",
        category_en: "Reports",
        updated_at: "2026-04-10"
      }
    ],

    resetTokens: {},
    emailChangeTokens: {},
    stripe_events: [],
    audit_log: []
  };
}

function normalizeDb(db) {
  const base = defaultDb();

  db.buildings ||= base.buildings;
  db.platform_settings ||= base.platform_settings;
  db.platform_settings.resido_bank_iban = normalizeIban(db.platform_settings.resido_bank_iban || db.platform_settings.platform_bank_iban);
  db.platform_settings.currency = "EUR";
  db.users ||= base.users;
  db.notices ||= [];
  db.warnings ||= [];
  db.payments ||= [];
  db.requests ||= [];
  db.documents ||= [];
  db.chat_messages ||= [];
  db.resetTokens ||= {};
  db.emailChangeTokens ||= {};
  db.stripe_events ||= [];
  db.audit_log ||= [];

  Object.values(db.buildings).forEach((building) => {
    building.currency = "EUR";
    building.bank_iban = normalizeIban(building.bank_iban || building.iban);
    building.stripe_account_id = stripeConnectAccountId(building);
    if (!building.status) building.status = "active";
    const legacyServiceFee = Number(building.service_fee_amount || building.resido_service_fee || 0);
    const hasServiceMode = cleanText(building.service_fee_mode || building.resido_service_fee_mode);
    building.service_fee_mode = hasServiceMode
      ? normalizeServiceFeeMode(hasServiceMode)
      : ((Number.isFinite(legacyServiceFee) && legacyServiceFee > 0) ? "fixed" : "proportional");
    const serviceRate = Number(building.service_fee_per_apartment ?? building.resido_fee_per_apartment ?? DEFAULT_SERVICE_FEE_PER_APARTMENT);
    building.service_fee_per_apartment = Number.isFinite(serviceRate) && serviceRate >= 0
      ? serviceRate
      : DEFAULT_SERVICE_FEE_PER_APARTMENT;
    const fixedFee = Number(building.service_fixed_fee_amount ?? (building.service_fee_mode === "fixed" ? legacyServiceFee : 0));
    building.service_fixed_fee_amount = Number.isFinite(fixedFee) && fixedFee >= 0 ? fixedFee : 0;
    building.service_fee_amount = buildingServiceFeeAmount(building, db);
    building.service_billing_cycle = normalizeServiceBillingCycle(building.service_billing_cycle || building.resido_billing_cycle);
    building.service_paid_until = servicePaidUntil(building);
    building.service_currency = "EUR";
    const dueDay = Number(building.payment_due_day);
    building.payment_due_day = Number.isFinite(dueDay)
      ? Math.min(Math.max(Math.floor(dueDay), 1), 31)
      : 10;

    if (building.address === "Сграда A, София") building.address = "бул. Витоша 32, София";
    if (building.address === "Сграда B, Пловдив") building.address = "бул. Цариградско шосе 89, София";

    if (building.id !== "all" && building.admin_user_id === undefined) {
      const admin = db.users.find(
        u => u.role === "admin" && String(u.building_id) === String(building.id)
      );
      building.admin_user_id = admin ? admin.id : null;
    }
  });

  db.users.forEach((user) => {
    if (user.floor === undefined) user.floor = "";
    if (norm(user.email) === "user@condo-a.bg" && !user.floor) user.floor = "4";
    if (norm(user.email) === "user@condo-b.bg" && !user.floor) user.floor = "2";
    const seedCreatedAt = {
      "superadmin@resido.com": "2026-04-01T09:00:00.000Z",
      "admin-a@resido.com": "2026-04-02T09:00:00.000Z",
      "admin-b@resido.com": "2026-04-03T09:00:00.000Z",
      "user@condo-a.bg": "2026-04-12T10:15:00.000Z",
      "user@condo-b.bg": "2026-04-14T11:30:00.000Z"
    }[norm(user.email)];
    if (!user.created_at && seedCreatedAt) user.created_at = seedCreatedAt;
  });

  db.payments.forEach((payment) => {
    payment.currency = "EUR";
    if (!payment.billing_month) payment.billing_month = String(payment.date || today()).slice(0, 7);
    if (payment.method === "card") {
      payment.card_brand = normalizeCardBrand(payment.card_brand || payment.card_type);
      payment.card_mask = cleanCardMask(payment.card_mask || payment.card_masked || payment.masked_card);
    }
  });

  db.chat_messages.forEach((message) => {
    if (!Array.isArray(message.attachments)) message.attachments = [];
  });

  db.requests.forEach((request) => {
    if (request.status === "open") request.status = "new";
    if (request.status === "in_progress") request.status = "in_process";
    if (request.status === "done") request.status = "processed";
    if (request.status === "canceled") request.status = "cancelled";
  });

  return db;
}

function loadDbFromFile() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify(defaultDb(), null, 2));
  }

  return normalizeDb(JSON.parse(fs.readFileSync(DB_FILE, "utf8")));
}

function postgresSslConfig() {
  const mode = String(process.env.PGSSLMODE || process.env.POSTGRES_SSL || "").toLowerCase();
  const url = DATABASE_URL.toLowerCase();

  if (mode === "disable" || mode === "false") return undefined;
  if (mode === "require" || mode === "no-verify" || mode === "true") {
    return { rejectUnauthorized: false };
  }

  if (url.includes("sslmode=require")) return undefined;
  if (url.includes("render.com") && !url.includes(".internal")) {
    return { rejectUnauthorized: false };
  }

  return undefined;
}

async function ensurePostgres() {
  if (pgPool) return pgPool;

  const { Pool } = require("pg");
  const ssl = postgresSslConfig();

  pgPool = new Pool({
    connectionString: DATABASE_URL,
    max: Number(process.env.PGPOOL_MAX || 5),
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    ...(ssl ? { ssl } : {})
  });

  pgPool.on("error", (err) => {
    console.error("POSTGRES POOL ERROR:", err);
  });

  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS resido_app_state (
      key TEXT PRIMARY KEY,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS resido_audit_log (
      id BIGSERIAL PRIMARY KEY,
      actor_user_id TEXT,
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id TEXT,
      building_id TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pgPool.query(`
    CREATE INDEX IF NOT EXISTS resido_audit_log_created_at_idx
      ON resido_audit_log (created_at DESC)
  `);

  return pgPool;
}

async function loadDbFromPostgres() {
  const pool = await ensurePostgres();
  const result = await pool.query(
    "SELECT data FROM resido_app_state WHERE key = $1",
    [APP_STATE_KEY]
  );

  if (result.rows[0]?.data) {
    return normalizeDb(result.rows[0].data);
  }

  const seeded = loadDbFromFile();
  await pool.query(
    `INSERT INTO resido_app_state (key, data, updated_at)
     VALUES ($1, $2::jsonb, NOW())
     ON CONFLICT (key)
     DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
    [APP_STATE_KEY, JSON.stringify(seeded)]
  );

  return seeded;
}

async function loadDb() {
  if (!USE_POSTGRES) return loadDbFromFile();

  try {
    return await loadDbFromPostgres();
  } catch (err) {
    console.error("POSTGRES STARTUP ERROR:", err);
    if (String(process.env.ALLOW_JSON_DB_FALLBACK || "").toLowerCase() === "true") {
      console.warn("ALLOW_JSON_DB_FALLBACK=true, using resido-db.json instead of PostgreSQL.");
      return loadDbFromFile();
    }
    throw err;
  }
}

async function saveDb() {
  if (!USE_POSTGRES || !pgPool) {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    return;
  }

  const snapshot = JSON.stringify(db);
  saveDbQueue = saveDbQueue
    .catch(() => {})
    .then(() => pgPool.query(
      `INSERT INTO resido_app_state (key, data, updated_at)
       VALUES ($1, $2::jsonb, NOW())
       ON CONFLICT (key)
       DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
      [APP_STATE_KEY, snapshot]
    ));

  await saveDbQueue;
}

let db;

function safeAuditDetails(details = {}) {
  const blocked = new Set([
    "password", "new_password", "newPassword", "temporaryPassword", "temporary_password",
    "token", "resetToken", "confirmEmailToken", "authorization", "card_number", "cardNumber",
    "cvv", "cvc", "stripe_secret_key", "stripe_webhook_secret", "gmail_app_password",
    "smtp_pass", "SMTP_PASS", "GMAIL_APP_PASSWORD", "resend_api_key", "RESEND_API_KEY",
    "mail_api_key", "MAIL_API_KEY"
  ]);

  function clean(value, key = "") {
    if (blocked.has(key)) return "[redacted]";
    if (value === null || value === undefined) return value;
    if (Array.isArray(value)) return value.slice(0, 10).map((item) => clean(item));
    if (typeof value === "object") {
      const out = {};
      for (const [childKey, childValue] of Object.entries(value)) {
        out[childKey] = clean(childValue, childKey);
      }
      return out;
    }
    if (typeof value === "string") return value.length > 300 ? `${value.slice(0, 300)}…` : value;
    return value;
  }

  return clean(details) || {};
}

function auditEntityFromPath(req) {
  const pathValue = cleanText(req.path || req.originalUrl || "").split("?")[0];
  const parts = pathValue.split("/").filter(Boolean);
  const actionPart = parts[2] || parts[1] || "";

  if (parts[0] === "buildings") return { entity_type: "building", entity_id: parts[1] || "", action_part: actionPart };
  if (parts[0] === "residents") return { entity_type: "user", entity_id: parts[1] || "", action_part: parts[0] };
  if (["notices", "warnings", "documents", "requests"].includes(parts[0])) return { entity_type: parts[0].replace(/s$/, ""), entity_id: parts[1] || "", action_part: parts[0] };
  if (parts[0] === "create-user") return { entity_type: "user", entity_id: "", action_part: "create-user" };
  if (parts[0] === "create-request") return { entity_type: "request", entity_id: "", action_part: "create-request" };
  if (parts[0] === "pay" || parts[0] === "stripe") return { entity_type: "payment", entity_id: "", action_part: parts.join("/") };
  if (parts[0] === "profile") return { entity_type: "profile", entity_id: String(req.user?.id || ""), action_part: parts.join("/") };
  if (parts[0] === "chat") return { entity_type: "chat", entity_id: parts[1] || "", action_part: "message" };
  return { entity_type: parts[0] || "app", entity_id: parts[1] || "", action_part: actionPart };
}

function auditActionFromRequest(req) {
  const { action_part } = auditEntityFromPath(req);
  const method = String(req.method || "").toUpperCase();
  const verb = method === "POST" ? "created" : method === "PUT" ? "updated" : method === "DELETE" ? "deleted" : method.toLowerCase();
  return `${verb}:${action_part || cleanText(req.path)}`;
}

async function logAudit(actor, action, entity_type, entity_id, building_id, details = {}) {
  if (!db) return null;

  db.audit_log ||= [];
  const entry = {
    id: nextId(db.audit_log),
    actor_user_id: actor?.id ? String(actor.id) : "system",
    actor_name: actor?.full_name || actor?.email || "System",
    actor_role: actor?.role || "system",
    action: cleanText(action).slice(0, 120) || "changed",
    entity_type: cleanText(entity_type).slice(0, 80) || "app",
    entity_id: cleanText(entity_id).slice(0, 120),
    building_id: String(building_id || actor?.building_id || ""),
    details: safeAuditDetails(details),
    created_at: new Date().toISOString()
  };

  db.audit_log.unshift(entry);
  db.audit_log = db.audit_log.slice(0, 1000);

  if (USE_POSTGRES && pgPool) {
    try {
      await pgPool.query(
        `INSERT INTO resido_audit_log (actor_user_id, action, entity_type, entity_id, building_id, details)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
        [entry.actor_user_id, entry.action, entry.entity_type, entry.entity_id, entry.building_id, JSON.stringify(entry.details || {})]
      );
    } catch (err) {
      console.warn("Audit insert failed:", err.message);
    }
  }

  return entry;
}

function auditMutatingRequests(req, res, next) {
  const method = String(req.method || "").toUpperCase();
  if (!["POST", "PUT", "DELETE"].includes(method)) return next();
  if (["/login", "/forgot-password", "/reset-password", "/confirm-email-change", "/stripe/webhook"].includes(req.path)) return next();

  const started = Date.now();
  res.on("finish", () => {
    if (!req.user || res.statusCode < 200 || res.statusCode >= 400) return;
    const entity = auditEntityFromPath(req);
    const buildingId = entity.entity_type === "building"
      ? entity.entity_id
      : (req.body?.building_id || req.user.building_id || "");

    logAudit(req.user, auditActionFromRequest(req), entity.entity_type, entity.entity_id, buildingId, {
      method,
      path: req.path,
      status_code: res.statusCode,
      duration_ms: Date.now() - started,
      body: safeAuditDetails(req.body || {})
    })
      .then(() => saveDb())
      .catch((err) => console.warn("Audit log failed:", err.message));
  });

  next();
}

function auditEntriesFor(user, buildingId, limit = 60) {
  const requestedBuilding = String(buildingId || user.building_id || "");
  const maxLimit = Math.min(Math.max(Number(limit) || 60, 1), 200);
  return (db.audit_log || [])
    .filter((entry) => {
      if (user.role === "super_admin") {
        return requestedBuilding === "all" || !requestedBuilding || String(entry.building_id) === requestedBuilding;
      }
      return String(entry.building_id) === String(user.building_id);
    })
    .slice(0, maxLimit)
    .map((entry) => ({
      id: entry.id,
      actor_name: entry.actor_name || "-",
      actor_role: entry.actor_role || "-",
      action: entry.action,
      entity_type: entry.entity_type,
      entity_id: entry.entity_id,
      building_id: entry.building_id,
      created_at: entry.created_at,
      details: entry.details || {}
    }));
}

function exportDataFor(user, buildingId) {
  const requestedBuilding = String(buildingId || user.building_id || "");
  const includeAll = user.role === "super_admin" && (requestedBuilding === "all" || !requestedBuilding);
  const allowedBuildingIds = includeAll
    ? Object.values(db.buildings || {}).filter((building) => building.id !== "all").map((building) => String(building.id))
    : [user.role === "super_admin" ? requestedBuilding : String(user.building_id)];
  const allowedSet = new Set(allowedBuildingIds.map(String));
  const inScope = (item) => allowedSet.has(String(item.building_id));

  const buildings = Object.values(db.buildings || {})
    .filter((building) => building.id !== "all" && (includeAll || allowedSet.has(String(building.id))))
    .map((building) => publicBuilding(building, user));

  return {
    exported_at: new Date().toISOString(),
    exported_by: publicUser(user),
    scope: includeAll ? "all_active_buildings" : `building:${allowedBuildingIds[0] || ""}`,
    buildings,
    users: (db.users || []).filter((u) => includeAll ? u.role !== "super_admin" : allowedSet.has(String(u.building_id))).map(publicUser),
    payments: (db.payments || []).filter(inScope),
    requests: (db.requests || []).filter(inScope),
    warnings: (db.warnings || []).filter(inScope),
    notices: (db.notices || []).filter(inScope),
    documents: (db.documents || []).filter(inScope).map((document) => {
      if (String(process.env.EXPORT_INCLUDE_FILE_DATA || "").toLowerCase() === "true") return document;
      const { file_data, ...safe } = document;
      return safe;
    }),
    audit_log: auditEntriesFor(user, includeAll ? "all" : allowedBuildingIds[0], 200)
  };
}

async function applyRuntimeConfig() {
  let changed = false;
  const superAdmin = db.users.find((user) => user.role === "super_admin");

  if (superAdmin) {
    const email = configuredEmail("SUPER_ADMIN_EMAIL", "RESIDO_SUPER_ADMIN_EMAIL");

    if (email && norm(superAdmin.email) !== email) {
      const duplicate = db.users.some(
        (user) => String(user.id) !== String(superAdmin.id) && norm(user.email) === email
      );

      if (duplicate) {
        console.warn(`SUPER_ADMIN_EMAIL was ignored because ${email} already belongs to another user.`);
      } else {
        superAdmin.email = email;
        superAdmin.updated_at = new Date().toISOString();
        changed = true;
      }
    }

    const name = cleanText(process.env.SUPER_ADMIN_NAME || process.env.RESIDO_SUPER_ADMIN_NAME);
    if (name && superAdmin.full_name !== name) {
      superAdmin.full_name = name;
      superAdmin.updated_at = new Date().toISOString();
      changed = true;
    }

    const phone = cleanText(process.env.SUPER_ADMIN_PHONE || process.env.RESIDO_SUPER_ADMIN_PHONE);
    if (phone && superAdmin.phone !== phone) {
      superAdmin.phone = phone;
      superAdmin.updated_at = new Date().toISOString();
      changed = true;
    }

    const password = cleanText(process.env.SUPER_ADMIN_PASSWORD || process.env.RESIDO_SUPER_ADMIN_PASSWORD);
    if (password) {
      const policyError = passwordPolicyError(password);
      if (policyError) throw new Error(`SUPER_ADMIN_PASSWORD rejected: ${policyError}`);

      const samePassword = await bcrypt.compare(password, superAdmin.password_hash || "");
      if (!samePassword) {
        superAdmin.password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        delete superAdmin.password;
        superAdmin.updated_at = new Date().toISOString();
        changed = true;
      }
    }
  }

  if (changed) await saveDb();
}

async function migratePasswords() {
  let changed = false;

  for (const user of db.users) {
    if (!user.password_hash) {
      user.password_hash = await bcrypt.hash(String(user.password || "1234"), BCRYPT_ROUNDS);
      delete user.password;
      changed = true;
    }
  }

  if (changed) await saveDb();
}

async function assertProductionReady() {
  if (!isProductionLike()) return;

  const issues = [];

  if (!USE_POSTGRES) issues.push("DATABASE_URL or POSTGRES_URL is required for production.");
  if (!AUTH_SECRET || AUTH_SECRET.length < 32) issues.push("AUTH_SECRET must be set to a random value with at least 32 characters.");
  if (!/^https:\/\//i.test(cleanText(process.env.FRONTEND_ORIGIN))) issues.push("FRONTEND_ORIGIN must be your HTTPS domain, for example https://www.residoco.com.");
  if (!emailConfigured()) issues.push("RESEND_API_KEY and MAIL_FROM are required for forgot-password, welcome, and email-change delivery over HTTPS.");
  if (!stripeConfigured()) issues.push("STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET are required for real card/GPay payments.");

  const superAdmin = db.users.find((user) => user.role === "super_admin");
  if (superAdmin?.password_hash && await bcrypt.compare("1234", superAdmin.password_hash)) {
    issues.push("The default super admin password is still 1234. Set SUPER_ADMIN_PASSWORD or change it before production.");
  }

  if (issues.length) {
    throw new Error(`Production readiness failed:\n- ${issues.join("\n- ")}`);
  }
}

function publicUser(user) {
  const { password, password_hash, ...safe } = user;
  return safe;
}

function authTokenSecret() {
  if (AUTH_SECRET) return AUTH_SECRET;
  if (isProductionLike()) return DATABASE_URL;
  return "resido-local-dev-auth-secret";
}

function authPasswordVersion(user) {
  return crypto
    .createHash("sha256")
    .update(String(user?.password_hash || ""))
    .digest("hex")
    .slice(0, 16);
}

function authTokenSignature(payload, secret) {
  return crypto.createHmac("sha256", secret).update(payload).digest("base64url");
}

function authTokenFor(user) {
  const secret = authTokenSecret();
  if (!secret) {
    throw new Error("AUTH_SECRET or DATABASE_URL is required for production auth tokens");
  }

  const payload = Buffer.from(JSON.stringify({
    sub: String(user.id),
    pv: authPasswordVersion(user),
    iat: Date.now()
  })).toString("base64url");
  const signature = authTokenSignature(payload, secret);

  return `resido.${payload}.${signature}`;
}

function userFromSignedAuthToken(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3 || parts[0] !== "resido") return null;

  const secret = authTokenSecret();
  if (!secret) return null;

  const expected = authTokenSignature(parts[1], secret);
  const a = Buffer.from(expected);
  const b = Buffer.from(parts[2]);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  let payload;

  try {
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch (_) {
    return null;
  }

  if (!payload?.sub || !payload?.iat) return null;
  if (Date.now() - Number(payload.iat) > AUTH_TOKEN_TTL_MS) return null;

  const user = db.users.find(u => String(u.id) === String(payload.sub));
  if (!user || payload.pv !== authPasswordVersion(user)) return null;

  return user;
}

function userFromAuth(req) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  const signedUser = userFromSignedAuthToken(token);
  if (signedUser) return signedUser;
  if (isProductionLike()) return null;

  return db.users.find(u => `token-user-${u.id}` === token || `token-${norm(u.email)}` === token) || null;
}

function isBuildingCancelled(buildingId) {
  if (String(buildingId) === "all") return false;
  const building = db.buildings[String(buildingId)];
  return !building || building.status === "cancelled";
}

function activeBuildingIds() {
  return Object.values(db.buildings)
    .filter(b => b.id !== "all" && b.status !== "cancelled")
    .map(b => String(b.id));
}

function requireAuth(req, res, next) {
  const user = userFromAuth(req);

  if (!user) return res.status(401).json({ message: "Unauthorized" });

  if (user.role !== "super_admin" && isBuildingCancelled(user.building_id)) {
    return res.status(403).json({ message: "This building/client account is cancelled" });
  }

  if (user.role === "resident" && isServiceSuspended(user.building_id)) {
    return res.status(403).json({ message: serviceAccessMessage() });
  }

  if (user.role === "admin" && isServiceSuspended(user.building_id) && !serviceRestrictedRequestAllowed(req)) {
    return res.status(402).json({ message: serviceAccessMessage() });
  }

  req.user = user;
  next();
}

function requireManager(req, res, next) {
  if (!req.user || !["admin", "super_admin"].includes(req.user.role)) {
    return res.status(403).json({ message: "Managers only" });
  }

  next();
}

function buildingFor(user) {
  return user.role === "super_admin"
    ? db.buildings.all
    : db.buildings[String(user.building_id)];
}

function adminForBuilding(buildingId) {
  return db.users.find(
    u => u.role === "admin" && String(u.building_id) === String(buildingId)
  ) || null;
}

function publicBuilding(building, viewer = null) {
  const admin = adminForBuilding(building.id);
  const canSeeBankInfo = viewer && ["admin", "super_admin"].includes(viewer.role);

  return {
    ...building,
    currency: "EUR",
    status: building.status || "active",
    admin_user_id: admin ? admin.id : (building.admin_user_id || null),
    admin_name: admin ? admin.full_name : "-",
    admin_email: admin ? admin.email : "",
    bank_iban: canSeeBankInfo ? normalizeIban(building.bank_iban || building.iban) : "",
    stripe_account_id: canSeeBankInfo ? stripeConnectAccountId(building) : "",
    platform_bank_iban: canSeeBankInfo ? platformBankIban() : "",
    ...servicePaymentSummary(building)
  };
}

function canChatWith(user, target) {
  if (!user || !target || String(user.id) === String(target.id)) return false;
  if (user.role === "resident") {
    return target.role === "admin" && String(target.building_id) === String(user.building_id);
  }
  if (user.role === "admin") {
    return target.role === "resident" && String(target.building_id) === String(user.building_id);
  }
  if (user.role === "super_admin") {
    return target.role !== "super_admin";
  }
  return false;
}

function getChatTarget(req, res, targetId) {
  const target = db.users.find(u => String(u.id) === String(targetId));
  if (!target || !canChatWith(req.user, target)) {
    res.status(403).json({ message: "Chat is not allowed for this user" });
    return null;
  }
  return target;
}

function chatBetween(userId, targetId) {
  return db.chat_messages
    .filter(m =>
      (String(m.sender_id) === String(userId) && String(m.recipient_id) === String(targetId)) ||
      (String(m.sender_id) === String(targetId) && String(m.recipient_id) === String(userId))
    )
    .sort((a, b) => String(a.created_at || "").localeCompare(String(b.created_at || "")));
}

function publicChatMessage(message) {
  return {
    id: message.id,
    sender_id: message.sender_id,
    recipient_id: message.recipient_id,
    body: message.body,
    attachments: Array.isArray(message.attachments) ? message.attachments : [],
    urgent: Boolean(message.urgent),
    created_at: message.created_at,
    delivered_at: message.delivered_at || message.created_at,
    read_at: message.read_at || null
  };
}

function chatAttachmentsFromBody(body = {}) {
  const incoming = Array.isArray(body.attachments) ? body.attachments : [];
  const attachments = [];
  let totalLength = 0;

  for (const raw of incoming.slice(0, 4)) {
    const name = cleanText(raw.name || raw.file_name || "attachment").slice(0, 160) || "attachment";
    const type = cleanText(raw.type || raw.file_type || "application/octet-stream").slice(0, 120) || "application/octet-stream";
    const size = Number(raw.size || raw.file_size || 0);
    const dataUrl = String(raw.data_url || raw.file_data || "");

    if (!dataUrl.startsWith("data:")) {
      return { error: "Invalid attachment" };
    }

    totalLength += dataUrl.length;
    if (totalLength > 14_000_000 || dataUrl.length > 11_000_000) {
      return { error: "Attachment is too large" };
    }

    attachments.push({
      name,
      type,
      size: Number.isFinite(size) && size > 0 ? Math.round(size) : 0,
      data_url: dataUrl
    });
  }

  return { attachments };
}

function chatSummaryFor(user) {
  const targetIds = new Set();
  db.chat_messages.forEach((message) => {
    if (String(message.sender_id) === String(user.id)) targetIds.add(String(message.recipient_id));
    if (String(message.recipient_id) === String(user.id)) targetIds.add(String(message.sender_id));
  });

  return Array.from(targetIds).map((targetId) => {
    const target = db.users.find(u => String(u.id) === String(targetId));
    if (!target || !canChatWith(user, target)) return null;
    const messages = chatBetween(user.id, targetId);
    const unread = messages.filter(m => String(m.recipient_id) === String(user.id) && !m.read_at);
    const last = messages[messages.length - 1] || null;
    return {
      target_id: Number(targetId),
      unread_count: unread.length,
      urgent_unread_count: unread.filter(m => m.urgent).length,
      last_message_at: last?.created_at || null
    };
  }).filter(Boolean);
}

function canAccessBuilding(user, buildingId) {
  if (user.role === "super_admin") return true;
  return String(user.building_id) === String(buildingId);
}

function ensureBuildingScope(req, res, buildingId) {
  if (!canAccessBuilding(req.user, buildingId)) {
    res.status(403).json({ message: "Not allowed for this building" });
    return false;
  }

  if (req.user.role !== "super_admin" && isBuildingCancelled(buildingId)) {
    res.status(403).json({ message: "Building is cancelled" });
    return false;
  }

  return true;
}

function filterByBuilding(user, data, buildingId) {
  if (user.role === "super_admin") {
    if (String(buildingId) === "all") {
      const activeIds = activeBuildingIds();
      return data.filter(x => x.role === "super_admin" || activeIds.includes(String(x.building_id)));
    }

    return data.filter(x => String(x.building_id) === String(buildingId));
  }

  return data.filter(x => String(x.building_id) === String(user.building_id));
}

function scopedBuildingId(req, body = req.body) {
  if (req.user.role === "admin") return req.user.building_id;

  return body.building_id && body.building_id !== "all"
    ? body.building_id
    : 1;
}

function containsCyrillic(text) {
  return /[А-Яа-яЁё]/.test(String(text || ""));
}

function normalizeTranslationKey(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[„“”"]/g, "")
    .replace(/\s+/g, " ")
    .replace(/\s*([.,:;!?-])\s*/g, "$1")
    .replace(/\.$/, "");
}

const translationPairs = [
  ["Проверка на пожароизвестяване утре", "Fire alarm inspection tomorrow"],
  ["Годишна проверка от 10:00 ч. Моля осигурете достъп при нужда.", "Annual inspection at 10:00. Please provide access if needed."],
  ["Почистване на входа", "Entrance cleaning"],
  ["Общите части ще бъдат почистени между 08:00 и 12:00 ч.", "Common areas will be cleaned between 08:00 and 12:00."],
  ["Теч в мазето", "Basement leak"],
  ["Избягвайте зона M-2. Екипът по поддръжка работи по проблема.", "Avoid area M-2. The maintenance team is working on the issue."],
  ["Неработещ асансьор 2", "Elevator 2 out of service"],
  ["Използвайте асансьор 1 или стълбите до приключване на ремонта.", "Use elevator 1 or the stairs until the repair is complete."],
  ["Счупена лампа на етаж 3", "Broken light on floor 3"],
  ["Проверка на входна врата", "Entrance door inspection"],
  ["Правила за поддръжка", "Maintenance rules"],
  ["Финансов отчет", "Financial report"],
  ["Правила", "Rules"],
  ["Отчети", "Reports"],
  ["Общи", "General"],
  ["Административни", "Administrative"],
  ["Отказана", "Cancelled"]
];

const serverTranslationIndex = { bg: {}, en: {} };

translationPairs.forEach(([bg, en]) => {
  serverTranslationIndex.en[normalizeTranslationKey(bg)] = en;
  serverTranslationIndex.bg[normalizeTranslationKey(en)] = bg;
});

function translateForStorage(text, targetLanguage) {
  const value = cleanText(text);
  if (!value) return "";
  return serverTranslationIndex[targetLanguage]?.[normalizeTranslationKey(value)] || value;
}

function localizedPayloadFromSingleInput(body, fieldName) {
  const directBg = cleanText(body[`${fieldName}_bg`]);
  const directEn = cleanText(body[`${fieldName}_en`]);

  if (directBg || directEn) {
    return {
      [`${fieldName}_bg`]: directBg || translateForStorage(directEn, "bg"),
      [`${fieldName}_en`]: directEn || translateForStorage(directBg, "en")
    };
  }

  const single = cleanText(body[fieldName]);

  if (!single) {
    return {
      [`${fieldName}_bg`]: "",
      [`${fieldName}_en`]: ""
    };
  }

  if (containsCyrillic(single)) {
    return {
      [`${fieldName}_bg`]: single,
      [`${fieldName}_en`]: translateForStorage(single, "en")
    };
  }

  return {
    [`${fieldName}_bg`]: translateForStorage(single, "bg"),
    [`${fieldName}_en`]: single
  };
}

function localizedPayloadForUpdate(body, item, fieldName) {
  const hasSingle = Object.prototype.hasOwnProperty.call(body, fieldName);
  const hasBg = Object.prototype.hasOwnProperty.call(body, `${fieldName}_bg`);
  const hasEn = Object.prototype.hasOwnProperty.call(body, `${fieldName}_en`);

  if (hasSingle || hasBg || hasEn) {
    return localizedPayloadFromSingleInput(body, fieldName);
  }

  return {
    [`${fieldName}_bg`]: item[`${fieldName}_bg`] || "",
    [`${fieldName}_en`]: item[`${fieldName}_en`] || ""
  };
}

function normalizeRequestStatus(value) {
  const status = norm(value).replace(/\s+/g, "_");

  if (status === "new") return "new";
  if (status === "in_process") return "in_process";
  if (status === "done") return "processed";
  if (status === "canceled") return "cancelled";

  const allowed = ["new", "in_process", "processed", "cancelled"];
  return allowed.includes(status) ? status : "";
}

function resendApiKey() {
  return cleanText(process.env.RESEND_API_KEY || process.env.MAIL_API_KEY);
}

function resendApiUrl() {
  return (cleanText(process.env.RESEND_API_URL) || "https://api.resend.com/emails").replace(/\/+$/, "");
}

function mailFromAddress() {
  return cleanText(process.env.MAIL_FROM || process.env.RESEND_FROM || process.env.MAIL_SENDER);
}

function mailReplyToAddress() {
  return configuredEmail(
    "MAIL_REPLY_TO",
    "SUPPORT_EMAIL",
    "SUPER_ADMIN_EMAIL",
    "RESIDO_SUPER_ADMIN_EMAIL"
  );
}

function emailConfigured() {
  return Boolean(resendApiKey()) && Boolean(mailFromAddress());
}

function mailPayload(base) {
  const replyTo = mailReplyToAddress();
  return {
    from: mailFromAddress(),
    ...(replyTo ? { reply_to: replyTo } : {}),
    ...base
  };
}

function sanitizeEmailApiError(value) {
  return String(value || "")
    .replace(/re_[A-Za-z0-9_\-]+/g, "re_***")
    .replace(/Bearer\s+[A-Za-z0-9_\-.]+/gi, "Bearer ***")
    .slice(0, 800);
}

async function sendTransactionalEmail(base, idempotencyKey) {
  const apiKey = resendApiKey();

  if (!apiKey || !mailFromAddress()) {
    return false;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Number(process.env.EMAIL_API_TIMEOUT_MS || 15000));

  try {
    const response = await fetch(resendApiUrl(), {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey || crypto.randomUUID()
      },
      body: JSON.stringify(mailPayload(base)),
      signal: controller.signal
    });

    const raw = await response.text();
    let data = null;

    if (raw) {
      try {
        data = JSON.parse(raw);
      } catch (_) {
        data = { message: raw };
      }
    }

    if (!response.ok) {
      const message = data?.message || data?.error?.message || data?.error || raw || response.statusText;
      throw new Error(`Resend API ${response.status}: ${sanitizeEmailApiError(message)}`);
    }

    return true;
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("Resend API request timed out");
    }

    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

function logEmailFallback(title, details) {
  if (!allowDevEmailDetails()) {
    console.log(`${title}: email was not sent. Check RESEND_API_KEY, MAIL_FROM, and Resend domain/sender verification.`);
    return;
  }

  console.log(`\n================ ${title} ================`);
  Object.entries(details).forEach(([label, value]) => console.log(`${label}:`, value));
  console.log("=======================================================\n");
}

function frontendPageUrl(req) {
  const configured = cleanText(
    process.env.FRONTEND_URL ||
    process.env.PUBLIC_APP_URL ||
    process.env.APP_URL
  );

  if (configured) {
    const trimmed = configured.replace(/\/+$/, "");
    return trimmed.endsWith(".html") ? trimmed : `${trimmed}/index.html`;
  }

  const origin = cleanText(req.headers.origin);
  if (origin) return `${origin.replace(/\/+$/, "")}/index.html`;

  const referer = cleanText(req.headers.referer || req.headers.referrer);
  if (referer) {
    try {
      const url = new URL(referer);
      url.hash = "";
      url.search = "";
      return url.toString();
    } catch (_) {}
  }

  return "http://127.0.0.1:5500/index.html";
}

function frontendLink(req, params = {}) {
  const url = new URL(frontendPageUrl(req));
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, String(value));
    }
  });
  return url.toString();
}

async function sendResetEmail(to, resetLink, temporaryPassword) {
  if (String(process.env.EMAIL_DRY_RUN || "").toLowerCase() === "true") {
    logEmailFallback("RESIDO PASSWORD RESET DRY RUN", { Email: to, "Verification code": temporaryPassword, "Reset link": resetLink, "Valid for": `${RESET_TOKEN_TTL_MS / 60000} minutes` });
    return true;
  }

  if (!emailConfigured()) {
    logEmailFallback("RESIDO PASSWORD RESET", { Email: to, "Verification code": temporaryPassword, "Reset link": resetLink, "Valid for": `${RESET_TOKEN_TTL_MS / 60000} minutes` });
    return false;
  }

  await sendTransactionalEmail({
    to,
    subject: "Resido password reset",
    text: [
      "Hello,",
      "",
      "You requested a password reset for your Resido account.",
      `Verification code: ${temporaryPassword}`,
      `Reset link: ${resetLink}`,
      `This link is valid for ${RESET_TOKEN_TTL_MS / 60000} minutes.`,
      "",
      "If you did not request this, please contact your building administrator."
    ].join("\n"),
    html: `
      <p>Hello,</p>
      <p>You requested a password reset for your Resido account.</p>
      <p>Your verification code is:</p>
      <h2>${htmlEscape(temporaryPassword)}</h2>
      <p>Open this link to set a new password:</p>
      <p><a href="${htmlEscape(resetLink)}">${htmlEscape(resetLink)}</a></p>
      <p>This link is valid for ${htmlEscape(String(RESET_TOKEN_TTL_MS / 60000))} minutes.</p>
      <p>If you did not request this, please contact your building administrator.</p>
    `
  }, `resido-reset-${crypto.createHash("sha256").update(resetLink).digest("hex").slice(0, 40)}`);

  return true;
}

async function sendEmailChangeConfirmation(to, confirmLink, userName) {
  if (String(process.env.EMAIL_DRY_RUN || "").toLowerCase() === "true") {
    logEmailFallback("RESIDO EMAIL CHANGE DRY RUN", { Email: to, "Confirm link": confirmLink, "Valid for": `${EMAIL_CHANGE_TOKEN_TTL_MS / 60000} minutes` });
    return true;
  }

  if (!emailConfigured()) {
    logEmailFallback("RESIDO EMAIL CHANGE", { Email: to, "Confirm link": confirmLink, "Valid for": `${EMAIL_CHANGE_TOKEN_TTL_MS / 60000} minutes` });
    return false;
  }

  await sendTransactionalEmail({
    to,
    subject: "Confirm your new Resido email",
    text: [
      `Hello ${userName || ""},`,
      "",
      "Please confirm this email address for your Resido account:",
      confirmLink,
      `This confirmation link is valid for ${EMAIL_CHANGE_TOKEN_TTL_MS / 60000} minutes.`,
      "",
      "If you did not request this change, you can ignore this email."
    ].join("\n"),
    html: `
      <p>Hello ${htmlEscape(userName || "")},</p>
      <p>Please confirm this email address for your Resido account:</p>
      <p><a href="${htmlEscape(confirmLink)}">${htmlEscape(confirmLink)}</a></p>
      <p>This confirmation link is valid for ${htmlEscape(String(EMAIL_CHANGE_TOKEN_TTL_MS / 60000))} minutes.</p>
      <p>If you did not request this change, you can ignore this email.</p>
    `
  }, `resido-email-change-${crypto.createHash("sha256").update(confirmLink).digest("hex").slice(0, 40)}`);

  return true;
}

async function sendWelcomeEmail(to, userName, email, password, loginLink) {
  if (String(process.env.EMAIL_DRY_RUN || "").toLowerCase() === "true") {
    logEmailFallback("RESIDO NEW USER DRY RUN", { Email: email, "Temporary password": password, "Login link": loginLink });
    return true;
  }

  if (!emailConfigured()) {
    logEmailFallback("RESIDO NEW USER", { Email: email, "Temporary password": password, "Login link": loginLink });
    return false;
  }

  await sendTransactionalEmail({
    to,
    subject: "Your Resido account",
    text: [
      `Hello ${userName || ""},`,
      "",
      "Your Resido account has been created.",
      `Email: ${email}`,
      `Temporary password: ${password}`,
      `Login link: ${loginLink}`,
      "",
      "Please change your password after your first login if your administrator asks you to."
    ].join("\n"),
    html: `
      <p>Hello ${htmlEscape(userName || "")},</p>
      <p>Your Resido account has been created.</p>
      <p><strong>Email:</strong> ${htmlEscape(email)}</p>
      <p><strong>Temporary password:</strong> ${htmlEscape(password)}</p>
      <p>You can log in here:</p>
      <p><a href="${htmlEscape(loginLink)}">${htmlEscape(loginLink)}</a></p>
      <p>Please change your password after your first login if your administrator asks you to.</p>
    `
  }, `resido-welcome-${crypto.createHash("sha256").update(`${email}:${loginLink}:${password}`).digest("hex").slice(0, 40)}`);

  return true;
}

app.use(auditMutatingRequests);

app.get("/audit-log/:buildingId", requireAuth, requireManager, (req, res) => {
  const buildingId = req.params.buildingId;
  if (req.user.role !== "super_admin" && String(buildingId) !== String(req.user.building_id)) {
    return res.status(403).json({ message: "Not allowed for this building" });
  }

  res.json(auditEntriesFor(req.user, buildingId, req.query.limit));
});

app.get("/admin/export-data/:buildingId", requireAuth, requireManager, (req, res) => {
  const buildingId = req.params.buildingId;
  if (req.user.role !== "super_admin" && String(buildingId) !== String(req.user.building_id)) {
    return res.status(403).json({ message: "Not allowed for this building" });
  }

  const data = exportDataFor(req.user, buildingId);
  const safeScope = String(buildingId || "building").replace(/[^a-z0-9_-]+/gi, "-").slice(0, 40) || "building";
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="resido-backup-${safeScope}-${today()}.json"`);
  res.json(data);
});

app.get("/healthz", (_, res) => {
  res.json({ ok: true, service: "resido" });
});

app.get("/", (_, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/index.html", (_, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get([
  "/favicon.ico",
  "/resido-mark-header-40x40.png",
  "/resido-mark-header-48x48.png",
  "/resido_logo.svg"
], (req, res) => {
  res.sendFile(path.join(__dirname, req.path.slice(1)));
});

app.post("/login", authRateLimit, async (req, res) => {
  const email = norm(req.body.email);
  const password = String(req.body.password || "");

  if (!isValidEmail(email)) {
    return res.status(401).json({ message: "Invalid email or password" });
  }

  const user = db.users.find(u => norm(u.email) === email);

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ message: "Invalid email or password" });
  }

  if (user.role !== "super_admin" && isBuildingCancelled(user.building_id)) {
    return res.status(403).json({
      message: "This building/client account is cancelled"
    });
  }

  if (user.role === "resident" && isServiceSuspended(user.building_id)) {
    return res.status(403).json({ message: serviceAccessMessage() });
  }

  const safeUser = publicUser(user);
  if (user.role === "admin") {
    safeUser.service_payment_required = isServiceSuspended(user.building_id);
  }

  res.json({
    user: safeUser,
    building: publicBuilding(buildingFor(user), user),
    token: authTokenFor(user)
  });
});

app.post("/forgot-password", passwordResetRateLimit, async (req, res) => {
  const email = norm(req.body.email);

  if (!isValidEmail(email)) {
    return res.json({
      message: "If this email exists, reset instructions were sent."
    });
  }

  const user = db.users.find(u => norm(u.email) === email);

  if (!user) {
    return res.json({
      message: "If this email exists, reset instructions were sent."
    });
  }

  const token = crypto.randomBytes(24).toString("hex");
  const temporaryPassword = "Resido-" + crypto.randomBytes(3).toString("hex").toUpperCase();

  db.resetTokens[token] = {
    user_id: user.id,
    email,
    temporaryPasswordHash: await bcrypt.hash(temporaryPassword, BCRYPT_ROUNDS),
    expiresAt: Date.now() + RESET_TOKEN_TTL_MS,
    createdAt: Date.now(),
    attempts: 0
  };

  await saveDb();

  const resetLink = frontendLink(req, {
    email: user.email,
    resetToken: token
  });

  let emailSent = false;

  try {
    emailSent = await sendResetEmail(user.email, resetLink, temporaryPassword);
  } catch (err) {
    console.error("Email send failed:", err.message);
  }

  const response = {
    message: "If this email exists, reset instructions were sent.",
    email_sent: emailSent
  };

  if (!emailSent && allowDevEmailDetails()) {
    response.dev_reset_link = resetLink;
    response.dev_temporary_password = temporaryPassword;
  }

  res.json(response);
});

app.post("/reset-password", passwordResetRateLimit, async (req, res) => {
  const email = norm(req.body.email);
  const token = cleanText(req.body.token);
  const temporaryPassword = cleanText(req.body.temporaryPassword);
  const newPassword = cleanText(req.body.newPassword);

  if (!isValidEmail(email)) {
    return res.status(400).json({ message: "Invalid reset token" });
  }

  const reset = db.resetTokens[token];

  if (!reset || reset.email !== email) {
    return res.status(400).json({ message: "Invalid reset token" });
  }

  if (Date.now() > reset.expiresAt) {
    delete db.resetTokens[token];
    await saveDb();
    return res.status(400).json({ message: "Reset token expired" });
  }

  const tempOk = await bcrypt.compare(temporaryPassword, reset.temporaryPasswordHash);

  if (!tempOk) {
    reset.attempts = Number(reset.attempts || 0) + 1;
    if (reset.attempts >= Number(process.env.RESET_TOKEN_MAX_ATTEMPTS || 5)) {
      delete db.resetTokens[token];
    }
    await saveDb();
    return res.status(400).json({ message: "Invalid verification code" });
  }

  const policyError = passwordPolicyError(newPassword);
  if (policyError) return res.status(400).json({ message: policyError });

  const user = db.users.find(u => String(u.id) === String(reset.user_id) || norm(u.email) === email);

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  user.password_hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  delete db.resetTokens[token];

  await saveDb();

  res.json({ message: "Password updated" });
});

app.put("/profile/phone", requireAuth, async (req, res) => {
  req.user.phone = cleanText(req.body.phone);
  await saveDb();

  res.json({
    message: "Phone updated",
    user: publicUser(req.user)
  });
});

app.put("/profile/super-admin/password", requireAuth, sensitiveAccountRateLimit, async (req, res) => {
  if (req.user.role !== "super_admin") {
    return res.status(403).json({ message: "Super admin only" });
  }

  const password = cleanText(req.body.password || req.body.new_password);

  const policyError = passwordPolicyError(password);
  if (policyError) return res.status(400).json({ message: policyError });

  req.user.password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

  await saveDb();

  res.json({
    message: "Password updated",
    token: authTokenFor(req.user),
    user: publicUser(req.user)
  });
});

app.put("/profile/super-admin/email", requireAuth, sensitiveAccountRateLimit, async (req, res) => {
  if (req.user.role !== "super_admin") {
    return res.status(403).json({ message: "Super admin only" });
  }

  const email = norm(req.body.email || req.body.new_email);

  if (!isValidEmail(email)) {
    return res.status(400).json({ message: "Valid email is required" });
  }

  if (db.users.some(u => String(u.id) !== String(req.user.id) && norm(u.email) === email)) {
    return res.status(409).json({ message: "Email already exists" });
  }

  req.user.email = email;
  await saveDb();

  res.json({
    message: "Email updated",
    token: authTokenFor(req.user),
    user: publicUser(req.user)
  });
});

app.post("/profile/email-change", requireAuth, sensitiveAccountRateLimit, async (req, res) => {
  if (req.user.role !== "resident") {
    return res.status(403).json({
      message: "Only residents can change their email."
    });
  }

  const newEmail = norm(req.body.new_email || req.body.email);

  if (!isValidEmail(newEmail)) {
    return res.status(400).json({ message: "Valid new email is required" });
  }

  if (newEmail === norm(req.user.email)) {
    return res.status(400).json({ message: "New email is the same as the current email" });
  }

  if (db.users.some(u => norm(u.email) === newEmail)) {
    return res.status(409).json({ message: "Email already exists" });
  }

  const token = crypto.randomBytes(24).toString("hex");

  db.emailChangeTokens[token] = {
    user_id: req.user.id,
    old_email: norm(req.user.email),
    new_email: newEmail,
    expiresAt: Date.now() + EMAIL_CHANGE_TOKEN_TTL_MS,
    createdAt: Date.now()
  };

  await saveDb();

  const confirmLink = frontendLink(req, {
    confirmEmailToken: token
  });

  let emailSent = false;

  try {
    emailSent = await sendEmailChangeConfirmation(newEmail, confirmLink, req.user.full_name);
  } catch (err) {
    console.error("Email-change confirmation send failed:", err.message);
  }

  const response = {
    message: "Confirmation sent to the new email address.",
    email_sent: emailSent
  };

  if (!emailSent && allowDevEmailDetails()) response.dev_confirm_link = confirmLink;

  res.json(response);
});

app.post("/confirm-email-change", sensitiveAccountRateLimit, async (req, res) => {
  const token = cleanText(req.body.token);
  const pending = db.emailChangeTokens[token];

  if (!pending) {
    return res.status(400).json({ message: "Invalid email confirmation token" });
  }

  if (Date.now() > pending.expiresAt) {
    delete db.emailChangeTokens[token];
    await saveDb();
    return res.status(400).json({ message: "Email confirmation token expired" });
  }

  const user = db.users.find(u => String(u.id) === String(pending.user_id));

  if (!user) {
    delete db.emailChangeTokens[token];
    await saveDb();
    return res.status(404).json({ message: "User not found" });
  }

  if (db.users.some(u => String(u.id) !== String(user.id) && norm(u.email) === pending.new_email)) {
    delete db.emailChangeTokens[token];
    await saveDb();
    return res.status(409).json({ message: "Email already exists" });
  }

  user.email = pending.new_email;
  delete db.emailChangeTokens[token];

  await saveDb();

  res.json({
    message: "Email confirmed.",
    token: authTokenFor(user),
    user: publicUser(user),
    building: publicBuilding(buildingFor(user), user)
  });
});

app.get("/buildings", requireAuth, (req, res) => {
  const values = Object.values(db.buildings)
    .filter(b => b.id !== "all" && b.status !== "cancelled")
    .map(building => publicBuilding(building, req.user));

  if (req.user.role === "super_admin") {
    return res.json(values);
  }

  res.json(values.filter(b => String(b.id) === String(req.user.building_id)));
});

app.get("/admins", requireAuth, (req, res) => {
  if (req.user.role !== "super_admin") {
    return res.status(403).json({ message: "Super admin only" });
  }

  res.json(db.users.filter(u => u.role === "admin").map(publicUser));
});

app.put("/buildings/:id/price", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  const id = req.params.id;

  if (!ensureBuildingScope(req, res, id)) return;

  const building = db.buildings[String(id)];

  if (!building || building.id === "all") {
    return res.status(404).json({ message: "Building not found" });
  }

  const fee = Number(req.body.monthly_fee);

  if (!Number.isFinite(fee) || fee < 0) {
    return res.status(400).json({ message: "Invalid monthly fee" });
  }

  building.monthly_fee = fee;
  building.currency = "EUR";

  await saveDb();

  res.json(publicBuilding(building, req.user));
});

app.put("/buildings/:id/payment-due-day", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  const id = req.params.id;

  if (!ensureBuildingScope(req, res, id)) return;

  const building = db.buildings[String(id)];

  if (!building || building.id === "all") {
    return res.status(404).json({ message: "Building not found" });
  }

  const dueDay = Number(req.body.payment_due_day);

  if (!Number.isFinite(dueDay) || dueDay < 1 || dueDay > 31) {
    return res.status(400).json({ message: "Invalid payment due day" });
  }

  building.payment_due_day = Math.floor(dueDay);

  await saveDb();

  res.json(publicBuilding(building, req.user));
});

app.put("/buildings/:id/payment-routing", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  if (req.user.role !== "super_admin") {
    return res.status(403).json({ message: "Super admin only" });
  }

  const building = db.buildings[String(req.params.id)];

  if (!building || building.id === "all") {
    return res.status(404).json({ message: "Building not found" });
  }

  const bankIban = normalizeIban(req.body.bank_iban || req.body.iban);
  const stripeAccountId = cleanText(req.body.stripe_account_id || req.body.stripeAccountId);
  const platformIban = normalizeIban(req.body.platform_bank_iban || req.body.resido_bank_iban || req.body.residoIban);
  const serviceFeeMode = normalizeServiceFeeMode(req.body.service_fee_mode || req.body.resido_service_fee_mode);
  const serviceFeePerApartment = Number(req.body.service_fee_per_apartment ?? req.body.resido_fee_per_apartment ?? DEFAULT_SERVICE_FEE_PER_APARTMENT);
  const serviceFixedFee = Number(req.body.service_fixed_fee_amount ?? req.body.service_fee_amount ?? req.body.resido_service_fee ?? 0);
  const servicePaidUntilValue = cleanText(req.body.service_paid_until || req.body.resido_paid_until);

  if (!isValidIban(bankIban)) {
    return res.status(400).json({ message: "Invalid IBAN" });
  }

  if (!isValidIban(platformIban)) {
    return res.status(400).json({ message: "Invalid Resido IBAN" });
  }

  if (stripeAccountId && !/^acct_[A-Za-z0-9]+$/.test(stripeAccountId)) {
    return res.status(400).json({ message: "Invalid Stripe account ID" });
  }

  if (!Number.isFinite(serviceFeePerApartment) || serviceFeePerApartment < 0) {
    return res.status(400).json({ message: "Invalid Resido service fee per apartment" });
  }

  if (!Number.isFinite(serviceFixedFee) || serviceFixedFee < 0) {
    return res.status(400).json({ message: "Invalid Resido fixed service fee" });
  }

  if (servicePaidUntilValue && !/^\d{4}-\d{2}-\d{2}$/.test(servicePaidUntilValue)) {
    return res.status(400).json({ message: "Invalid Resido paid-until date" });
  }

  building.bank_iban = bankIban;
  building.stripe_account_id = stripeAccountId;
  building.currency = "EUR";
  building.service_fee_mode = serviceFeeMode;
  building.service_fee_per_apartment = serviceFeePerApartment;
  building.service_fixed_fee_amount = serviceFixedFee;
  building.service_fee_amount = buildingServiceFeeAmount(building);
  building.service_billing_cycle = normalizeServiceBillingCycle(req.body.service_billing_cycle || req.body.resido_billing_cycle);
  building.service_paid_until = servicePaidUntilValue;
  building.service_currency = "EUR";

  if (platformIban) {
    db.platform_settings ||= { resido_bank_iban: "", currency: "EUR" };
    db.platform_settings.resido_bank_iban = platformIban;
    db.platform_settings.currency = "EUR";
  }

  await saveDb();

  res.json(publicBuilding(building, req.user));
});

app.put("/buildings/:id/rename", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  if (req.user.role !== "super_admin") {
    return res.status(403).json({ message: "Super admin only" });
  }

  const building = db.buildings[String(req.params.id)];

  if (!building || building.id === "all") {
    return res.status(404).json({ message: "Building not found" });
  }

  const location = cleanText(req.body.location || req.body.name || req.body.address);

  if (!location) {
    return res.status(400).json({ message: "Building / address is required" });
  }

  building.name = location;
  building.address = location;
  building.currency = "EUR";

  await saveDb();

  res.json(publicBuilding(building, req.user));
});

app.post("/buildings/:id/cancel", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  if (req.user.role !== "super_admin") {
    return res.status(403).json({ message: "Super admin only" });
  }

  const building = db.buildings[String(req.params.id)];

  if (!building || building.id === "all") {
    return res.status(404).json({ message: "Building not found" });
  }

  building.status = "cancelled";

  await saveDb();

  res.json({
    message: "Building cancelled and removed from active lists.",
    building: publicBuilding(building, req.user)
  });
});

app.put("/buildings/:id/admin", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  if (req.user.role !== "super_admin") {
    return res.status(403).json({ message: "Super admin only" });
  }

  const building = db.buildings[String(req.params.id)];

  if (!building || building.id === "all") {
    return res.status(404).json({ message: "Building not found" });
  }

  if (building.status === "cancelled") {
    return res.status(400).json({ message: "Cannot assign admin to cancelled building" });
  }

  const admin = db.users.find(
    u => String(u.id) === String(req.body.admin_user_id) && u.role === "admin"
  );

  if (!admin) {
    return res.status(404).json({ message: "Admin not found" });
  }

  Object.values(db.buildings).forEach((b) => {
    if (String(b.admin_user_id) === String(admin.id) && String(b.id) !== String(building.id)) {
      b.admin_user_id = null;
    }
  });

  const previousAdmin = db.users.find(u => String(u.id) === String(building.admin_user_id));

  if (previousAdmin && previousAdmin.role === "admin") {
    previousAdmin.building_id = "unassigned";
  }

  admin.building_id = building.id;
  building.admin_user_id = admin.id;
  building.status = "active";

  await saveDb();

  res.json(publicBuilding(building, req.user));
});

app.get("/dashboard/:buildingId", requireAuth, (req, res) => {
  const buildingId = req.params.buildingId;

  const requests = filterByBuilding(req.user, db.requests, buildingId);
  const warnings = filterByBuilding(req.user, db.warnings, buildingId);
  const payments = filterByBuilding(req.user, db.payments, buildingId);
  const users = filterByBuilding(req.user, db.users, buildingId);
  const year = today().slice(0, 4);
  const paidMonths = new Set(
    payments
      .filter(p => p.status === "paid")
      .map(p => String(p.billing_month || p.date || "").slice(0, 7))
      .filter(month => month.startsWith(`${year}-`))
  );

  res.json({
    stats: {
      residents: users.filter(u => u.role === "resident").length,
      openRequests: requests.filter(r => r.status === "new" || r.status === "in_process").length,
      activeWarnings: warnings.length,
      paidCount: paidMonths.size,
      unpaidCount: 12
    }
  });
});

app.get("/notices/:buildingId", requireAuth, (req, res) => {
  res.json(filterByBuilding(req.user, db.notices, req.params.buildingId));
});

app.get("/warnings/:buildingId", requireAuth, (req, res) => {
  res.json(filterByBuilding(req.user, db.warnings, req.params.buildingId));
});

app.get("/payments/:buildingId", requireAuth, (req, res) => {
  res.json(filterByBuilding(req.user, db.payments, req.params.buildingId));
});

app.get("/documents/:buildingId", requireAuth, (req, res) => {
  res.json(filterByBuilding(req.user, db.documents, req.params.buildingId));
});

app.get("/residents/:buildingId", requireAuth, (req, res) => {
  const buildingId = req.params.buildingId;

  if (req.user.role === "resident") {
    const admin = adminForBuilding(req.user.building_id);
    return res.json(admin ? [publicUser(admin)] : []);
  }

  if (req.user.role === "admin") {
    return res.json(
      db.users
        .filter(u => u.role === "resident" && String(u.building_id) === String(req.user.building_id))
        .map(publicUser)
    );
  }

  let users = filterByBuilding(req.user, db.users, buildingId);

  if (String(buildingId) !== "all") {
    users = users.filter(u => u.role === "admin" || u.role === "resident");
  } else {
    const activeIds = activeBuildingIds();
    users = users.filter(u => u.role === "super_admin" || activeIds.includes(String(u.building_id)));
  }

  res.json(users.map(publicUser));
});

app.get("/chat/summary", requireAuth, (req, res) => {
  res.json(chatSummaryFor(req.user));
});

app.get("/chat/:targetId", requireAuth, async (req, res) => {
  const target = getChatTarget(req, res, req.params.targetId);
  if (!target) return;

  const now = new Date().toISOString();
  let changed = false;
  const messages = chatBetween(req.user.id, target.id);

  messages.forEach((message) => {
    if (String(message.recipient_id) === String(req.user.id) && !message.read_at) {
      message.read_at = now;
      changed = true;
    }
  });

  if (changed) await saveDb();

  res.json({
    target: publicUser(target),
    messages: messages.map(publicChatMessage)
  });
});

app.post("/chat/:targetId", requireAuth, writeRateLimit, async (req, res) => {
  const target = getChatTarget(req, res, req.params.targetId);
  if (!target) return;

  const body = cleanText(req.body.body || req.body.message);
  const attachmentPayload = chatAttachmentsFromBody(req.body);
  if (attachmentPayload.error) return res.status(400).json({ message: attachmentPayload.error });
  const attachments = attachmentPayload.attachments || [];
  if (!body && !attachments.length) return res.status(400).json({ message: "Message is required" });
  if (body.length > 2000) return res.status(400).json({ message: "Message is too long" });

  const now = new Date().toISOString();
  const item = {
    id: nextId(db.chat_messages),
    sender_id: req.user.id,
    recipient_id: target.id,
    building_id: target.building_id || req.user.building_id,
    body,
    attachments,
    urgent: Boolean(req.body.urgent),
    created_at: now,
    delivered_at: now,
    read_at: null
  };

  db.chat_messages.push(item);
  await saveDb();

  res.status(201).json(publicChatMessage(item));
});

app.get("/requests/:buildingId", requireAuth, (req, res) => {
  let data = filterByBuilding(req.user, db.requests, req.params.buildingId);

  if (req.user.role === "resident") {
    data = data.filter(r => norm(r.resident_email) === norm(req.user.email));
  }

  res.json(data);
});

app.post("/create-user", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  const email = norm(req.body.email);
  const role = norm(req.body.role || "resident");

  const fullName = cleanText(req.body.full_name);
  const password = cleanText(req.body.password);
  const apartment = cleanText(req.body.apartment);

  if (!fullName || !email || !password || (role !== "admin" && !apartment)) {
    return res.status(400).json({ message: "Missing fields" });
  }

  const policyError = passwordPolicyError(password);
  if (policyError) return res.status(400).json({ message: policyError });

  if (!isValidEmail(email)) {
    return res.status(400).json({ message: "Valid email is required" });
  }

  if (db.users.some(u => norm(u.email) === email)) {
    return res.status(409).json({ message: "Email already exists" });
  }

  if (req.user.role === "admin" && role !== "resident") {
    return res.status(403).json({ message: "Admins can only create residents" });
  }

  let buildingId;

  if (req.user.role === "admin") {
    buildingId = req.user.building_id;
  } else if (role === "admin") {
    const buildingLocation = cleanText(req.body.building_location || req.body.building_address || req.body.building_name);
    const fee = Number(req.body.monthly_fee || 0);
    const bankIban = normalizeIban(req.body.bank_iban || req.body.iban || req.body.building_iban);
    const stripeAccountId = cleanText(req.body.stripe_account_id || req.body.stripeAccountId);
    const platformIban = normalizeIban(req.body.platform_bank_iban || req.body.resido_bank_iban || req.body.residoIban);
    const serviceFeeMode = normalizeServiceFeeMode(req.body.service_fee_mode || req.body.resido_service_fee_mode);
    const serviceFeePerApartment = Number(req.body.service_fee_per_apartment ?? req.body.resido_fee_per_apartment ?? DEFAULT_SERVICE_FEE_PER_APARTMENT);
    const serviceFixedFee = Number(req.body.service_fixed_fee_amount ?? req.body.service_fee_amount ?? req.body.resido_service_fee ?? 0);
    const servicePaidUntilValue = cleanText(req.body.service_paid_until || req.body.resido_paid_until);

    if (!buildingLocation || !Number.isFinite(fee) || fee < 0) {
      return res.status(400).json({
        message: "Admin creation requires building/address and valid monthly fee"
      });
    }

    if (!isValidIban(bankIban)) {
      return res.status(400).json({ message: "Invalid IBAN" });
    }

    if (!isValidIban(platformIban)) {
      return res.status(400).json({ message: "Invalid Resido IBAN" });
    }

    if (stripeAccountId && !/^acct_[A-Za-z0-9]+$/.test(stripeAccountId)) {
      return res.status(400).json({ message: "Invalid Stripe account ID" });
    }

    if (!Number.isFinite(serviceFeePerApartment) || serviceFeePerApartment < 0) {
      return res.status(400).json({ message: "Invalid Resido service fee per apartment" });
    }

    if (!Number.isFinite(serviceFixedFee) || serviceFixedFee < 0) {
      return res.status(400).json({ message: "Invalid Resido fixed service fee" });
    }

    if (servicePaidUntilValue && !/^\d{4}-\d{2}-\d{2}$/.test(servicePaidUntilValue)) {
      return res.status(400).json({ message: "Invalid Resido paid-until date" });
    }

    buildingId = nextId(Object.values(db.buildings).filter(b => b.id !== "all"));

    db.buildings[String(buildingId)] = {
      id: buildingId,
      name: buildingLocation,
      address: buildingLocation,
      monthly_fee: fee,
      payment_due_day: 10,
      currency: "EUR",
      bank_iban: bankIban,
      stripe_account_id: stripeAccountId,
      service_fee_mode: serviceFeeMode,
      service_fee_per_apartment: serviceFeePerApartment,
      service_fixed_fee_amount: serviceFixedFee,
      service_fee_amount: 0,
      service_billing_cycle: normalizeServiceBillingCycle(req.body.service_billing_cycle || req.body.resido_billing_cycle),
      service_paid_until: servicePaidUntilValue,
      service_currency: "EUR",
      admin_user_id: null,
      status: "active",
      image: cleanText(req.body.building_image) ||
        "https://images.unsplash.com/photo-1460317442991-0ec209397118?auto=format&fit=crop&w=1600&q=80"
    };
    db.buildings[String(buildingId)].service_fee_amount = buildingServiceFeeAmount(db.buildings[String(buildingId)]);

    if (platformIban) {
      db.platform_settings ||= { resido_bank_iban: "", currency: "EUR" };
      db.platform_settings.resido_bank_iban = platformIban;
      db.platform_settings.currency = "EUR";
    }
  } else {
    buildingId = scopedBuildingId(req);
  }

  if (role !== "super_admin" && isBuildingCancelled(buildingId)) {
    return res.status(400).json({ message: "Cannot create user for cancelled building" });
  }

  const now = new Date().toISOString();
  const item = {
    id: nextId(db.users),
    full_name: fullName,
    apartment: role === "admin" ? "Admin" : apartment,
    floor: role === "admin" ? "" : cleanText(req.body.floor),
    phone: cleanText(req.body.phone),
    role,
    email,
    password_hash: await bcrypt.hash(password, BCRYPT_ROUNDS),
    building_id: buildingId,
    created_at: now,
    updated_at: now
  };

  db.users.push(item);

  if (role === "admin" && db.buildings[String(buildingId)]) {
    db.buildings[String(buildingId)].admin_user_id = item.id;
  }

  await saveDb();

  const loginLink = frontendLink(req);
  let emailSent = false;

  try {
    emailSent = await sendWelcomeEmail(email, fullName, email, password, loginLink);
  } catch (err) {
    console.error("Welcome email send failed:", err.message);
  }

  res.status(201).json({
    ...publicUser(item),
    email_sent: emailSent
  });
});

app.delete("/residents/:id", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  const target = db.users.find(u => String(u.id) === String(req.params.id));

  if (!target) {
    return res.status(404).json({ message: "User not found" });
  }

  if (target.role === "super_admin") {
    return res.status(403).json({ message: "Cannot delete super admin" });
  }

  if (
    req.user.role === "admin" &&
    (target.role !== "resident" || String(target.building_id) !== String(req.user.building_id))
  ) {
    return res.status(403).json({
      message: "Admins can delete only residents in their own building"
    });
  }

  if (target.role === "admin") {
    const building = db.buildings[String(target.building_id)];

    if (building && String(building.admin_user_id) === String(target.id)) {
      building.admin_user_id = null;
    }
  }

  db.users = db.users.filter(u => String(u.id) !== String(target.id));

  await saveDb();

  res.json({ message: "Deleted" });
});

async function managerRecordCreate(collection, req, res, extra = {}) {
  const buildingId = scopedBuildingId(req);

  if (!ensureBuildingScope(req, res, buildingId)) return null;

  if (isBuildingCancelled(buildingId)) {
    res.status(400).json({ message: "Cannot create records for cancelled building" });
    return null;
  }

  const item = {
    id: nextId(collection),
    building_id: buildingId,
    date: cleanText(req.body.date) || today(),
    created_at: new Date().toISOString(),
    ...extra
  };

  collection.unshift(item);
  await saveDb();

  res.status(201).json(item);
  return item;
}

function findManagedRecord(collection, req, res) {
  const item = collection.find(x => String(x.id) === String(req.params.id));

  if (!item) {
    res.status(404).json({ message: "Not found" });
    return null;
  }

  if (!ensureBuildingScope(req, res, item.building_id)) return null;

  return item;
}

app.post("/notices", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  await managerRecordCreate(db.notices, req, res, {
    ...localizedPayloadFromSingleInput(req.body, "title"),
    ...localizedPayloadFromSingleInput(req.body, "description")
  });
});

app.put("/notices/:id", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  const item = findManagedRecord(db.notices, req, res);
  if (!item) return;

  const titlePayload = localizedPayloadForUpdate(req.body, item, "title");
  const descriptionPayload = localizedPayloadForUpdate(req.body, item, "description");

  Object.assign(item, {
    date: cleanText(req.body.date) || item.date,
    ...titlePayload,
    ...descriptionPayload
  });

  await saveDb();

  res.json(item);
});

app.delete("/notices/:id", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  const item = findManagedRecord(db.notices, req, res);
  if (!item) return;

  db.notices = db.notices.filter(x => String(x.id) !== String(req.params.id));
  await saveDb();

  res.json({ message: "Deleted" });
});

app.post("/warnings", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  await managerRecordCreate(db.warnings, req, res, {
    level: cleanText(req.body.level) || "medium",
    ...localizedPayloadFromSingleInput(req.body, "title"),
    ...localizedPayloadFromSingleInput(req.body, "description")
  });
});

app.put("/warnings/:id", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  const item = findManagedRecord(db.warnings, req, res);
  if (!item) return;

  const titlePayload = localizedPayloadForUpdate(req.body, item, "title");
  const descriptionPayload = localizedPayloadForUpdate(req.body, item, "description");

  Object.assign(item, {
    date: cleanText(req.body.date) || item.date,
    level: cleanText(req.body.level) || item.level,
    ...titlePayload,
    ...descriptionPayload
  });

  await saveDb();

  res.json(item);
});

app.delete("/warnings/:id", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  const item = findManagedRecord(db.warnings, req, res);
  if (!item) return;

  db.warnings = db.warnings.filter(x => String(x.id) !== String(req.params.id));
  await saveDb();

  res.json({ message: "Deleted" });
});

function documentAttachmentPayload(body = {}) {
  const fileName = cleanText(body.file_name);
  const fileData = String(body.file_data || "");
  const fileType = cleanText(body.file_type);

  if (!fileName || !fileData) return {};
  if (!fileData.startsWith("data:")) return {};

  return {
    file_name: fileName,
    file_type: fileType || "application/octet-stream",
    file_data: fileData,
    file_uploaded_at: today()
  };
}

app.post("/documents", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  await managerRecordCreate(db.documents, req, res, {
    ...localizedPayloadFromSingleInput(req.body, "title"),
    ...localizedPayloadFromSingleInput(req.body, "category"),
    ...documentAttachmentPayload(req.body),
    updated_at: today()
  });
});

app.put("/documents/:id", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  const item = findManagedRecord(db.documents, req, res);
  if (!item) return;

  const titlePayload = localizedPayloadForUpdate(req.body, item, "title");
  const categoryPayload = localizedPayloadForUpdate(req.body, item, "category");

  Object.assign(item, {
    ...titlePayload,
    ...categoryPayload,
    ...documentAttachmentPayload(req.body),
    updated_at: today()
  });

  await saveDb();

  res.json(item);
});

app.delete("/documents/:id", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  const item = findManagedRecord(db.documents, req, res);
  if (!item) return;

  db.documents = db.documents.filter(x => String(x.id) !== String(req.params.id));
  await saveDb();

  res.json({ message: "Deleted" });
});

app.post("/create-request", requireAuth, writeRateLimit, async (req, res) => {
  if (isBuildingCancelled(req.user.building_id)) {
    return res.status(400).json({ message: "Cannot create request for cancelled building" });
  }

  const now = new Date().toISOString();
  const item = {
    id: nextId(db.requests),
    building_id: req.user.building_id,
    date: today(),
    created_at: now,
    updated_at: now,
    ...localizedPayloadFromSingleInput(req.body, "title"),
    ...localizedPayloadFromSingleInput(req.body, "description"),
    resident_email: req.user.email,
    status: "new"
  };

  db.requests.unshift(item);
  await saveDb();

  res.status(201).json(item);
});

app.put("/requests/:id/status", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  const item = findManagedRecord(db.requests, req, res);
  if (!item) return;

  const nextStatus = normalizeRequestStatus(req.body.status);

  if (!nextStatus) {
    return res.status(400).json({ message: "Invalid request status" });
  }

  item.status = nextStatus;
  item.updated_at = new Date().toISOString();

  await saveDb();

  res.json(item);
});

app.post("/requests/:id/cancel", requireAuth, writeRateLimit, async (req, res) => {
  const item = db.requests.find(x => String(x.id) === String(req.params.id));

  if (!item) {
    return res.status(404).json({ message: "Not found" });
  }

  const isOwnerResident =
    req.user.role === "resident" &&
    norm(item.resident_email) === norm(req.user.email);

  const isManager =
    ["admin", "super_admin"].includes(req.user.role) &&
    canAccessBuilding(req.user, item.building_id);

  if (!isOwnerResident && !isManager) {
    return res.status(403).json({ message: "Not allowed" });
  }

  item.status = "cancelled";
  item.updated_at = new Date().toISOString();

  await saveDb();

  res.json(item);
});

app.delete("/requests/:id", requireAuth, requireManager, writeRateLimit, async (req, res) => {
  const item = findManagedRecord(db.requests, req, res);
  if (!item) return;

  db.requests = db.requests.filter(x => String(x.id) !== String(req.params.id));
  await saveDb();

  res.json({ message: "Deleted" });
});

app.post("/stripe/create-checkout-session", requireAuth, paymentRateLimit, async (req, res) => {
  if (req.user.role === "super_admin") {
    return res.status(400).json({ message: "Super admin cannot pay here" });
  }

  if (!stripeConfigured()) {
    return res.status(503).json({
      message: "Stripe is not configured yet. Set STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET on Render."
    });
  }

  if (isBuildingCancelled(req.user.building_id)) {
    return res.status(400).json({ message: "Cannot pay for cancelled building" });
  }

  const building = buildingFor(req.user);

  if (!building || building.id === "all") {
    return res.status(400).json({ message: "Building payment is not available" });
  }

  const paymentType = cleanText(req.body.payment_type || req.body.paymentType || "building_fee") || "building_fee";
  const isServicePayment = paymentType === "resido_service";

  if (!["building_fee", "resido_service"].includes(paymentType)) {
    return res.status(400).json({ message: "Invalid payment type" });
  }

  if (isServiceSuspended(building.id) && !isServicePayment) {
    return res.status(402).json({ message: serviceAccessMessage() });
  }

  if (isServicePayment && req.user.role !== "admin") {
    return res.status(403).json({ message: "Only the building admin can pay the Resido service fee" });
  }

  const connectedAccountId = stripeConnectAccountId(building);
  let baseCents;
  let billingMonth = normalizeBillingMonth(req.body.billing_month);
  let serviceCycle = "";
  let serviceMonths = 0;
  let productName;
  let productDescription;

  if (isServicePayment && paidServiceFeeExists(building, billingMonth)) {
    return res.status(409).json({
      message: "This month is already paid. The next payment opens on the first day of the next month."
    });
  }

  if (!isServicePayment && paidBuildingFeeExists({ buildingId: building.id, email: req.user.email, billingMonth })) {
    return res.status(409).json({
      message: "This month is already paid. The next payment opens on the first day of the next month."
    });
  }

  if (isServicePayment) {
    serviceCycle = normalizeServiceBillingCycle(req.body.service_cycle || req.body.service_billing_cycle || building.service_billing_cycle);
    serviceMonths = serviceCycleMonths(serviceCycle);
    const serviceFeeAmount = buildingServiceFeeAmount(building);
    baseCents = amountToCents(serviceFeeAmount) * serviceMonths;
    productName = `Resido service fee - ${serviceCycle}`;
    productDescription = `${building.address || building.name || "Building"} | ${serviceMonths} month${serviceMonths === 1 ? "" : "s"} platform access`;
  } else {
    if (STRIPE_REQUIRE_CONNECT && !connectedAccountId) {
      return res.status(400).json({
        message: "Card/GPay payout is not connected for this building yet. Add the building Stripe Connect account first."
      });
    }

    baseCents = amountToCents(building.monthly_fee);
    productName = `Resido monthly fee - ${billingMonth}`;
    productDescription = `${building.address || building.name || "Building"}`;
  }

  if (baseCents < 50) {
    return res.status(400).json({
      message: isServicePayment
        ? "Resido service fee is too low for online card payment"
        : "Monthly fee is too low for online card payment"
    });
  }

  const onlineFeeCents = cardProcessingFeeCents(baseCents);
  const totalCents = baseCents + onlineFeeCents;
  const successUrl = new URL(frontendPageUrl(req));
  successUrl.searchParams.set("payment", "success");
  successUrl.searchParams.set("session_id", "{CHECKOUT_SESSION_ID}");
  successUrl.searchParams.set("payment_type", paymentType);
  const cancelUrl = new URL(frontendPageUrl(req));
  cancelUrl.searchParams.set("payment", "cancelled");
  cancelUrl.searchParams.set("payment_type", paymentType);

  const params = {
    mode: "payment",
    success_url: successUrl.toString(),
    cancel_url: cancelUrl.toString(),
    "payment_method_types[0]": "card",
    "line_items[0][quantity]": "1",
    "line_items[0][price_data][currency]": "eur",
    "line_items[0][price_data][unit_amount]": String(baseCents),
    "line_items[0][price_data][product_data][name]": productName,
    "line_items[0][price_data][product_data][description]": productDescription,
    "metadata[payment_type]": paymentType,
    "metadata[user_id]": String(req.user.id),
    "metadata[resident_email]": req.user.email,
    "metadata[building_id]": String(building.id),
    "metadata[apartment]": req.user.apartment || "-",
    "metadata[billing_month]": billingMonth,
    "metadata[service_cycle]": serviceCycle,
    "metadata[service_months]": String(serviceMonths),
    "metadata[service_fee_mode]": isServicePayment ? normalizeServiceFeeMode(building.service_fee_mode) : "",
    "metadata[service_fee_per_apartment]": isServicePayment ? String(serviceFeePerApartment(building)) : "",
    "metadata[service_apartment_count]": isServicePayment ? String(buildingApartmentCount(building.id)) : "",
    "metadata[base_amount_cents]": String(baseCents),
    "metadata[online_fee_cents]": String(onlineFeeCents),
    "metadata[total_amount_cents]": String(totalCents),
    "payment_intent_data[metadata][payment_type]": paymentType,
    "payment_intent_data[metadata][user_id]": String(req.user.id),
    "payment_intent_data[metadata][resident_email]": req.user.email,
    "payment_intent_data[metadata][building_id]": String(building.id),
    "payment_intent_data[metadata][billing_month]": billingMonth,
    "payment_intent_data[metadata][service_cycle]": serviceCycle,
    "payment_intent_data[metadata][service_months]": String(serviceMonths)
  };

  if (onlineFeeCents > 0) {
    params["line_items[1][quantity]"] = "1";
    params["line_items[1][price_data][currency]"] = "eur";
    params["line_items[1][price_data][unit_amount]"] = String(onlineFeeCents);
    params["line_items[1][price_data][product_data][name]"] = "Online payment fee";
    params["line_items[1][price_data][product_data][description]"] = "Shown before payment and included in the total.";
  }

  if (isValidEmail(req.user.email)) {
    params.customer_email = req.user.email;
  }

  if (!isServicePayment && connectedAccountId) {
    params["payment_intent_data[transfer_data][destination]"] = connectedAccountId;
    params["payment_intent_data[on_behalf_of]"] = connectedAccountId;
    if (onlineFeeCents > 0) params["payment_intent_data[application_fee_amount]"] = String(onlineFeeCents);
  }

  try {
    const session = await stripeApiRequest("checkout/sessions", params);

    res.status(201).json({
      id: session.id,
      url: session.url,
      base_amount: centsToAmount(baseCents),
      online_fee: centsToAmount(onlineFeeCents),
      total_amount: centsToAmount(totalCents),
      payment_type: paymentType,
      service_cycle: serviceCycle,
      service_months: serviceMonths,
      connect_ready: isServicePayment ? true : Boolean(connectedAccountId)
    });
  } catch (err) {
    res.status(502).json({ message: err.message || "Could not start Stripe Checkout" });
  }
});

function rememberStripeEvent(event) {
  if (!event?.id) return true;
  db.stripe_events ||= [];

  if (db.stripe_events.some((item) => item.id === event.id)) return false;

  db.stripe_events.unshift({
    id: event.id,
    type: cleanText(event.type),
    created_at: new Date().toISOString()
  });

  db.stripe_events = db.stripe_events.slice(0, 300);
  return true;
}

function stripeObjectId(value) {
  if (!value) return "";
  if (typeof value === "string") return cleanText(value);
  return cleanText(value.id);
}

function stripePaymentIntentId(obj) {
  return stripeObjectId(obj?.payment_intent || obj?.paymentIntent || obj?.payment_intent_id);
}

function stripeChargeId(obj) {
  return stripeObjectId(obj?.charge || obj?.latest_charge || obj?.latestCharge || obj?.id);
}

function findPaymentForStripeObject(obj) {
  const paymentIntentId = stripePaymentIntentId(obj);
  const chargeId = stripeChargeId(obj);
  const checkoutSessionId = cleanText(obj?.checkout_session || obj?.checkout_session_id || obj?.session_id);

  return db.payments.find((payment) => (
    (paymentIntentId && payment.stripe_payment_intent_id === paymentIntentId) ||
    (chargeId && (payment.stripe_charge_id === chargeId || payment.stripe_latest_charge_id === chargeId)) ||
    (checkoutSessionId && payment.stripe_session_id === checkoutSessionId)
  ));
}

function paymentEventList(payment) {
  if (!Array.isArray(payment.stripe_events)) payment.stripe_events = [];
  return payment.stripe_events;
}

function addPaymentStripeEvent(payment, eventType, details = {}) {
  payment.updated_at = new Date().toISOString();
  paymentEventList(payment).unshift({
    type: eventType,
    at: payment.updated_at,
    ...details
  });
  payment.stripe_events = payment.stripe_events.slice(0, 20);
}

async function recordStripeCheckoutSession(session) {
  if (!session || session.payment_status !== "paid") return;
  if (db.payments.some(p => p.stripe_session_id === session.id)) return;

  const metadata = session.metadata || {};
  const user = db.users.find(u => String(u.id) === String(metadata.user_id))
    || db.users.find(u => norm(u.email) === norm(metadata.resident_email));
  const buildingId = metadata.building_id || user?.building_id;
  const building = db.buildings[String(buildingId)];

  if (!building || String(building.id) === "all") return;

  const paymentType = cleanText(metadata.payment_type || metadata.paymentType || "building_fee") || "building_fee";
  const billingMonth = normalizeBillingMonth(metadata.billing_month);
  const baseCents = Number(metadata.base_amount_cents || amountToCents(building.monthly_fee));
  const onlineFeeCents = Number(metadata.online_fee_cents || 0);
  const totalCents = Number(metadata.total_amount_cents || session.amount_total || (baseCents + onlineFeeCents));
  const now = new Date().toISOString();

  if (paymentType === "resido_service") {
    if (paidServiceFeeExists(building, billingMonth)) return;

    const serviceCycle = normalizeServiceBillingCycle(metadata.service_cycle || building.service_billing_cycle);
    const parsedServiceMonths = Number(metadata.service_months || serviceCycleMonths(serviceCycle));
    const serviceMonths = Number.isFinite(parsedServiceMonths) && parsedServiceMonths > 0
      ? Math.floor(parsedServiceMonths)
      : serviceCycleMonths(serviceCycle);
    const paidUntilBefore = servicePaidUntil(building);
    const renewalBase = paidUntilBefore && paidUntilBefore > today() ? paidUntilBefore : today();
    const paidUntilAfter = addMonthsDate(renewalBase, serviceMonths);
    building.service_paid_until = paidUntilAfter;
    building.service_billing_cycle = serviceCycle;
    building.service_currency = "EUR";

    db.payments.unshift({
      id: nextId(db.payments),
      building_id: building.id,
      date: today(),
      created_at: now,
      paid_at: now,
      apartment: "Admin",
      resident_email: norm(metadata.resident_email || user?.email),
      amount: centsToAmount(totalCents),
      base_amount: centsToAmount(baseCents),
      online_fee: centsToAmount(onlineFeeCents),
      currency: "EUR",
      method: "resido_service",
      provider: "stripe",
      payment_type: "resido_service",
      service_cycle: serviceCycle,
      service_months: serviceMonths,
      service_fee_mode: normalizeServiceFeeMode(metadata.service_fee_mode || building.service_fee_mode),
      service_fee_per_apartment: Number(metadata.service_fee_per_apartment || serviceFeePerApartment(building)),
      service_apartment_count: Number(metadata.service_apartment_count || buildingApartmentCount(building.id)),
      service_paid_until_before: paidUntilBefore,
      service_paid_until_after: paidUntilAfter,
      stripe_session_id: session.id,
      stripe_payment_intent_id: cleanText(session.payment_intent),
      stripe_charge_id: stripeObjectId(session.latest_charge || session.charge),
      status: "paid",
      billing_month: billingMonth
    });

    await saveDb();
    return;
  }

  if (paidBuildingFeeExists({ buildingId: building.id, email: metadata.resident_email || user?.email, billingMonth })) return;

  db.payments.unshift({
    id: nextId(db.payments),
    building_id: building.id,
    date: today(),
    created_at: now,
    paid_at: now,
    apartment: cleanText(metadata.apartment) || user?.apartment || "-",
    resident_email: norm(metadata.resident_email || user?.email),
    amount: centsToAmount(totalCents),
    base_amount: centsToAmount(baseCents),
    online_fee: centsToAmount(onlineFeeCents),
    currency: "EUR",
    method: "card_gpay",
    provider: "stripe",
    payment_type: "building_fee",
    stripe_session_id: session.id,
    stripe_payment_intent_id: cleanText(session.payment_intent),
    stripe_charge_id: stripeObjectId(session.latest_charge || session.charge),
    status: "paid",
    billing_month: billingMonth
  });

  await saveDb();
}

async function recordStripeRefund(obj, eventType) {
  const payment = findPaymentForStripeObject(obj);
  if (!payment) return;

  const refundStatus = cleanText(obj.status);
  if (/^(failed|canceled|cancelled)$/i.test(refundStatus)) {
    payment.refund_status = refundStatus;
    addPaymentStripeEvent(payment, eventType, {
      refund_id: stripeObjectId(obj.id),
      charge_id: stripeObjectId(obj.charge),
      status: refundStatus
    });
    await saveDb();
    return;
  }

  if (eventType.startsWith("refund.")) {
    const refundAmount = centsToAmount(Number(obj.amount || 0));
    payment.stripe_charge_id = stripeObjectId(obj.charge) || payment.stripe_charge_id || "";
    payment.stripe_refund_id = stripeObjectId(obj.id) || payment.stripe_refund_id || "";
    payment.refund_status = refundStatus || eventType.replace("refund.", "");
    payment.refunded_amount = Math.max(Number(payment.refunded_amount || 0), refundAmount);
    if (refundStatus === "pending") payment.status = "refund_pending";
    if (refundStatus === "succeeded" && payment.status === "paid") payment.status = "partially_refunded";
    addPaymentStripeEvent(payment, eventType, {
      refund_id: payment.stripe_refund_id,
      charge_id: payment.stripe_charge_id,
      amount: refundAmount,
      status: payment.refund_status
    });
    await saveDb();
    return;
  }

  const amountRefunded = Number(obj.amount_refunded || obj.amount || 0);
  const amountTotal = Number(obj.amount || amountToCents(payment.amount));
  const isFullRefund = obj.refunded === true || (amountRefunded > 0 && amountTotal > 0 && amountRefunded >= amountTotal);

  payment.status = isFullRefund ? "refunded" : "partially_refunded";
  payment.refunded_amount = centsToAmount(amountRefunded);
  payment.stripe_charge_id = stripeObjectId(obj.charge) || payment.stripe_charge_id || stripeObjectId(obj.id);
  payment.stripe_refund_id = stripeObjectId(obj.refund || obj.id) || payment.stripe_refund_id || "";
  payment.refund_status = refundStatus || (isFullRefund ? "succeeded" : "partial");
  addPaymentStripeEvent(payment, eventType, {
    refund_id: payment.stripe_refund_id,
    charge_id: payment.stripe_charge_id,
    amount: payment.refunded_amount,
    status: payment.refund_status
  });

  await saveDb();
}

async function recordStripeChargeReference(obj, eventType) {
  const payment = findPaymentForStripeObject(obj);
  if (!payment) return;

  const chargeId = eventType === "charge.succeeded"
    ? stripeObjectId(obj.id)
    : stripeObjectId(obj.latest_charge || obj.charge);

  if (chargeId) payment.stripe_charge_id = chargeId;
  if (stripePaymentIntentId(obj)) payment.stripe_payment_intent_id = stripePaymentIntentId(obj);
  addPaymentStripeEvent(payment, eventType, {
    charge_id: payment.stripe_charge_id || "",
    payment_intent_id: payment.stripe_payment_intent_id || ""
  });

  await saveDb();
}

async function recordStripeDispute(dispute, eventType) {
  const payment = findPaymentForStripeObject(dispute);
  if (!payment) return;

  const stripeStatus = cleanText(dispute.status);
  const closedWon = stripeStatus === "won" || stripeStatus === "warning_closed";
  const closedLost = stripeStatus === "lost";

  payment.status = closedWon ? "dispute_won" : (closedLost ? "dispute_lost" : "disputed");
  payment.stripe_dispute_id = stripeObjectId(dispute.id);
  payment.stripe_charge_id = stripeObjectId(dispute.charge) || payment.stripe_charge_id || "";
  payment.dispute_status = stripeStatus || eventType.replace("charge.dispute.", "");
  payment.dispute_reason = cleanText(dispute.reason);
  payment.dispute_amount = centsToAmount(dispute.amount);
  addPaymentStripeEvent(payment, eventType, {
    dispute_id: payment.stripe_dispute_id,
    charge_id: payment.stripe_charge_id,
    reason: payment.dispute_reason,
    status: payment.dispute_status,
    amount: payment.dispute_amount
  });

  await saveDb();
}

async function handleStripeWebhook(req, res) {
  if (!verifyStripeWebhookSignature(req.body, req.headers["stripe-signature"])) {
    return res.status(400).send("Invalid Stripe signature");
  }

  let event;

  try {
    event = JSON.parse(req.body.toString("utf8"));
  } catch (_) {
    return res.status(400).send("Invalid Stripe payload");
  }

  if (!rememberStripeEvent(event)) {
    return res.json({ received: true, duplicate: true });
  }

  const object = event.data?.object;

  if (event.type === "checkout.session.completed" || event.type === "checkout.session.async_payment_succeeded") {
    await recordStripeCheckoutSession(object);
  } else if (event.type === "charge.succeeded" || event.type === "payment_intent.succeeded") {
    await recordStripeChargeReference(object, event.type);
  } else if (event.type === "charge.refunded" || event.type === "refund.created" || event.type === "refund.updated") {
    await recordStripeRefund(object, event.type);
  } else if (
    event.type === "charge.dispute.created" ||
    event.type === "charge.dispute.updated" ||
    event.type === "charge.dispute.closed" ||
    event.type === "charge.dispute.funds_withdrawn" ||
    event.type === "charge.dispute.funds_reinstated"
  ) {
    await recordStripeDispute(object, event.type);
  }

  res.json({ received: true });
}

app.post("/pay", requireAuth, paymentRateLimit, async (req, res) => {
  if (!ALLOW_DEMO_CARD_PAYMENTS) {
    return res.status(403).json({
      message: "Demo card payments are disabled. Use Stripe Checkout for real card/GPay payments."
    });
  }

  if (isBuildingCancelled(req.user.building_id)) {
    return res.status(400).json({ message: "Cannot pay for cancelled building" });
  }

  const building = buildingFor(req.user);
  const cardNumber = digitsOnly(req.body.card_number || req.body.cardNumber);
  const cardMask = maskCardNumber(cardNumber);
  const cardBrand = normalizeCardBrand(req.body.card_brand || req.body.cardBrand || detectCardBrand(cardNumber));
  const paymentType = cleanText(req.body.payment_type || req.body.paymentType || "building_fee") || "building_fee";
  const isServicePayment = paymentType === "resido_service";
  const billingMonth = normalizeBillingMonth(req.body.billing_month);
  const now = new Date().toISOString();

  if (!cardMask) {
    return res.status(400).json({ message: "Valid card number is required" });
  }

  if (!["building_fee", "resido_service"].includes(paymentType)) {
    return res.status(400).json({ message: "Invalid payment type" });
  }

  if (isServicePayment && req.user.role !== "admin") {
    return res.status(403).json({ message: "Only the building admin can pay the Resido service fee" });
  }

  if (isServicePayment && paidServiceFeeExists(building, billingMonth)) {
    return res.status(409).json({
      message: "This month is already paid. The next payment opens on the first day of the next month."
    });
  }

  if (!isServicePayment && paidBuildingFeeExists({ buildingId: req.user.building_id, email: req.user.email, billingMonth })) {
    return res.status(409).json({
      message: "This month is already paid. The next payment opens on the first day of the next month."
    });
  }

  const item = {
    id: nextId(db.payments),
    building_id: req.user.building_id,
    date: today(),
    created_at: now,
    paid_at: now,
    apartment: req.user.apartment || "-",
    resident_email: req.user.email,
    amount: Number(req.body.amount || building?.monthly_fee || 0),
    currency: "EUR",
    method: isServicePayment ? "resido_service" : "card",
    payment_type: paymentType,
    card_brand: cardBrand,
    card_mask: cardMask,
    status: "paid",
    billing_month: billingMonth
  };

  if (isServicePayment) {
    const serviceCycle = normalizeServiceBillingCycle(req.body.service_cycle || req.body.service_billing_cycle || building?.service_billing_cycle);
    const serviceMonths = serviceCycleMonths(serviceCycle);
    const paidUntilBefore = servicePaidUntil(building);
    const renewalBase = paidUntilBefore && paidUntilBefore > today() ? paidUntilBefore : today();
    const paidUntilAfter = addMonthsDate(renewalBase, serviceMonths);
    building.service_paid_until = paidUntilAfter;
    building.service_billing_cycle = serviceCycle;
    building.service_currency = "EUR";
    item.apartment = "Admin";
    item.service_cycle = serviceCycle;
    item.service_months = serviceMonths;
    item.service_fee_mode = normalizeServiceFeeMode(building?.service_fee_mode);
    item.service_fee_per_apartment = serviceFeePerApartment(building);
    item.service_apartment_count = buildingApartmentCount(building?.id);
    item.service_paid_until_before = paidUntilBefore;
    item.service_paid_until_after = paidUntilAfter;
  }

  db.payments.unshift(item);
  await saveDb();

  res.status(201).json(item);
});

process.on("uncaughtException", err => {
  console.error("UNCAUGHT EXCEPTION:", err);
});

process.on("unhandledRejection", err => {
  console.error("UNHANDLED REJECTION:", err);
});

async function startServer() {
  db = await loadDb();
  await applyRuntimeConfig();
  await migratePasswords();
  await assertProductionReady();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Frontend: http://localhost:${PORT}/`);
    console.log("Currency: EUR only");
    console.log("Cancelled buildings are hidden from active lists.");
    console.log(emailConfigured()
      ? "Email delivery is configured."
      : "Email delivery is not configured. Set RESEND_API_KEY and MAIL_FROM before production use.");
  });
}

startServer().catch((err) => {
  console.error("STARTUP ERROR:", err);
  process.exit(1);
});
