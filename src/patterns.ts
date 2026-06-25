/**
 * Secret detection patterns for env-secure.
 * Each pattern has a name, regex, confidence level, and associated env var name.
 */

export interface SecretPattern {
  name: string;
  regex: RegExp;
  confidence: 'high' | 'medium' | 'low';
  envVar?: string;
  category: string;
}

export const PATTERNS: SecretPattern[] = [
  // ─── Cloud Providers ───────────────────────────────
  {
    name: 'AWS Access Key ID',
    regex: /(?:AKIA|ASIA|ANPA|AROA|AIPA|ANVA|AIDA)[A-Z0-9]{16}/g,
    confidence: 'high',
    envVar: 'AWS_ACCESS_KEY_ID',
    category: 'Cloud',
  },
  {
    name: 'AWS Secret Access Key',
    regex: /aws.{0,20}(?:secret.?access.?key|secret.?key).{0,20}['\"][A-Za-z0-9\/+=]{40}['\"]/gi,
    confidence: 'high',
    envVar: 'AWS_SECRET_ACCESS_KEY',
    category: 'Cloud',
  },
  {
    name: 'Google API Key',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    confidence: 'high',
    envVar: 'GOOGLE_API_KEY',
    category: 'Cloud',
  },
  {
    name: 'Google OAuth Client ID',
    regex: /[0-9]+-[0-9a-zA-Z_]+\.apps\.googleusercontent\.com/g,
    confidence: 'high',
    envVar: 'GOOGLE_CLIENT_ID',
    category: 'Cloud',
  },
  {
    name: 'Google OAuth Client Secret',
    regex: /GOCSPX-[0-9a-zA-Z_\-]{28}/g,
    confidence: 'high',
    envVar: 'GOOGLE_CLIENT_SECRET',
    category: 'Cloud',
  },
  {
    name: 'DigitalOcean Personal Access Token',
    regex: /dop_v1_[0-9a-f]{64}/g,
    confidence: 'high',
    envVar: 'DIGITALOCEAN_TOKEN',
    category: 'Cloud',
  },
  {
    name: 'Heroku API Key',
    regex: /heroku.{0,10}(?:api.?key).{0,10}['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]/gi,
    confidence: 'high',
    envVar: 'HEROKU_API_KEY',
    category: 'Cloud',
  },
  {
    name: 'Vercel Token',
    regex: /[a-zA-Z0-9]{24,40}(?:(?:[^a-zA-Z0-9])|$)/g,
    confidence: 'low',
    envVar: 'VERCEL_TOKEN',
    category: 'Cloud',
  },
  {
    name: 'Netlify API Token',
    regex: /nfp_[a-zA-Z0-9]{40,64}/g,
    confidence: 'high',
    envVar: 'NETLIFY_AUTH_TOKEN',
    category: 'Cloud',
  },
  {
    name: 'Azure Storage Key',
    regex: /[a-zA-Z0-9\/+=]{88}/g,
    confidence: 'low',
    envVar: 'AZURE_STORAGE_KEY',
    category: 'Cloud',
  },

  // ─── Version Control ───────────────────────────────
  {
    name: 'GitHub Personal Access Token',
    regex: /ghp_[a-zA-Z0-9]{36,255}/g,
    confidence: 'high',
    envVar: 'GITHUB_TOKEN',
    category: 'Version Control',
  },
  {
    name: 'GitHub OAuth Access Token',
    regex: /gho_[a-zA-Z0-9]{36,255}/g,
    confidence: 'high',
    envVar: 'GITHUB_TOKEN',
    category: 'Version Control',
  },
  {
    name: 'GitHub App Token',
    regex: /ghs_[a-zA-Z0-9]{36,255}/g,
    confidence: 'high',
    envVar: 'GITHUB_APP_TOKEN',
    category: 'Version Control',
  },
  {
    name: 'GitLab Personal Access Token',
    regex: /glpat-[0-9a-zA-Z_\-]{20,40}/g,
    confidence: 'high',
    envVar: 'GITLAB_TOKEN',
    category: 'Version Control',
  },

  // ─── Payments ──────────────────────────────────────
  {
    name: 'Stripe Live Secret Key',
    regex: /sk_live_[0-9a-zA-Z]{24,40}/g,
    confidence: 'high',
    envVar: 'STRIPE_SECRET_KEY',
    category: 'Payments',
  },
  {
    name: 'Stripe Test Secret Key',
    regex: /sk_test_[0-9a-zA-Z]{24,40}/g,
    confidence: 'high',
    envVar: 'STRIPE_SECRET_KEY',
    category: 'Payments',
  },
  {
    name: 'Stripe Live Publishable Key',
    regex: /pk_live_[0-9a-zA-Z]{24,40}/g,
    confidence: 'high',
    envVar: 'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY',
    category: 'Payments',
  },
  {
    name: 'Stripe Webhook Secret',
    regex: /whsec_[0-9a-zA-Z]{24,60}/g,
    confidence: 'high',
    envVar: 'STRIPE_WEBHOOK_SECRET',
    category: 'Payments',
  },
  {
    name: 'Shopify Access Token',
    regex: /shpat_[a-zA-Z0-9]{32}/g,
    confidence: 'high',
    envVar: 'SHOPIFY_ACCESS_TOKEN',
    category: 'Payments',
  },
  {
    name: 'PayPal Client Secret',
    regex: /E[A-Za-z0-9]{31}/g,
    confidence: 'medium',
    envVar: 'PAYPAL_CLIENT_SECRET',
    category: 'Payments',
  },

  // ─── Communication ─────────────────────────────────
  {
    name: 'Slack Bot Token',
    regex: /xoxb-[0-9a-zA-Z]{10,48}/g,
    confidence: 'high',
    envVar: 'SLACK_BOT_TOKEN',
    category: 'Communication',
  },
  {
    name: 'Slack Workspace Token',
    regex: /xoxa-[0-9a-zA-Z]{10,48}/g,
    confidence: 'high',
    envVar: 'SLACK_ACCESS_TOKEN',
    category: 'Communication',
  },
  {
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]{30,70}/g,
    confidence: 'high',
    envVar: 'SLACK_WEBHOOK_URL',
    category: 'Communication',
  },
  {
    name: 'Discord Bot Token',
    regex: /[a-zA-Z0-9_-]{23,28}\.[a-zA-Z0-9_-]{6,7}\.[a-zA-Z0-9_-]{27,}/g,
    confidence: 'high',
    envVar: 'DISCORD_BOT_TOKEN',
    category: 'Communication',
  },
  {
    name: 'Twilio Account SID',
    regex: /AC[a-zA-Z0-9]{32}/g,
    confidence: 'high',
    envVar: 'TWILIO_ACCOUNT_SID',
    category: 'Communication',
  },
  {
    name: 'Twilio Auth Token',
    regex: /tw[a-f0-9]{32}/g,
    confidence: 'high',
    envVar: 'TWILIO_AUTH_TOKEN',
    category: 'Communication',
  },

  // ─── Email ─────────────────────────────────────────
  {
    name: 'SendGrid API Key',
    regex: /SG\.[a-zA-Z0-9_\-]{20,80}\.[a-zA-Z0-9_\-]{20,80}/g,
    confidence: 'high',
    envVar: 'SENDGRID_API_KEY',
    category: 'Email',
  },
  {
    name: 'Mailgun API Key',
    regex: /key-[0-9a-fA-F]{32}/g,
    confidence: 'high',
    envVar: 'MAILGUN_API_KEY',
    category: 'Email',
  },
  {
    name: 'Mailchimp API Key',
    regex: /[0-9a-f]{32}-us[0-9]{1,2}/g,
    confidence: 'high',
    envVar: 'MAILCHIMP_API_KEY',
    category: 'Email',
  },
  {
    name: 'Postmark Server Token',
    regex: /[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}/g,
    confidence: 'medium',
    envVar: 'POSTMARK_TOKEN',
    category: 'Email',
  },
  {
    name: 'Resend API Key',
    regex: /re_[a-zA-Z0-9]{20,40}/g,
    confidence: 'high',
    envVar: 'RESEND_API_KEY',
    category: 'Email',
  },

  // ─── Database ──────────────────────────────────────
  {
    name: 'MongoDB Connection String',
    regex: /mongodb(?:\+srv)?:\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9_\-\.]+\/[a-zA-Z0-9_\-]+/g,
    confidence: 'high',
    envVar: 'MONGODB_URI',
    category: 'Database',
  },
  {
    name: 'PostgreSQL Connection String',
    regex: /postgres(?:ql)?:\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-@]+@[a-zA-Z0-9_\-\.]+:\d+\/[a-zA-Z0-9_\-]+/g,
    confidence: 'high',
    envVar: 'DATABASE_URL',
    category: 'Database',
  },
  {
    name: 'MySQL Connection String',
    regex: /mysql:\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-@]+@[a-zA-Z0-9_\-\.]+:\d+\/[a-zA-Z0-9_\-]+/g,
    confidence: 'high',
    envVar: 'MYSQL_URL',
    category: 'Database',
  },
  {
    name: 'Redis Connection String',
    regex: /redis:\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-@]+@[a-zA-Z0-9_\-\.]+:\d+/g,
    confidence: 'high',
    envVar: 'REDIS_URL',
    category: 'Database',
  },
  {
    name: 'Supabase URL',
    regex: /https:\/\/[a-zA-Z0-9_\-]{20,40}\.supabase\.co/g,
    confidence: 'high',
    envVar: 'NEXT_PUBLIC_SUPABASE_URL',
    category: 'Database',
  },
  {
    name: 'Supabase Anon Key',
    regex: /eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}/g,
    confidence: 'high',
    envVar: 'NEXT_PUBLIC_SUPABASE_ANON_KEY',
    category: 'Database',
  },

  // ─── Auth & Tokens ─────────────────────────────────
  {
    name: 'JWT Token',
    regex: /eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9._\-]{10,}\.[a-zA-Z0-9_\-]{10,}/g,
    confidence: 'medium',
    envVar: 'JWT_SECRET',
    category: 'Auth',
  },
  {
    name: 'npm Auth Token',
    regex: /npm_[a-z0-9]{36}/g,
    confidence: 'high',
    envVar: 'NPM_TOKEN',
    category: 'Auth',
  },
  {
    name: 'npmRC auth token',
    regex: /\/\/registry\.npmjs\.org\/:_authToken=[a-zA-Z0-9_\-]{36,}/g,
    confidence: 'high',
    envVar: 'NPM_TOKEN',
    category: 'Auth',
  },
  {
    name: 'Docker Config Auth',
    regex: /"auth":"[a-zA-Z0-9\/+=]{20,}"/g,
    confidence: 'medium',
    envVar: 'DOCKER_AUTH',
    category: 'Auth',
  },
  {
    name: 'Clerk Secret Key',
    regex: /sk_test_[a-zA-Z0-9]{40,60}/g,
    confidence: 'high',
    envVar: 'CLERK_SECRET_KEY',
    category: 'Auth',
  },
  {
    name: 'Clerk Publishable Key',
    regex: /pk_test_[a-zA-Z0-9]{40,60}/g,
    confidence: 'high',
    envVar: 'NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY',
    category: 'Auth',
  },
  {
    name: 'Auth0 Client Secret',
    regex: /auth0.{0,20}(?:client.?secret).{0,20}['\"][a-zA-Z0-9_\-]{32,64}['\"]/gi,
    confidence: 'high',
    envVar: 'AUTH0_CLIENT_SECRET',
    category: 'Auth',
  },

  // ─── Monitoring ────────────────────────────────────
  {
    name: 'Sentry DSN',
    regex: /https:\/\/[a-f0-9]{32}@[a-f0-9]{32}\.ingest\.sentry\.io\/\d+/g,
    confidence: 'high',
    envVar: 'NEXT_PUBLIC_SENTRY_DSN',
    category: 'Monitoring',
  },
  {
    name: 'Datadog API Key',
    regex: /[a-f0-9]{32}/g,
    confidence: 'medium',
    envVar: 'DATADOG_API_KEY',
    category: 'Monitoring',
  },

  // ─── Generic Secrets ──────────────────────────────
  {
    name: 'Generic API Key',
    regex: /(?:api[_-]?(?:key|secret)|secret[_-]?key)[\s:=]+['\"][A-Za-z0-9\/+=_\-]{20,80}['\"]/gi,
    confidence: 'medium',
    category: 'Generic',
  },
  {
    name: 'Password Field',
    regex: /(?:password|passwd|pwd)[\s:=]+['\"][a-zA-Z0-9!@#$%^&*()_+\-={}|;:',.<>?\/]{8,80}['\"]/gi,
    confidence: 'medium',
    category: 'Generic',
  },
  {
    name: 'Private Key',
    regex: /-----BEGIN (?:RSA |DSA |EC |PGP )?PRIVATE KEY-----[\s\S]{1,5000}-----END (?:RSA |DSA |EC |PGP )?PRIVATE KEY-----/g,
    confidence: 'high',
    category: 'Generic',
  },
  {
    name: 'Bearer Token in Code',
    regex: /['\"]Bearer\s+[a-zA-Z0-9_\-\.]{20,200}['\"]/g,
    confidence: 'medium',
    category: 'Generic',
  },
  {
    name: 'Environment Variable Assignment',
    regex: /^[A-Z][A-Z0-9_]{2,50}=['\"][a-zA-Z0-9!@#$%^&*()_+\-={}|;:',.<>?\/]{10,200}['\"]$/gm,
    confidence: 'low',
    category: 'Generic',
  },
];

/**
 * Get all patterns, optionally filtered by minimum confidence level.
 */
export function getPatterns(minConfidence: 'high' | 'medium' | 'low' = 'low'): SecretPattern[] {
  const levels = ['high', 'medium', 'low'];
  const maxIdx = levels.indexOf(minConfidence);
  // Return patterns whose confidence level is AT MOST the specified threshold.
  // E.g., 'low' includes all levels (high, medium, low),
  // 'medium' includes high + medium,
  // 'high' includes only high.
  return PATTERNS.filter(p => levels.indexOf(p.confidence) <= maxIdx);
}
