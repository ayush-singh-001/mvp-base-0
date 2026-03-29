require('dotenv').config();

// Validate environment variables before starting
const { validateEnvironment } = require('./lib/validateEnv');
validateEnvironment();

const express   = require('express');
const mongoose  = require('mongoose');
const cors      = require('cors');
const multer    = require('multer');
const crypto    = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet    = require('helmet');

const { getThreshold, checkAuthenticity } = require('./lib/aiCheck');
const { pinToIPFS }                       = require('./lib/ipfs');
const DocModel                            = require('./models/Document');
const { requireAuth, loginHandler }       = require('./middleware/auth');
const { validateFileUpload, validateLogin } = require('./middleware/validation');
const logger                              = require('./lib/logger');

const app = express();

// --- Trust Proxy Configuration -----------------------------------------------
// Enable trust proxy when running behind reverse proxies (Render, Heroku, etc.)
// This allows Express to correctly read X-Forwarded-* headers for rate limiting
app.set('trust proxy', true);

// --- Security Headers --------------------------------------------------------
app.use(helmet({
  crossOriginEmbedderPolicy: false, // Needed for IPFS integration
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.edenai.run", "https://ipfs.io"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
}));

// --- CORS Configuration ------------------------------------------------------
const allowedOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(origin => origin.trim())
  : ['http://localhost:3000', 'http://localhost:3001'];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, curl)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
      callback(null, true);
    } else {
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// --- Request Size Limits -----------------------------------------------------
app.use(express.json({ limit: '10mb' })); // Prevent large JSON attacks
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// --- Rate Limiters -----------------------------------------------------------
// General API: 200 req / 15 min per IP
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  // Ensure CORS headers are still sent on rate-limit rejection responses
  handler: (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.status(429).json({ error: 'Too many requests – please try again later.' });
  }
});

// AI analysis routes: expensive – 20 req / 15 min per IP
const analyzeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  // Ensure CORS headers are still sent on rate-limit rejection responses
  handler: (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.status(429).json({ error: 'AI analysis rate limit exceeded – please wait before submitting another file.' });
  }
});

app.use('/api', generalLimiter);

// --- MongoDB Setup -----------------------------------------------------------
mongoose.connect(process.env.MONGO_URI)
  .then(() => logger.info('MongoDB connected'))
  .catch((err) => { logger.error('MongoDB connection error:', err.message); process.exit(1); });

// --- Fabric routes (optional – only loaded when FABRIC_ENABLED=true) ---------
if (process.env.FABRIC_ENABLED === 'true') {
  try {
    const fabricRoutes = require('./fabric/fabricRoutes');
    app.use('/api/fabric/analyze', analyzeLimiter);   // extra cap on Fabric AI route
    app.use('/api/fabric', fabricRoutes);
    logger.info('[Fabric] Routes mounted at /api/fabric');
  } catch (err) {
    logger.warn('[Fabric] Failed to load fabric routes:', err.message);
  }
}

// --- Enhanced Multer Configuration with File Type Security ------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 1 // Only 1 file per request
  },
  fileFilter: (req, file, cb) => {
    // Allow only specific file types
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif',
      'application/pdf',
      'video/mp4', 'video/avi',
      'text/plain'
    ];

    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('File type not allowed'), false);
    }
  }
});

// --- POST /api/analyze -------------------------------------------------------
app.post('/api/analyze', analyzeLimiter, upload.single('file'), validateFileUpload, async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });

    const fileBuffer = req.file.buffer;
    const fileName   = req.file.originalname;
    const mimeType   = req.file.mimetype;

    // A. SHA-256 hash
    const docHash = '0x' + crypto.createHash('sha256').update(fileBuffer).digest('hex');

    // B. AI check with per-type threshold
    const threshold = getThreshold(mimeType);
    const aiResult  = await checkAuthenticity(fileBuffer, fileName, mimeType);

    if (aiResult.score > threshold) {
      return res.status(400).json({
        error:      'AI check failed: content appears synthetic or forged.',
        aiScore:    aiResult.score,
        aiProvider: aiResult.provider,
        threshold
      });
    }

    // C. isAuthentic reflects actual gate outcome (no longer hardcoded true)
    const isAuthentic = aiResult.score <= threshold;

    // D. IPFS via Pinata (gracefully skipped when keys not configured)
    let ipfsCid = null;
    try {
      ipfsCid = await pinToIPFS(fileBuffer, fileName);
      if (ipfsCid) logger.info(`[IPFS] Pinned: ${ipfsCid}`);
    } catch (pinErr) {
      logger.warn('[IPFS] Pinata upload failed (non-fatal):', pinErr.message);
    }

    // E. Persist to MongoDB
    await DocModel.findOneAndUpdate(
      { docHash },
      { docHash, fileName, aiScore: aiResult.score, aiProvider: aiResult.provider,
        aiDetails: aiResult.details, isAuthentic, ipfsCid },
      { upsert: true, returnDocument: 'after' }
    );

    res.json({ success: true, docHash, aiScore: aiResult.score, aiProvider: aiResult.provider, ipfsCid });

  } catch (err) {
    logger.error('/api/analyze error:', err);
    res.status(500).json({ error: err.message });
  }
});

// --- POST /api/auth/login ----------------------------------------------------
app.post('/api/auth/login', validateLogin, loginHandler);

// --- GET /api/health ---------------------------------------------------------
app.get('/api/health', async (_req, res) => {
  const health = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    environment: process.env.NODE_ENV || 'development',
    mongodb: {
      status: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      readyState: mongoose.connection.readyState,
      host: mongoose.connection.host || 'unknown',
      name: mongoose.connection.name || 'unknown'
    },
    services: {
      ai: !!process.env.AI_API_KEY,
      ipfs: !!(process.env.PINATA_API_KEY && process.env.PINATA_SECRET_KEY),
      fabric: process.env.FABRIC_ENABLED === 'true'
    },
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
      rss: Math.round(process.memoryUsage().rss / 1024 / 1024)
    }
  };

  // Return 503 Service Unavailable if MongoDB is not connected
  if (health.mongodb.status !== 'connected') {
    return res.status(503).json({ ...health, status: 'unhealthy' });
  }

  res.json(health);
});

// --- GET /api/document/:hash -------------------------------------------------
app.get('/api/document/:hash', async (req, res) => {
  try {
    const doc = await DocModel.findOne({ docHash: req.params.hash });
    if (!doc) return res.status(404).json({ error: 'No off-chain record found for this hash.' });
    res.json({
      fileName:    doc.fileName,
      aiScore:     doc.aiScore,
      aiProvider:  doc.aiProvider,
      aiDetails:   doc.aiDetails,
      isAuthentic: doc.isAuthentic,
      ipfsCid:     doc.ipfsCid,
      createdAt:   doc.createdAt
    });
  } catch (err) {
    logger.error('/api/document error:', err);
    res.status(500).json({ error: err.message });
  }
});

// --- Server startup ----------------------------------------------------------
// Guard prevents the port from being bound when Jest imports this module.
const PORT = process.env.PORT || 5000;
if (require.main === module) {
  app.listen(PORT, () => {
    const engine = process.env.AI_ENGINE || 'eden_ai';
    const hasKey = engine === 'eden_ai' ? !!process.env.AI_API_KEY : !!process.env.REALITY_DEFENDER_API_KEY;
    logger.info(`\nServer running on port ${PORT}`);
    logger.info(`  MongoDB   : ${process.env.MONGO_URI ? 'configured' : 'MISSING'}`);
    logger.info(`  AI Engine : ${engine} -- ${hasKey ? 'key loaded' : 'no key -- mock mode'}`);
    logger.info(`  Thresholds: image=${process.env.AI_THRESHOLD_IMAGE || '-'} video=${process.env.AI_THRESHOLD_VIDEO || '-'} text=${process.env.AI_THRESHOLD_TEXT || '-'} default=${process.env.AI_BLOCK_THRESHOLD || 80}`);
    logger.info(`  Pinata    : ${process.env.PINATA_API_KEY ? 'configured' : 'no key -- IPFS disabled'}\n`);
  });
}

// --- Enhanced Global Error Handler -------------------------------------------
// Ensures CORS headers are always present, even when Express catches an error
// (e.g. multer rejects an oversized file, rate limiter custom handler throws, etc.)
// Without this the browser sees a CORS error instead of the real status code.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  // Log error for debugging
  logger.error('Error occurred:', {
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });

  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV === 'development';
  const status = err.status || err.statusCode || 500;
  const errorResponse = {
    error: isDevelopment ? err.message : 'Internal server error',
    ...(isDevelopment && { stack: err.stack })
  };

  res.status(status).json(errorResponse);
});

// Export for integration tests (Jest imports this without triggering listen)
module.exports = app;

