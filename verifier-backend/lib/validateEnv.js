const requiredEnvVars = [
  'MONGO_URI',
  'JWT_SECRET',
  'ADMIN_PASSWORD'
];

const validateEnvironment = () => {
  const missing = requiredEnvVars.filter(envVar => !process.env[envVar]);

  if (missing.length > 0) {
    console.error('❌ Missing required environment variables:');
    missing.forEach(envVar => console.error(`   - ${envVar}`));
    console.error('   Please check your .env file and try again.');
    process.exit(1);
  }

  // Validate JWT_SECRET strength
  if (process.env.JWT_SECRET.length < 32) {
    console.error('❌ JWT_SECRET must be at least 32 characters long');
    process.exit(1);
  }

  // Validate CORS_ORIGINS in production
  if (process.env.NODE_ENV === 'production' &&
      process.env.CORS_ORIGINS?.includes('*')) {
    console.error('❌ Wildcard CORS origins not allowed in production');
    process.exit(1);
  }

  console.log('✅ Environment validation passed');
};

module.exports = { validateEnvironment };