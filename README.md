# DocVerify - Blockchain Document Authenticity System

AI-powered document verification with blockchain anchoring on Ethereum.

## Features

- 📄 Document upload and hash-based verification
- 🤖 AI deepfake detection (Eden AI / Reality Defender)
- ⛓️ Ethereum Sepolia blockchain anchoring
- 🔒 Immutable verification records
- 🚀 Production-ready with Railway/Render deployment

## Architecture

- **Frontend**: React + ethers.js
- **Backend**: Node.js + Express + MongoDB
- **Blockchain**: Ethereum Sepolia testnet
- **AI**: Eden AI / Reality Defender (optional)

## Quick Start

### Local Development

1. Clone repository
2. Install dependencies:
   ```bash
   cd verifier-backend && npm install
   cd ../verifier-client && npm install
   ```
3. Configure environment (copy `.env.example` to `.env`)
4. Start MongoDB locally or use Atlas
5. Run backend: `npm run dev` (in verifier-backend)
6. Run frontend: `npm start` (in verifier-client)

### Docker (Local Testing)

```bash
cp .env.example .env
# Edit .env with your values
docker-compose up
```

Access at http://localhost:3000

## Deployment

See comprehensive guides in `/docs`:

- **[Railway Deployment](docs/RAILWAY_DEPLOY.md)** (Recommended)
- **[Render Deployment](docs/RENDER_DEPLOY.md)**
- **[MongoDB Atlas Setup](docs/MONGODB_ATLAS_SETUP.md)**
- **[Environment Variables](docs/ENVIRONMENT_VARIABLES.md)**

**Quick Deploy to Railway**:
1. Set up MongoDB Atlas
2. Connect GitHub repo to Railway
3. Configure environment variables
4. Deploy backend and frontend services
5. Update CORS origins

Full guide: [docs/RAILWAY_DEPLOY.md](docs/RAILWAY_DEPLOY.md)

## Smart Contract

Deployed on Ethereum Sepolia:
```
Address: 0x83ed6653dB8c25Bacebf6B3110e352bfE6F9196c
Network: Sepolia Testnet
Explorer: https://sepolia.etherscan.io/address/0x83ed6653dB8c25Bacebf6B3110e352bfE6F9196c
```

## Project Structure

```
├── verifier-backend/     # Express API server
├── verifier-client/      # React frontend
├── hardhat/              # Smart contracts
├── fabric/               # Hyperledger Fabric (optional)
├── nginx/                # Production nginx config
└── docs/                 # Deployment documentation
```

## Environment Variables

See [docs/ENVIRONMENT_VARIABLES.md](docs/ENVIRONMENT_VARIABLES.md) for complete reference.

**Minimum required**:
- Backend: `MONGO_URI`, `JWT_SECRET`, `ADMIN_PASSWORD`, `CORS_ORIGINS`
- Frontend: `REACT_APP_API_URL`, `REACT_APP_CONTRACT_ADDRESS`

## API Endpoints

- `POST /api/analyze` - Upload and verify document
- `GET /api/document/:hash` - Get document info
- `POST /api/auth/login` - Admin login
- `GET /api/health` - Health check

## Security

- Rate limiting (20 AI requests / 15 min)
- JWT authentication for admin routes
- CORS protection
- Input validation
- MongoDB security

## License

MIT

## Support

For deployment issues, see troubleshooting sections in deployment guides.
