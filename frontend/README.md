# OpenWatch Frontend

React TypeScript single-page application for the OpenWatch SCAP compliance scanner interface.

## Directory Structure

```
frontend/
├── src/
│   ├── components/     # Reusable UI components
│   ├── pages/          # Page-level components
│   ├── services/       # API client services
│   ├── store/          # Redux state management
│   ├── hooks/          # Custom React hooks
│   ├── contexts/       # React contexts
│   ├── utils/          # Utility functions
│   ├── App.tsx         # Main application component
│   └── index.tsx       # Application entry point
├── public/             # Static assets
├── build/              # Production build output
├── package.json        # NPM dependencies
├── vite.config.ts      # Vite configuration
└── tsconfig.json       # TypeScript configuration
```

## Key Components

### Pages
- **Dashboard**: Overview with compliance metrics and alerts
- **Hosts**: Host inventory management and SSH credentials
- **Scans**: SCAP scan execution and results viewing
- **Content**: SCAP content upload and management
- **Users**: User and role management
- **Settings**: System configuration

### Component Library
- **design-system/**: Material-UI based components
  - StatCard, StatusChip, ComplianceRing
  - Consistent theming and styling
- **common/**: Shared components
  - PrivateRoute, PublicRoute
- **dashboard/**: Dashboard-specific widgets
- **remediation/**: AEGIS integration panel

### State Management
Redux Toolkit slices:
- **authSlice**: Authentication state
- **hostSlice**: Host inventory
- **scanSlice**: Scan management
- **resultSlice**: Scan results
- **notificationSlice**: UI notifications

## Development

### Setup
```bash
# Install dependencies
npm install

# Run development server (port 3001)
npm run dev

# Build for production
npm run build

# Run linting
npm run lint
npm run lint:fix
```

### Environment Variables
- `VITE_API_URL`: Backend API URL (defaults to proxy)

### Key Features

- **Material-UI Components**: Consistent, responsive design
- **Real-time Updates**: WebSocket integration for live scan progress
- **Dark Mode**: Theme switching support
- **Role-Based UI**: Components adapt to user permissions
- **CSV Import**: Bulk host import with field mapping
- **SSH Terminal**: Web-based terminal for host access

## API Integration

The frontend communicates with the backend via:
- RESTful API calls using authenticated fetch
- WebSocket connections for real-time updates
- JWT tokens stored in localStorage as 'auth_token'

### API Proxy
Development mode proxies `/api` requests to `http://localhost:8000`

## Build Configuration

- **Vite**: Fast build tool with HMR
- **TypeScript**: Type-safe development
- **Code Splitting**: Optimized bundles:
  - vendor (React, React-DOM)
  - mui (Material-UI)
  - redux (State management)
  - main (Application code)

## Testing

```bash
# Run tests (when available)
npm test

# Run tests in watch mode
npm test -- --watch
```

## Production Deployment

The production build is served by Nginx in Docker with:
- HTTPS enforcement
- Security headers
- Gzip compression
- Cache optimization

---
*Last updated: 2025-01-12*