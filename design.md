# Campus Transport System — Design Document

## System Overview
Campus Transport System is a realtime transport tracking system with an AI-ready architecture. The current platform uses a Flask backend, SSE live updates, in-memory transport state, and JSON persistence to support student visibility, driver location publishing, and admin fleet/route operations.

## Architecture Layers

### Frontend Layer
- Browser-based role views for students, drivers, admin, and simulator operations.
- Map-centric UI with realtime transport markers, route context, and ETA presentation.
- SSE subscription with polling fallback for resilience.

### Backend Flask Server
- Serves templates and API endpoints.
- Processes driver updates, admin commands, and route management actions.
- Orchestrates realtime broadcast events and request-level validation.

### Realtime State Layer
- Maintains active transport state in memory for low-latency reads/writes.
- Maintains subscriber registry for SSE fanout.
- Tracks transport lifecycle details (active, updated, stopped, cleaned up).

### Persistence Layer
- JSON files store durable system data:
  - active transport snapshots,
  - route/location definitions,
  - credentials/settings,
  - admin audit history.
- Runtime periodically syncs in-memory changes to durable files.

## Realtime Flow
Driver -> API -> memory -> SSE -> student UI

1. Driver publishes GPS update to backend API.
2. Backend validates update and writes latest transport state in memory.
3. Backend emits SSE event for connected consumers.
4. Student/admin clients receive push event and update UI.
5. If SSE is unavailable, clients use periodic polling to keep state current.

## AI Integration Design (Future)
AI capabilities are designed as add-on modules that consume persisted and streamed operational signals without blocking the primary realtime path.

### AI Analytics Module
Responsibilities:
- Consumes transport history.
- Reads route usage patterns.
- Processes student demand signals.

Output:
- Normalized analytics features and model-ready datasets for downstream AI engines.

### Route Optimization Engine
Responsibilities:
- Uses usage patterns and service outcomes to propose route adjustments.
- Produces recommendations such as stop sequence improvements, frequency tuning, and route balancing.

### Crowd Prediction Model
Responsibilities:
- Predicts daily passenger density using historical demand by route, stop, day, and time.
- Supports operational planning and pre-peak allocation decisions.

### ETA Prediction Model
Responsibilities:
- Improves ETA quality using historical movement and route segment travel-time patterns.
- Provides model-driven ETA inference that can augment or replace baseline heuristic estimates.

### Execution Principle
AI modules operate asynchronously and do not block realtime tracking. Realtime publishing, SSE fanout, and active transport lifecycle processing remain on the critical low-latency path, while AI workloads execute out-of-band.

## Data Required for AI
- Transport history
- Route usage logs
- Stop arrival timestamps
- Driver shift logs
- Student demand signals

## Scaling Considerations
The AI module can run as:
- background service
- scheduled batch job
- separate inference service

Recommended evolution path:
1. Keep realtime core lightweight and isolated.
2. Move heavy AI computation to asynchronous workers/services.
3. Introduce shared datastore/message infrastructure as AI and fleet scale increases.
4. Expose AI outputs through versioned APIs so UI can consume recommendations safely.
