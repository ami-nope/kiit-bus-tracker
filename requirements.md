# Campus Transport System — Requirements

## Purpose
Campus Transport System is a real-time campus transport coordination and tracking system. It provides continuous visibility of active transports, supports operational control for administrators, and enables timely travel decisions for students.

## Users
- Students
- Drivers
- Admin

## Functional Requirements

| ID | Description | Priority | Acceptance Criteria |
|---|---|---|---|
| FR-1 | Live bus tracking shall display active transport locations in near real time on student and admin views. | High | When a driver publishes valid location updates, corresponding transport markers and status are updated in connected clients within normal SSE/polling latency bounds. |
| FR-2 | Driver location publishing shall allow drivers to continuously send GPS coordinates for a selected transport. | High | Driver can start tracking, publish latitude/longitude updates repeatedly, and stop tracking; backend stores latest active state and reflects it to consumers. |
| FR-3 | SSE realtime updates shall push transport lifecycle events to connected clients. | High | Clients connected to event stream receive transport update/stop/clear events without manual refresh; system falls back to polling if stream is unavailable. |
| FR-4 | Route and stop management shall allow admins to create, update, and delete routes and stop metadata. | High | Route CRUD operations are persisted and reflected in driver/student/admin route views after reload. |
| FR-5 | Admin controls shall support fleet operations and configuration management. | High | Admin can view active fleet, stop vehicles, clear active fleet, and manage core configuration from dashboard interfaces. |
| FR-6 | ETA display shall provide route-aware arrival estimates to end users. | Medium | Driver/student views show ETA values during active trips and continue with graceful fallback behavior when routing inputs are limited. |
| FR-7 | Simulator mode shall support test traffic generation and route simulation. | Medium | Simulator can start/stop simulated transports and generated activity is visible through normal realtime tracking interfaces. |

## Future AI Requirements

| ID | Description | Priority | Acceptance Criteria |
|---|---|---|---|
| AI-1 | Route optimization using transport usage patterns. | Medium | System can ingest historical route usage and output route adjustment recommendations with measurable objective metrics (for example lower wait time or improved coverage). |
| AI-2 | Crowd prediction by day and time. | Medium | System can generate demand forecasts per route/stop/time window and expose predictions for planning views. |
| AI-3 | ETA prediction using historical movement data. | High | Predicted ETA quality improves over baseline rule-based ETA when evaluated against historical arrival outcomes. |
| AI-4 | Demand-based transport allocation suggestions. | Medium | System can recommend transport allocation across routes/time slots based on predicted demand and available fleet constraints. |

## Non-Functional Requirements

| ID | Category | Requirement | Target |
|---|---|---|---|
| NFR-1 | Performance | Realtime updates should remain responsive during normal campus operations. | End-to-end update propagation should remain low-latency for connected clients. |
| NFR-2 | Reliability | Stale transports must be removed automatically from active state. | Inactive/terminal transports are cleaned based on configured timeout logic. |
| NFR-3 | Availability | Core service must expose health status for hosting platforms. | Health endpoint returns service-ready response while process is healthy. |
| NFR-4 | Security | Admin operations must require authenticated access with role controls. | Protected endpoints reject unauthorized requests and enforce role-specific restrictions. |
| NFR-5 | Scalability | Architecture should preserve upgrade path from single-node to distributed design. | Design supports future migration to shared state and external datastore without changing user-facing workflows. |

## Assumptions and Constraints
- Current runtime uses single-server architecture with process-local realtime state.
- Driver updates depend on smartphone GPS quality and connectivity.
- Persistent state is stored in JSON files.
- SSE can be network/proxy sensitive; polling fallback remains mandatory.
- AI features are future extensions and must not degrade baseline realtime behavior.
