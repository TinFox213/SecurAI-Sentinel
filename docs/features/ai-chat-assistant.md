# AI Chat Assistant

## Purpose

AI Chat Assistant is a global floating assistant intended to answer questions about the latest analysis context.

## Source Files

- `src/components/common/AiChatOverlay.tsx`
- `App.tsx`

## What It Does Today

- Displays a floating chat button.
- Opens a chat panel with suggested security questions.
- If a current analysis exists, starts with context such as threat level and risk score.
- Sends the user's message and analysis context to `POST /api/chat`.
- Shows assistant responses or a generic error message.

## Data and API Dependencies

- Current in-memory `SecurityAnalysis` from `App.tsx`
- Intended backend: `/api/chat`

## Limitations

- The backend currently does not define `/api/chat`, so the assistant will fail unless that endpoint is added.
- Chat history is in component state only and is not persisted.

## Real-Tool Upgrade Path

Implement `/api/chat` as retrieval over current analysis, scan history, findings, docs, and tool artifacts. Keep tool execution out of chat until explicit user confirmation is added.

