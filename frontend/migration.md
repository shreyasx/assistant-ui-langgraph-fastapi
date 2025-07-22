Scope — Backend is already running and streaming. We only touch the frontend/ folder: connect @assistant-ui/react primitives to deliver threads, live streaming, branching, attachments, and thread‑list navigation on Next.js 15 (TypeScript). Remember: backend is stateless – every request carries the entire messages[].

0.5 · Backend URL & Proxy Strategy 🚦

Choose one pattern and use it consistently:

Strategy

When to use

What the runtime fetches

Same‑origin

Nginx (or Vercel Rewrite) proxies /api/chat → FastAPI.

'/api/chat' (no CORS)

Cross‑origin

FastAPI on another host/port (keep secrets server‑side).

'/api/assistant' (Next.js proxy)

0.5.1 Cross‑origin streaming proxy

app/api/assistant/route.ts:

import { NextRequest } from 'next/server';
export const runtime = 'nodejs'; // keep stream intact

export async function POST(req: NextRequest) {
const body = await req.text();
const resp = await fetch(`${process.env.BACKEND_URL}/chat`, {
method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
});
return new Response(resp.body, {
status: resp.status,
headers: {
'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive',
},
});
}

Set BACKEND*URL=https://api.mydomain.com (server‑only). No NEXT_PUBLIC* needed here.

1 · Runtime Adapter (Stateless)

app/lib/runtime.tsx:

'use client';
import { AssistantRuntimeProvider, useLocalRuntime } from '@assistant-ui/react';
import type { ChatModelAdapter } from '@assistant-ui/react';

const ENDPOINT = process.env.NEXT_PUBLIC_BACKEND_URL
? `${process.env.NEXT_PUBLIC_BACKEND_URL}/chat` // direct hit
: '/api/assistant'; // Next.js proxy

const FastAPIAdapter: ChatModelAdapter = {
async \*run({ messages, abortSignal }) {
const res = await fetch(ENDPOINT, {
method: 'POST', headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({ messages }), signal: abortSignal,
});
const decoder = new TextDecoder();
for await (const chunk of res.body!) {
yield { content: [{ type: 'text', text: decoder.decode(chunk) }] };
}
},
};

export function AssistantProvider({ children }: { children: React.ReactNode }) {
const runtime = useLocalRuntime(FastAPIAdapter); // threads in memory / localStorage history
return <AssistantRuntimeProvider runtime={runtime}>{children}</AssistantRuntimeProvider>;
}

2 · Global Provider Hook‑Up

app/layout.tsx:

import { AssistantProvider } from '@/app/lib/runtime';

export default function RootLayout({ children }: { children: React.ReactNode }) {
return (
<AssistantProvider>
<html lang="en">
<body className="h-screen w-screen overflow-hidden bg-background text-foreground">
{children}
</body>
</html>
</AssistantProvider>
);
}

3 · Chat Shell (Thread + Composer)

components/ChatShell.tsx:

import { ThreadPrimitive, ComposerPrimitive } from '@assistant-ui/react';
import { ThreadList } from './ThreadList';
import { Message } from './Message';

export function ChatShell() {
return (
<div className="grid h-full grid-cols-[260px_1fr]">
<ThreadList />

      <ThreadPrimitive.Root className="flex flex-col overflow-hidden">
        <ThreadPrimitive.Viewport autoScroll className="flex-1 overflow-y-auto p-4" />
        <ThreadPrimitive.Messages
          components={{ AssistantMessage: Message, UserMessage: Message }}
        />
        <ThreadPrimitive.Empty>No messages yet…</ThreadPrimitive.Empty>
        <ThreadPrimitive.ScrollToBottom />

        <ComposerPrimitive.Root className="border-t p-4 flex gap-2">
          <ComposerPrimitive.Attachments />
          <ComposerPrimitive.Input
            placeholder="Ask anything…"
            className="flex-1 resize-none"
            rows={1}
          />
          <ComposerPrimitive.Send asChild>
            <button className="btn-primary">Send</button>
          </ComposerPrimitive.Send>
        </ComposerPrimitive.Root>
      </ThreadPrimitive.Root>
    </div>

);
}

4 · Thread List Sidebar

components/ThreadList.tsx:

import { ThreadListPrimitive, ThreadListItemPrimitive } from '@assistant-ui/react';

export function ThreadList() {
return (
<aside className="border-r h-full flex flex-col w-64">
<ThreadListPrimitive.Root className="flex-1 overflow-y-auto">
<ThreadListPrimitive.New className="btn-primary m-2">New Chat</ThreadListPrimitive.New>
<ThreadListPrimitive.Items
components={{
            Item: ({ threadId, ...rest }) => (
              <ThreadListItemPrimitive.Root
                threadId={threadId}
                {...rest}
                className="px-3 py-2 hover:bg-muted"
              />
            ),
          }}
/>
</ThreadListPrimitive.Root>
</aside>
);
}

5 · Message Component (Branches + Action Bar)

components/Message.tsx:

import {
MessagePrimitive,
ActionBarPrimitive,
BranchPickerPrimitive,
ErrorPrimitive,
} from '@assistant-ui/react';

export function Message(props: MessagePrimitive.RootProps) {
return (
<MessagePrimitive.Root {...props} className="group relative">
<MessagePrimitive.Parts />

      {/* Branch navigation (for regenerated answers) */}
      <BranchPickerPrimitive.Root hideWhenSingleBranch className="mt-2" />

      {/* Hover action bar */}
      <ActionBarPrimitive.Root autohide hideWhenRunning className="absolute -left-8 top-2 hidden group-hover:block">
        <ActionBarPrimitive.Edit />
        <ActionBarPrimitive.Reload />
        <ActionBarPrimitive.Copy />
      </ActionBarPrimitive.Root>

      {/* Error display */}
      <MessagePrimitive.Error>
        <ErrorPrimitive />
      </MessagePrimitive.Error>
    </MessagePrimitive.Root>

);
}

6 · Streaming, Cancellation & Indicators

Concern

Implementation

Live tokens

Each SSE chunk becomes yield in FastAPIAdapter; React re‑renders the in‑progress assistant message.

Abort

<ComposerPrimitive.Cancel> connects to abortSignal → controller.abort() → FastAPI closes stream.

Typing indicator

Wrap UI with <ThreadPrimitive.If running> or use <MessagePrimitive.Running> component for spinner.

Scroll lock

The built‑in autoScroll prop keeps view at bottom unless user scrolls up.
