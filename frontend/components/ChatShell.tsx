
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
          <ComposerPrimitive.Attachments components={{}} />
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
