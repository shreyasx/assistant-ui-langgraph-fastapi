"use client";

import { ReactNode } from "react";
import { AssistantRuntimeProvider } from "@assistant-ui/react";
import { useChatRuntime } from "@assistant-ui/react-ai-sdk";

export function MyRuntimeProvider({ children }: { children: ReactNode }) {
	const runtime = useChatRuntime({
		api: "/api/chat",
	});

	return (
		<AssistantRuntimeProvider runtime={runtime}>
			{children}
		</AssistantRuntimeProvider>
	);
}
