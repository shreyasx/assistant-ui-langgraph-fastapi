"use client";

import { useAssistantInstructions } from "@assistant-ui/react";

export function MyAssistant() {
	// Set up the assistant instructions
	useAssistantInstructions(
		"You are a helpful AI assistant. You can help with various tasks and answer questions."
	);

	return (
		<div className="h-full flex flex-col">
			<div className="flex-1 p-4">
				<h1 className="text-2xl font-bold mb-4">AI Assistant</h1>
				<p className="text-gray-600">
					Welcome! I&apos;m here to help you with various tasks. You can ask me
					questions or request assistance with different tools.
				</p>
			</div>
		</div>
	);
}
