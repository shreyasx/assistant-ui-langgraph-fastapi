import {
	ThreadListPrimitive,
	ThreadListItemPrimitive,
} from "@assistant-ui/react";

export function ThreadList() {
	return (
		<aside className="border-r h-full flex flex-col w-64">
			<ThreadListPrimitive.Root className="flex-1 overflow-y-auto">
				<ThreadListPrimitive.New className="btn-primary m-2">
					New Chat
				</ThreadListPrimitive.New>
				<ThreadListPrimitive.Items
					components={{
						ThreadListItem: ({ ...rest }) => (
							<ThreadListItemPrimitive.Root
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
