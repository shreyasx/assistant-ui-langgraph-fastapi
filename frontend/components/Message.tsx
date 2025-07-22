
import {
MessagePrimitive,
ActionBarPrimitive,
BranchPickerPrimitive,
ErrorPrimitive,
} from '@assistant-ui/react';

export function Message(props: React.ComponentProps<typeof MessagePrimitive.Root>) {
return (
<MessagePrimitive.Root {...props} className="group relative">
<MessagePrimitive.Parts />

      {/* Branch navigation (for regenerated answers) */}
      <BranchPickerPrimitive.Root hideWhenSingleBranch className="mt-2" />

      {/* Hover action bar */}
      <ActionBarPrimitive.Root autohide="always" hideWhenRunning className="absolute -left-8 top-2 hidden group-hover:block">
        <ActionBarPrimitive.Edit />
        <ActionBarPrimitive.Reload />
        <ActionBarPrimitive.Copy />
      </ActionBarPrimitive.Root>

      {/* Error display */}
      <MessagePrimitive.Error>
        <ErrorPrimitive.Root />
      </MessagePrimitive.Error>
    </MessagePrimitive.Root>

);
}
