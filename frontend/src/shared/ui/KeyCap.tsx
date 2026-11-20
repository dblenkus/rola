interface KeyCapProps {
  // The key as printed on the keyboard: "0", "1–9", "←", "Backspace".
  children: string;
  // The 32 px cap, as in "0 = 10".
  large?: boolean;
}

// A keyboard key the judge can press. Name the action in the words beside
// it; put the shortcut itself on the control with aria-keyshortcuts.
export default function KeyCap({ children, large }: KeyCapProps) {
  return (
    <kbd className={large ? 'rl-keycap rl-keycap--large' : 'rl-keycap'}>
      {children}
    </kbd>
  );
}
