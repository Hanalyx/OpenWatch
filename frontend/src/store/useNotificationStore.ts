import { create } from 'zustand';

// useNotificationStore — the in-app notification bell's state.
//
// MVP scope (deliberately small, honest): a SESSION-SCOPED unread counter
// for "report ready" events. useLiveEvents bumps it when a report.ready
// SSE event arrives (the first, and currently only, producer); the TopBar
// bell renders the count as a badge and clears it when the operator opens
// Reports. There is no server-side notification feed, no per-item read
// state, and no cross-session persistence yet — a refresh resets the
// counter. A richer feed (a dropdown list, multiple event types, durable
// per-user notifications) is a deferred follow-on, not faked here.

interface NotificationState {
  /** Count of report.ready events received this session and not yet seen. */
  unreadReports: number;
  /** Increment the unread counter (one report finished rendering). */
  bumpReportReady: () => void;
  /** Clear the unread counter (the operator opened Reports). */
  clearReports: () => void;
}

export const useNotificationStore = create<NotificationState>((set) => ({
  unreadReports: 0,
  bumpReportReady: () => set((s) => ({ unreadReports: s.unreadReports + 1 })),
  clearReports: () => set({ unreadReports: 0 }),
}));
