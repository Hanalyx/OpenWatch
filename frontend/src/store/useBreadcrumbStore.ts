import { create } from 'zustand';

// Breadcrumb store — pages set their crumbs in a useEffect; TopBar
// reads them and renders them in the sticky header bar.

export interface Crumb {
  label: string;
  href?: string;
}

interface BreadcrumbStore {
  crumbs: Crumb[];
  setCrumbs: (crumbs: Crumb[]) => void;
}

export const useBreadcrumbStore = create<BreadcrumbStore>((set) => ({
  crumbs: [],
  setCrumbs: (crumbs) => set({ crumbs }),
}));
