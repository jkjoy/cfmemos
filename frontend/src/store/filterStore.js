import { create } from 'zustand';
import { persist } from 'zustand/middleware';

/**
 * Filter Store - Manages memo filtering state
 * Persists to localStorage for better UX
 */
export const useFilterStore = create(
  persist(
    (set, get) => ({
      // Filter state
      searchText: '',
      selectedTags: [],
      visibility: 'ALL', // 'ALL' | 'PUBLIC' | 'PRIVATE'
      dateRange: null, // { start: Date, end: Date } | null
      creatorId: null,

      // Actions
      setSearchText: (text) => set({ searchText: text }),

      setSelectedTags: (tags) => set({ selectedTags: tags }),

      toggleTag: (tag) => set((state) => {
        const exists = state.selectedTags.includes(tag);
        return {
          selectedTags: exists
            ? state.selectedTags.filter(t => t !== tag)
            : [...state.selectedTags, tag]
        };
      }),

      setVisibility: (visibility) => set({ visibility }),

      setDateRange: (range) => set({ dateRange: range }),

      setCreatorId: (creatorId) => set({ creatorId }),

      // Clear all filters
      clearFilters: () => set({
        searchText: '',
        selectedTags: [],
        visibility: 'ALL',
        dateRange: null,
        creatorId: null
      }),

      // Check if any filters are active
      hasActiveFilters: () => {
        const state = get();
        return Boolean(
          state.searchText ||
          state.selectedTags.length > 0 ||
          state.visibility !== 'ALL' ||
          state.dateRange ||
          state.creatorId
        );
      },

      // Get active filter count
      getActiveFilterCount: () => {
        const state = get();
        let count = 0;
        if (state.searchText) count++;
        if (state.selectedTags.length > 0) count++;
        if (state.visibility !== 'ALL') count++;
        if (state.dateRange) count++;
        if (state.creatorId) count++;
        return count;
      }
    }),
    {
      name: 'memo-filters', // localStorage key
      partialize: (state) => ({
        // Only persist these fields
        searchText: state.searchText,
        selectedTags: state.selectedTags,
        visibility: state.visibility
        // dateRange and creatorId are session-only
      })
    }
  )
);
