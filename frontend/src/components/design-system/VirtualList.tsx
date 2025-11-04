import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { Box, useTheme, alpha } from '@mui/material';

export interface VirtualListProps<T> {
  items: T[];
  height: number;
  itemHeight: number;
  renderItem: (item: T, index: number) => React.ReactNode;
  overscan?: number;
  className?: string;
  onScroll?: (scrollTop: number) => void;
  onVisibleRangeChange?: (startIndex: number, endIndex: number) => void;
}

const VirtualList = <T extends any>({
  items,
  height,
  itemHeight,
  renderItem,
  overscan = 5,
  className,
  onScroll,
  onVisibleRangeChange,
}: VirtualListProps<T>) => {
  const theme = useTheme();
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);

  // Calculate visible range
  const visibleRange = useMemo(() => {
    const startIndex = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan);
    const endIndex = Math.min(
      items.length - 1,
      Math.ceil((scrollTop + height) / itemHeight) + overscan
    );
    return { startIndex, endIndex };
  }, [scrollTop, height, itemHeight, overscan, items.length]);

  // Calculate total height and transform
  const totalHeight = items.length * itemHeight;
  const transform = `translateY(${visibleRange.startIndex * itemHeight}px)`;

  // Handle scroll events
  const handleScroll = useCallback(
    (event: React.UIEvent<HTMLDivElement>) => {
      const newScrollTop = event.currentTarget.scrollTop;
      setScrollTop(newScrollTop);
      onScroll?.(newScrollTop);
    },
    [onScroll]
  );

  // Notify visible range changes
  useEffect(() => {
    onVisibleRangeChange?.(visibleRange.startIndex, visibleRange.endIndex);
  }, [visibleRange.startIndex, visibleRange.endIndex, onVisibleRangeChange]);

  // Get visible items
  const visibleItems = useMemo(() => {
    return items.slice(visibleRange.startIndex, visibleRange.endIndex + 1);
  }, [items, visibleRange.startIndex, visibleRange.endIndex]);

  // Scroll to specific item
  const scrollToItem = useCallback(
    (index: number, behavior: 'auto' | 'smooth' = 'smooth') => {
      if (containerRef.current) {
        const scrollTop = index * itemHeight;
        containerRef.current.scrollTo({
          top: scrollTop,
          behavior,
        });
      }
    },
    [itemHeight]
  );

  // Scroll to top
  const scrollToTop = useCallback(() => {
    scrollToItem(0);
  }, [scrollToItem]);

  // Scroll to bottom
  const scrollToBottom = useCallback(() => {
    scrollToItem(items.length - 1);
  }, [scrollToItem, items.length]);

  // Get item index at current scroll position
  const getItemIndexAtPosition = useCallback(
    (scrollTop: number) => {
      return Math.floor(scrollTop / itemHeight);
    },
    [itemHeight]
  );

  // Check if item is visible
  const isItemVisible = useCallback(
    (index: number) => {
      return index >= visibleRange.startIndex && index <= visibleRange.endIndex;
    },
    [visibleRange.startIndex, visibleRange.endIndex]
  );

  return (
    <Box
      ref={containerRef}
      className={className}
      sx={{
        height,
        overflow: 'auto',
        position: 'relative',
        backgroundColor: theme.palette.background.paper,
        border: `1px solid ${alpha(theme.palette.divider, 0.2)}`,
        borderRadius: theme.shape.borderRadius,
        '&::-webkit-scrollbar': {
          width: '8px',
        },
        '&::-webkit-scrollbar-track': {
          backgroundColor: alpha(theme.palette.divider, 0.1),
          borderRadius: '4px',
        },
        '&::-webkit-scrollbar-thumb': {
          backgroundColor: alpha(theme.palette.primary.main, 0.3),
          borderRadius: '4px',
          '&:hover': {
            backgroundColor: alpha(theme.palette.primary.main, 0.5),
          },
        },
      }}
      onScroll={handleScroll}
    >
      {/* Total height container */}
      <Box sx={{ height: totalHeight, position: 'relative' }}>
        {/* Visible items container */}
        <Box
          sx={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            transform,
            willChange: 'transform',
          }}
        >
          {visibleItems.map((item, index) => {
            const actualIndex = visibleRange.startIndex + index;
            return (
              <Box
                key={actualIndex}
                sx={{
                  height: itemHeight,
                  display: 'flex',
                  alignItems: 'center',
                  padding: theme.spacing(0, 2),
                  borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                  '&:last-child': {
                    borderBottom: 'none',
                  },
                  '&:hover': {
                    backgroundColor: alpha(theme.palette.action.hover, 0.04),
                  },
                }}
              >
                {renderItem(item, actualIndex)}
              </Box>
            );
          })}
        </Box>
      </Box>
    </Box>
  );
};

// Enhanced VirtualList with additional features
export interface EnhancedVirtualListProps<T> extends VirtualListProps<T> {
  showScrollbar?: boolean;
  enableSmoothScrolling?: boolean;
  onItemClick?: (item: T, index: number) => void;
  selectedIndex?: number;
  highlightSelected?: boolean;
}

export const EnhancedVirtualList = <T extends any>({
  showScrollbar = true,
  enableSmoothScrolling = true,
  onItemClick,
  selectedIndex,
  highlightSelected = true,
  ...props
}: EnhancedVirtualListProps<T>) => {
  const theme = useTheme();

  const enhancedRenderItem = useCallback(
    (item: T, index: number) => {
      const isSelected = selectedIndex === index;

      return (
        <Box
          onClick={() => onItemClick?.(item, index)}
          sx={{
            width: '100%',
            cursor: onItemClick ? 'pointer' : 'default',
            backgroundColor:
              isSelected && highlightSelected
                ? alpha(theme.palette.primary.main, 0.1)
                : 'transparent',
            borderLeft:
              isSelected && highlightSelected
                ? `4px solid ${theme.palette.primary.main}`
                : '4px solid transparent',
            paddingLeft: theme.spacing(2),
            transition: 'all 0.2s ease',
            '&:hover': {
              backgroundColor: alpha(theme.palette.action.hover, 0.04),
            },
          }}
        >
          {props.renderItem(item, index)}
        </Box>
      );
    },
    [props.renderItem, onItemClick, selectedIndex, highlightSelected, theme]
  );

  return <VirtualList {...props} renderItem={enhancedRenderItem} className={props.className} />;
};

// Specialized virtual list for common use cases
export const VirtualTable = <T extends any>({
  items,
  height,
  itemHeight,
  columns,
  renderCell,
  ...props
}: {
  items: T[];
  height: number;
  itemHeight: number;
  columns: Array<{ key: string; label: string; width?: number | string }>;
  renderCell: (item: T, columnKey: string, index: number) => React.ReactNode;
} & Omit<VirtualListProps<T>, 'renderItem'>) => {
  const theme = useTheme();

  const renderTableRow = useCallback(
    (item: T, index: number) => (
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          height: '100%',
          borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          '&:last-child': {
            borderBottom: 'none',
          },
        }}
      >
        {columns.map((column) => (
          <Box
            key={column.key}
            sx={{
              flex: column.width ? 'none' : 1,
              width: column.width,
              padding: theme.spacing(0, 1),
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'flex-start',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {renderCell(item, column.key, index)}
          </Box>
        ))}
      </Box>
    ),
    [columns, renderCell, theme]
  );

  return (
    <Box>
      {/* Table Header */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          height: itemHeight,
          backgroundColor: theme.palette.background.default,
          borderBottom: `2px solid ${theme.palette.divider}`,
          fontWeight: 'bold',
          fontSize: '0.875rem',
        }}
      >
        {columns.map((column) => (
          <Box
            key={column.key}
            sx={{
              flex: column.width ? 'none' : 1,
              width: column.width,
              padding: theme.spacing(0, 1),
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'flex-start',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {column.label}
          </Box>
        ))}
      </Box>

      {/* Virtual Table Body */}
      <VirtualList
        items={items}
        height={height - itemHeight}
        itemHeight={itemHeight}
        renderItem={renderTableRow}
        {...props}
      />
    </Box>
  );
};

export default VirtualList;
