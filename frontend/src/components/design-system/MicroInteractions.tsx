import React, { useState, useEffect, useRef } from 'react';
import { Box, useTheme, alpha, keyframes } from '@mui/material';

// Animation keyframes
const fadeIn = keyframes`
  from {
    opacity: 0;
    transform: translateY(10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
`;

const slideIn = keyframes`
  from {
    transform: translateX(-100%);
  }
  to {
    transform: translateX(0);
  }
`;

const scaleIn = keyframes`
  from {
    transform: scale(0.8);
    opacity: 0;
  }
  to {
    transform: scale(1);
    opacity: 1;
  }
`;

const bounce = keyframes`
  0%, 20%, 53%, 80%, 100% {
    transform: translate3d(0, 0, 0);
  }
  40%, 43% {
    transform: translate3d(0, -8px, 0);
  }
  70% {
    transform: translate3d(0, -4px, 0);
  }
  90% {
    transform: translate3d(0, -2px, 0);
  }
`;

const ripple = keyframes`
  0% {
    transform: scale(0);
    opacity: 1;
  }
  100% {
    transform: scale(4);
    opacity: 0;
  }
`;

const shimmer = keyframes`
  0% {
    background-position: -200px 0;
  }
  100% {
    background-position: calc(200px + 100%) 0;
  }
`;

export interface MicroInteractionsProps {
  children: React.ReactNode;
  animation?: 'fadeIn' | 'slideIn' | 'scaleIn' | 'bounce' | 'ripple' | 'shimmer';
  duration?: number;
  delay?: number;
  trigger?: 'hover' | 'click' | 'focus' | 'mount' | 'scroll';
  className?: string;
  onAnimationComplete?: () => void;
}

const MicroInteractions: React.FC<MicroInteractionsProps> = ({
  children,
  animation = 'fadeIn',
  duration = 300,
  delay = 0,
  trigger = 'mount',
  className,
  onAnimationComplete,
}) => {
  const theme = useTheme();
  const [isAnimating, setIsAnimating] = useState(false);
  const [isVisible, setIsVisible] = useState(false);
  const elementRef = useRef<HTMLDivElement>(null);
  const observerRef = useRef<IntersectionObserver | null>(null);

  const getAnimationStyle = () => {
    const baseStyle = {
      animationDuration: `${duration}ms`,
      animationDelay: `${delay}ms`,
      animationFillMode: 'both' as const,
      animationTimingFunction: 'cubic-bezier(0.4, 0.0, 0.2, 1)',
    };

    switch (animation) {
      case 'fadeIn':
        return {
          ...baseStyle,
          animationName: fadeIn,
        };
      case 'slideIn':
        return {
          ...baseStyle,
          animationName: slideIn,
        };
      case 'scaleIn':
        return {
          ...baseStyle,
          animationName: scaleIn,
        };
      case 'bounce':
        return {
          ...baseStyle,
          animationName: bounce,
          animationDuration: '1000ms',
        };
      case 'shimmer':
        return {
          ...baseStyle,
          background: `linear-gradient(90deg, 
            ${alpha(theme.palette.primary.main, 0.1)} 25%, 
            ${alpha(theme.palette.primary.main, 0.2)} 50%, 
            ${alpha(theme.palette.primary.main, 0.1)} 75%)`,
          backgroundSize: '200px 100%',
          animationName: shimmer,
          animationDuration: '1500ms',
          animationIterationCount: 'infinite',
        };
      default:
        return {};
    }
  };

  const handleAnimationEnd = () => {
    setIsAnimating(false);
    onAnimationComplete?.();
  };

  const handleClick = () => {
    if (trigger === 'click') {
      setIsAnimating(true);
    }
  };

  const handleHover = () => {
    if (trigger === 'hover') {
      setIsAnimating(true);
    }
  };

  const handleFocus = () => {
    if (trigger === 'focus') {
      setIsAnimating(true);
    }
  };

  // Intersection Observer for scroll trigger
  useEffect(() => {
    if (trigger === 'scroll' && elementRef.current) {
      observerRef.current = new IntersectionObserver(
        ([entry]) => {
          if (entry.isIntersecting && !isVisible) {
            setIsVisible(true);
            setIsAnimating(true);
          }
        },
        {
          threshold: 0.1,
          rootMargin: '50px',
        }
      );

      observerRef.current.observe(elementRef.current);

      return () => {
        if (observerRef.current) {
          observerRef.current.disconnect();
        }
      };
    }
  }, [trigger, isVisible]);

  // Mount trigger
  useEffect(() => {
    if (trigger === 'mount') {
      setIsAnimating(true);
    }
  }, [trigger]);

  const animationStyle = isAnimating ? getAnimationStyle() : {};

  return (
    <Box
      ref={elementRef}
      className={className}
      onClick={handleClick}
      onMouseEnter={handleHover}
      onFocus={handleFocus}
      onAnimationEnd={handleAnimationEnd}
      sx={{
        ...animationStyle,
        ...(animation === 'ripple' &&
          isAnimating && {
            position: 'relative',
            overflow: 'hidden',
            '&::after': {
              content: '""',
              position: 'absolute',
              top: '50%',
              left: '50%',
              width: '20px',
              height: '20px',
              borderRadius: '50%',
              backgroundColor: alpha(theme.palette.primary.main, 0.3),
              transform: 'translate(-50%, -50%)',
              animation: `${ripple} ${duration}ms ease-out`,
            },
          }),
      }}
    >
      {children}
    </Box>
  );
};

/**
 * Higher-Order Component for animation wrapping
 * Wraps any component with MicroInteractions animation capabilities
 * Generic type P represents the props of the wrapped component
 */
// HOC for easy animation wrapping - wraps any component with animation capabilities
export const withAnimation = <P extends object>(
  WrappedComponent: React.ComponentType<P>,
  animationProps: Partial<MicroInteractionsProps> = {}
) => {
  return React.forwardRef<HTMLElement, P>((props, ref) => (
    <MicroInteractions {...animationProps}>
      <WrappedComponent {...props} ref={ref} />
    </MicroInteractions>
  ));
};

// Preset animations for common use cases
export const AnimatedCard = withAnimation(Box, { animation: 'scaleIn', trigger: 'hover' });
export const AnimatedButton = withAnimation(Box, { animation: 'bounce', trigger: 'click' });
export const AnimatedList = withAnimation(Box, { animation: 'fadeIn', trigger: 'scroll' });
export const AnimatedHeader = withAnimation(Box, { animation: 'slideIn', trigger: 'mount' });

export default MicroInteractions;
