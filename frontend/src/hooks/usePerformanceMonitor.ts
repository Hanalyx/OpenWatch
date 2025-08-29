import { useState, useEffect, useRef, useCallback } from 'react';

export interface PerformanceMetrics {
  renderTime: number;
  interactionTime: number;
  frameRate: number;
  memoryUsage: number;
  timestamp: number;
}

export interface PerformanceThresholds {
  renderTime: number;
  interactionTime: number;
  frameRate: number;
  memoryUsage: number;
}

export interface PerformanceMonitorOptions {
  enabled?: boolean;
  sampleRate?: number;
  thresholds?: Partial<PerformanceThresholds>;
  onThresholdExceeded?: (metric: keyof PerformanceMetrics, value: number, threshold: number) => void;
  onMetricsUpdate?: (metrics: PerformanceMetrics) => void;
}

const DEFAULT_THRESHOLDS: PerformanceThresholds = {
  renderTime: 16, // 16ms = 60fps
  interactionTime: 100, // 100ms for good UX
  frameRate: 30, // Minimum acceptable frame rate
  memoryUsage: 50 * 1024 * 1024, // 50MB
};

const DEFAULT_SAMPLE_RATE = 1000; // 1 second

export const usePerformanceMonitor = (options: PerformanceMonitorOptions = {}) => {
  const {
    enabled = true,
    sampleRate = DEFAULT_SAMPLE_RATE,
    thresholds = DEFAULT_THRESHOLDS,
    onThresholdExceeded,
    onMetricsUpdate,
  } = options;

  const [metrics, setMetrics] = useState<PerformanceMetrics>({
    renderTime: 0,
    interactionTime: 0,
    frameRate: 0,
    memoryUsage: 0,
    timestamp: Date.now(),
  });

  const [isMonitoring, setIsMonitoring] = useState(false);
  const frameCountRef = useRef(0);
  const lastFrameTimeRef = useRef(performance.now());
  const renderStartTimeRef = useRef(0);
  const interactionStartTimeRef = useRef(0);
  const frameRateIntervalRef = useRef<NodeJS.Timeout>();
  const memoryIntervalRef = useRef<NodeJS.Timeout>();

  // Measure render time
  const startRenderMeasure = useCallback(() => {
    if (!enabled) return;
    renderStartTimeRef.current = performance.now();
  }, [enabled]);

  const endRenderMeasure = useCallback(() => {
    if (!enabled || renderStartTimeRef.current === 0) return;
    
    const renderTime = performance.now() - renderStartTimeRef.current;
    renderStartTimeRef.current = 0;
    
    setMetrics(prev => ({
      ...prev,
      renderTime,
      timestamp: Date.now(),
    }));

    // Check threshold
    if (thresholds.renderTime && renderTime > thresholds.renderTime) {
      onThresholdExceeded?.('renderTime', renderTime, thresholds.renderTime);
    }
  }, [enabled, thresholds.renderTime, onThresholdExceeded]);

  // Measure interaction time
  const startInteractionMeasure = useCallback(() => {
    if (!enabled) return;
    interactionStartTimeRef.current = performance.now();
  }, [enabled]);

  const endInteractionMeasure = useCallback(() => {
    if (!enabled || interactionStartTimeRef.current === 0) return;
    
    const interactionTime = performance.now() - interactionStartTimeRef.current;
    interactionStartTimeRef.current = 0;
    
    setMetrics(prev => ({
      ...prev,
      interactionTime,
      timestamp: Date.now(),
    }));

    // Check threshold
    if (thresholds.interactionTime && interactionTime > thresholds.interactionTime) {
      onThresholdExceeded?.('interactionTime', interactionTime, thresholds.interactionTime);
    }
  }, [enabled, thresholds.interactionTime, onThresholdExceeded]);

  // Measure frame rate
  const measureFrameRate = useCallback(() => {
    if (!enabled) return;
    
    const currentTime = performance.now();
    const deltaTime = currentTime - lastFrameTimeRef.current;
    
    if (deltaTime > 0) {
      frameCountRef.current++;
      
      if (deltaTime >= 1000) { // Calculate FPS every second
        const frameRate = Math.round((frameCountRef.current * 1000) / deltaTime);
        
        setMetrics(prev => ({
          ...prev,
          frameRate,
          timestamp: Date.now(),
        }));

        // Check threshold
        if (thresholds.frameRate && frameRate < thresholds.frameRate) {
          onThresholdExceeded?.('frameRate', frameRate, thresholds.frameRate);
        }

        frameCountRef.current = 0;
        lastFrameTimeRef.current = currentTime;
      }
    }
  }, [enabled, thresholds.frameRate, onThresholdExceeded]);

  // Measure memory usage
  const measureMemoryUsage = useCallback(() => {
    if (!enabled) return;
    
    if ('memory' in performance) {
      const memory = (performance as any).memory;
      const memoryUsage = memory.usedJSHeapSize;
      
      setMetrics(prev => ({
        ...prev,
        memoryUsage,
        timestamp: Date.now(),
      }));

      // Check threshold
      if (thresholds.memoryUsage && memoryUsage > thresholds.memoryUsage) {
        onThresholdExceeded?.('memoryUsage', memoryUsage, thresholds.memoryUsage);
      }
    }
  }, [enabled, thresholds.memoryUsage, onThresholdExceeded]);

  // Start monitoring
  const startMonitoring = useCallback(() => {
    if (!enabled || isMonitoring) return;
    
    setIsMonitoring(true);
    
    // Start frame rate monitoring
    frameRateIntervalRef.current = setInterval(measureFrameRate, 16); // ~60fps
    
    // Start memory monitoring
    memoryIntervalRef.current = setInterval(measureMemoryUsage, sampleRate);
    
    // Initial measurements
    measureMemoryUsage();
  }, [enabled, isMonitoring, measureFrameRate, measureMemoryUsage, sampleRate]);

  // Stop monitoring
  const stopMonitoring = useCallback(() => {
    setIsMonitoring(false);
    
    if (frameRateIntervalRef.current) {
      clearInterval(frameRateIntervalRef.current);
      frameRateIntervalRef.current = undefined;
    }
    
    if (memoryIntervalRef.current) {
      clearInterval(memoryIntervalRef.current);
      memoryIntervalRef.current = undefined;
    }
  }, []);

  // Reset metrics
  const resetMetrics = useCallback(() => {
    setMetrics({
      renderTime: 0,
      interactionTime: 0,
      frameRate: 0,
      memoryUsage: 0,
      timestamp: Date.now(),
    });
  }, []);

  // Get performance summary
  const getPerformanceSummary = useCallback(() => {
    const { renderTime, interactionTime, frameRate, memoryUsage } = metrics;
    
    const summary = {
      renderPerformance: renderTime <= (thresholds.renderTime || 100) ? 'good' : 'poor',
      interactionPerformance: interactionTime <= (thresholds.interactionTime || 100) ? 'good' : 'poor',
      frameRatePerformance: frameRate >= (thresholds.frameRate || 30) ? 'good' : 'poor',
      memoryPerformance: memoryUsage <= (thresholds.memoryUsage || 100) ? 'good' : 'poor',
      overallScore: 0,
    };

    // Calculate overall score (0-100)
    let score = 0;
    if (summary.renderPerformance === 'good') score += 25;
    if (summary.interactionPerformance === 'good') score += 25;
    if (summary.frameRatePerformance === 'good') score += 25;
    if (summary.memoryPerformance === 'good') score += 25;
    
    summary.overallScore = score;
    
    return summary;
  }, [metrics, thresholds]);

  // Get recommendations
  const getRecommendations = useCallback(() => {
    const recommendations: string[] = [];
    const summary = getPerformanceSummary();
    
    if (summary.renderPerformance === 'poor') {
      recommendations.push('Consider optimizing component rendering with React.memo or useMemo');
    }
    
    if (summary.interactionPerformance === 'poor') {
      recommendations.push('Optimize event handlers and reduce computational complexity');
    }
    
    if (summary.frameRatePerformance === 'poor') {
      recommendations.push('Reduce animations or use CSS transforms for better performance');
    }
    
    if (summary.memoryPerformance === 'poor') {
      recommendations.push('Check for memory leaks and optimize data structures');
    }
    
    return recommendations;
  }, [getPerformanceSummary]);

  // Auto-start monitoring on mount
  useEffect(() => {
    if (enabled) {
      startMonitoring();
    }
    
    return () => {
      stopMonitoring();
    };
  }, [enabled, startMonitoring, stopMonitoring]);

  // Notify metrics update
  useEffect(() => {
    if (onMetricsUpdate && metrics.timestamp > 0) {
      onMetricsUpdate(metrics);
    }
  }, [metrics, onMetricsUpdate]);

  return {
    metrics,
    isMonitoring,
    startMonitoring,
    stopMonitoring,
    resetMetrics,
    startRenderMeasure,
    endRenderMeasure,
    startInteractionMeasure,
    endInteractionMeasure,
    getPerformanceSummary,
    getRecommendations,
  };
};

// Hook for measuring specific component performance
export const useComponentPerformance = (componentName: string, options?: PerformanceMonitorOptions) => {
  const { startRenderMeasure, endRenderMeasure, metrics } = usePerformanceMonitor(options);
  
  useEffect(() => {
    startRenderMeasure();
    
    return () => {
      endRenderMeasure();
    };
  }, [startRenderMeasure, endRenderMeasure]);
  
  return metrics;
};

// Hook for measuring interaction performance
export const useInteractionPerformance = (options?: PerformanceMonitorOptions) => {
  const { startInteractionMeasure, endInteractionMeasure, metrics } = usePerformanceMonitor(options);
  
  const measureInteraction = useCallback(async <T>(
    interaction: () => Promise<T> | T
  ): Promise<T> => {
    startInteractionMeasure();
    
    try {
      const result = await interaction();
      return result;
    } finally {
      endInteractionMeasure();
    }
  }, [startInteractionMeasure, endInteractionMeasure]);
  
  return {
    measureInteraction,
    metrics,
  };
};

export default usePerformanceMonitor;
