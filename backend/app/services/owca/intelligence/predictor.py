"""
OWCA Intelligence Layer - Predictive Analytics

Provides forecasting and anomaly detection for compliance scores:
1. Compliance score forecasting (linear regression)
2. Anomaly detection (statistical z-score method)
3. Trend prediction for capacity planning

Uses statistical methods to enable proactive compliance management.

Security: All database queries use QueryBuilder for SQL injection protection.
"""

import logging
import statistics
from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from ..core.score_calculator import ComplianceScoreCalculator
from ..models import AnomalySeverity, ComplianceAnomaly, ComplianceForecast, ForecastPoint
from .trend_analyzer import TrendAnalyzer

logger = logging.getLogger(__name__)


class CompliancePredictor:
    """
    Predictive analytics for compliance trends.

    Provides:
    1. Compliance forecasting - predict future scores using linear regression
    2. Anomaly detection - identify unusual compliance changes using z-score
    3. Capacity planning - estimate remediation timeline

    Note: Uses simple statistical methods (linear regression, z-score)
    for computational efficiency. More advanced ML models (ARIMA, LSTM)
    could be added in future versions if needed.
    """

    # Anomaly detection thresholds (standard deviations)
    THRESHOLD_CRITICAL = 3.0  # >3 standard deviations
    THRESHOLD_HIGH = 2.0  # 2-3 standard deviations
    THRESHOLD_MEDIUM = 1.0  # 1-2 standard deviations

    # Minimum data points required for statistical analysis
    MIN_DATA_POINTS_FORECAST = 5  # Need at least 5 points for regression
    MIN_DATA_POINTS_ANOMALY = 10  # Need at least 10 points for z-score

    def __init__(
        self,
        db: Session,
        score_calculator: ComplianceScoreCalculator,
        trend_analyzer: Optional[TrendAnalyzer] = None,
    ):
        """
        Initialize compliance predictor.

        Args:
            db: SQLAlchemy database session
            score_calculator: ComplianceScoreCalculator for current scores
            trend_analyzer: Optional TrendAnalyzer for historical data
        """
        self.db = db
        self.score_calculator = score_calculator
        self.trend_analyzer = trend_analyzer or TrendAnalyzer(db, score_calculator)

    async def forecast_compliance(
        self,
        entity_id: UUID,
        entity_type: str = "host",
        days_ahead: int = 30,
        historical_days: int = 90,
    ) -> Optional[ComplianceForecast]:
        """
        Forecast future compliance scores using linear regression.

        Analyzes historical trend data and projects future compliance
        trajectory based on current rate of change.

        Args:
            entity_id: UUID of entity to forecast
            entity_type: Type of entity ("host", "group", "organization")
            days_ahead: Number of days to forecast (default: 30)
            historical_days: Historical days to use for regression (default: 90)

        Returns:
            ComplianceForecast with predicted scores, or None if insufficient data

        Example:
            >>> predictor = CompliancePredictor(db, score_calculator)
            >>> forecast = await predictor.forecast_compliance(host_id, days_ahead=30)
            >>> if forecast:
            ...     for point in forecast.forecast_points[:5]:
            ...         print(f"{point.date}: {point.predicted_score}%")

        Algorithm:
            1. Get historical trend data (last N days)
            2. Calculate linear regression slope and intercept
            3. Project forward using y = mx + b formula
            4. Calculate 95% confidence intervals using standard error
        """
        # Get historical trend data
        trend = await self.trend_analyzer.analyze_trend(
            entity_id=entity_id, entity_type=entity_type, days=historical_days
        )

        if not trend or len(trend.data_points) < self.MIN_DATA_POINTS_FORECAST:
            logger.info(
                f"Insufficient data for forecasting: {len(trend.data_points) if trend else 0} points "
                f"(need at least {self.MIN_DATA_POINTS_FORECAST})"
            )
            return None

        # Extract historical scores
        historical_scores = [point.overall_score for point in trend.data_points]

        # Calculate linear regression parameters
        slope, intercept, std_error = self._calculate_regression(historical_scores)

        # Generate forecast points
        forecast_points = []
        base_date = datetime.utcnow()
        n = len(historical_scores)

        for day in range(1, days_ahead + 1):
            # Linear regression formula: y = mx + b
            # x = n + day (continue from last historical point)
            x = n + day
            predicted_score = slope * x + intercept

            # Clamp to [0, 100] range
            predicted_score = max(0, min(100, predicted_score))

            # Calculate 95% confidence interval
            # CI = predicted ± (1.96 * standard_error)
            margin = 1.96 * std_error
            confidence_lower = max(0, predicted_score - margin)
            confidence_upper = min(100, predicted_score + margin)

            forecast_date = (base_date + timedelta(days=day)).strftime("%Y-%m-%d")

            forecast_points.append(
                ForecastPoint(
                    date=forecast_date,
                    predicted_score=round(predicted_score, 2),
                    confidence_lower=round(confidence_lower, 2),
                    confidence_upper=round(confidence_upper, 2),
                )
            )

        logger.info(
            f"Generated {days_ahead}-day forecast for {entity_type} {entity_id} "
            f"(slope={slope:.3f}, n={n})"
        )

        return ComplianceForecast(
            entity_id=entity_id,
            entity_type=entity_type,
            forecast_days=days_ahead,
            forecast_points=forecast_points,
            method="linear",
            confidence_level=0.95,
            calculated_at=datetime.utcnow(),
        )

    async def detect_anomalies(
        self, entity_id: UUID, entity_type: str = "host", lookback_days: int = 60
    ) -> List[ComplianceAnomaly]:
        """
        Detect anomalous compliance scores using statistical z-score method.

        Identifies scans with compliance scores that deviate significantly
        from the historical mean, indicating potential issues or improvements.

        Args:
            entity_id: UUID of entity to analyze
            entity_type: Type of entity ("host", "group", "organization")
            lookback_days: Days of history to analyze (default: 60)

        Returns:
            List of detected anomalies (empty if none found or insufficient data)

        Example:
            >>> predictor = CompliancePredictor(db, score_calculator)
            >>> anomalies = await predictor.detect_anomalies(host_id, lookback_days=60)
            >>> for anomaly in anomalies:
            ...     if anomaly.severity == AnomalySeverity.CRITICAL:
            ...         print(f"CRITICAL: {anomaly.description}")

        Algorithm:
            1. Get historical scores (last N days)
            2. Calculate mean and standard deviation
            3. Calculate z-score for each scan: z = (x - mean) / stdev
            4. Flag scores with |z| > threshold as anomalies
        """
        # Get historical trend data
        trend = await self.trend_analyzer.analyze_trend(
            entity_id=entity_id, entity_type=entity_type, days=lookback_days
        )

        if not trend or len(trend.data_points) < self.MIN_DATA_POINTS_ANOMALY:
            logger.info(
                f"Insufficient data for anomaly detection: "
                f"{len(trend.data_points) if trend else 0} points "
                f"(need at least {self.MIN_DATA_POINTS_ANOMALY})"
            )
            return []

        # Extract scores
        scores = [point.overall_score for point in trend.data_points]

        # Calculate statistical parameters
        mean = statistics.mean(scores)
        stdev = statistics.stdev(scores) if len(scores) > 1 else 0

        if stdev == 0:
            # All scores identical - no anomalies possible
            logger.info("Zero standard deviation - no anomalies detected")
            return []

        # Detect anomalies
        anomalies = []
        for point in trend.data_points:
            score = point.overall_score

            # Calculate z-score
            z_score = (score - mean) / stdev

            # Check if anomaly
            if abs(z_score) >= self.THRESHOLD_MEDIUM:
                severity = self._classify_anomaly_severity(abs(z_score))

                # Generate human-readable description
                direction = "higher" if z_score > 0 else "lower"
                description = (
                    f"Compliance score ({score}%) is {abs(z_score):.1f} standard "
                    f"deviations {direction} than expected ({mean:.1f}%)"
                )

                # Note: We don't have scan_id in TrendDataPoint, so use placeholder
                # In production, would need to query scans table to get scan_id
                placeholder_scan_id = UUID("00000000-0000-0000-0000-000000000001")

                anomalies.append(
                    ComplianceAnomaly(
                        host_id=entity_id,
                        scan_id=placeholder_scan_id,
                        actual_score=score,
                        expected_score=round(mean, 2),
                        deviation=round(z_score, 2),
                        severity=severity,
                        detected_at=datetime.utcnow(),
                        description=description,
                    )
                )

        logger.info(
            f"Detected {len(anomalies)} anomalies for {entity_type} {entity_id} "
            f"(mean={mean:.1f}, stdev={stdev:.1f})"
        )

        return anomalies

    def _calculate_regression(self, values: List[float]) -> tuple[float, float, float]:
        """
        Calculate linear regression parameters using least squares method.

        Args:
            values: List of y-values (scores) in chronological order

        Returns:
            Tuple of (slope, intercept, standard_error)

        Formula:
            slope = (n*Σxy - Σx*Σy) / (n*Σx² - (Σx)²)
            intercept = (Σy - slope*Σx) / n
            standard_error = sqrt(Σ(y - predicted_y)² / (n - 2))
        """
        n = len(values)
        x_values = list(range(n))

        # Calculate sums for least squares regression
        sum_x = sum(x_values)
        sum_y = sum(values)
        sum_xy = sum(x * y for x, y in zip(x_values, values))
        sum_x_squared = sum(x * x for x in x_values)

        # Calculate slope
        denominator = n * sum_x_squared - sum_x * sum_x
        if denominator == 0:
            slope = 0.0
        else:
            slope = (n * sum_xy - sum_x * sum_y) / denominator

        # Calculate intercept
        intercept = (sum_y - slope * sum_x) / n

        # Calculate standard error of regression
        residuals = [values[i] - (slope * i + intercept) for i in range(n)]
        sum_squared_residuals = sum(r * r for r in residuals)

        if n > 2:
            std_error = (sum_squared_residuals / (n - 2)) ** 0.5
        else:
            std_error = 0.0

        return slope, intercept, std_error

    def _classify_anomaly_severity(self, z_score: float) -> AnomalySeverity:
        """
        Classify anomaly severity based on z-score magnitude.

        Args:
            z_score: Absolute value of z-score (standard deviations from mean)

        Returns:
            AnomalySeverity enum

        Thresholds:
            - critical: >3 standard deviations (0.3% probability)
            - high: 2-3 standard deviations (4.6% probability)
            - medium: 1-2 standard deviations (27% probability)
        """
        if z_score >= self.THRESHOLD_CRITICAL:
            return AnomalySeverity.CRITICAL
        elif z_score >= self.THRESHOLD_HIGH:
            return AnomalySeverity.HIGH
        else:
            return AnomalySeverity.MEDIUM
