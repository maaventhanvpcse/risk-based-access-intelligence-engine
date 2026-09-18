# =========================================================
# SIMULATED THREAT INTELLIGENCE
# =========================================================

def analyze_threat(data):

    threat_scores = {
        "none": 0,
        "low": 5,
        "medium": 15,
        "high": 25,
        "critical": 40
    }

    # Initial threat signal
    threat = data.threat_level.lower()

    base_score = threat_scores.get(
        threat,
        0
    )

    indicators = []


    # =====================================================
    # FAILED ACCESS SIGNAL
    # =====================================================

    if data.failed_attempts >= 5:

        indicators.append(
            "Excessive failed authentication attempts"
        )

    elif data.failed_attempts >= 3:

        indicators.append(
            "Multiple failed authentication attempts"
        )


    # =====================================================
    # DEVICE SIGNAL
    # =====================================================

    if not data.device_trusted:

        indicators.append(
            "Untrusted device signal"
        )


    if not data.device_secure:

        indicators.append(
            "Device security anomaly"
        )


    # =====================================================
    # LOCATION SIGNAL
    # =====================================================

    if not data.location_known:

        indicators.append(
            "Unusual location signal"
        )


    # =====================================================
    # BEHAVIOUR SIGNAL
    # =====================================================

    if data.behaviour_anomaly >= 70:

        indicators.append(
            "High behavioural anomaly signal"
        )

    elif data.behaviour_anomaly >= 50:

        indicators.append(
            "Suspicious behavioural anomaly signal"
        )


    # =====================================================
    # RESOURCE SIGNAL
    # =====================================================

    if data.resource_sensitivity >= 80:

        indicators.append(
            "High-value resource access"
        )

    elif data.resource_sensitivity >= 70:

        indicators.append(
            "Sensitive resource access"
        )


    # =====================================================
    # ACCESS FREQUENCY SIGNAL
    # =====================================================

    if data.access_frequency >= 70:

        indicators.append(
            "Unusually high access frequency"
        )

    elif data.access_frequency >= 50:

        indicators.append(
            "Elevated access frequency"
        )


    # =====================================================
    # INTELLIGENCE BONUS
    # =====================================================

    indicator_count = len(indicators)

    intelligence_bonus = min(
        indicator_count * 5,
        25
    )


    # Final intelligence threat score
    threat_score = min(
        base_score + intelligence_bonus,
        100
    )


    # =====================================================
    # DYNAMIC THREAT CLASSIFICATION
    # =====================================================

    if threat_score >= 75:

        threat_level = "CRITICAL"

    elif threat_score >= 50:

        threat_level = "HIGH"

    elif threat_score >= 25:

        threat_level = "MEDIUM"

    elif threat_score > 0:

        threat_level = "LOW"

    else:

        threat_level = "NONE"


    # =====================================================
    # STATUS
    # =====================================================

    if threat_level in [
        "HIGH",
        "CRITICAL"
    ]:

        status = "THREAT DETECTED"

    elif threat_level == "MEDIUM":

        status = "SUSPICIOUS SIGNAL"

    else:

        status = "NO SIGNIFICANT THREAT"


    # =====================================================
    # RESULT
    # =====================================================

    return {

        "status":
            status,

        "threat_level":
            threat_level,

        "threat_score":
            threat_score,

        "indicators":
            indicators,

        "indicator_count":
            indicator_count,

        "source":
            "SIMULATED THREAT INTELLIGENCE"
    }