from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime
from pathlib import Path
import os

import joblib
import pandas as pd
from dotenv import load_dotenv
from supabase import create_client, Client

from threat_intelligence import analyze_threat


# =========================================================
# ENVIRONMENT
# =========================================================

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY")


# =========================================================
# SUPABASE CLIENT
# =========================================================

supabase: Client | None = None
SUPABASE_CONNECTED = False

if SUPABASE_URL and SUPABASE_SECRET_KEY:
    try:
        supabase = create_client(
            SUPABASE_URL,
            SUPABASE_SECRET_KEY
        )

        SUPABASE_CONNECTED = True

        print("Supabase database connected successfully.")

    except Exception as error:
        print("WARNING: Supabase connection failed.")
        print(f"Reason: {error}")

else:
    print("WARNING: Supabase credentials not configured.")


# =========================================================
# APPLICATION
# =========================================================

app = FastAPI(
    title="Risk-Based Access Intelligence Engine",
    version="4.0.0"
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# FALLBACK IN-MEMORY HISTORY
# =========================================================

access_history = []


# =========================================================
# ML MODEL
# =========================================================

MODEL_PATH = (
    Path(__file__).resolve().parent
    / "ml"
    / "behaviour_model.pkl"
)

try:
    behaviour_model = joblib.load(MODEL_PATH)

    ML_MODEL_LOADED = True

    print(
        "ML behaviour model loaded successfully."
    )

except Exception as error:

    behaviour_model = None

    ML_MODEL_LOADED = False

    print(
        "WARNING: ML model could not be loaded."
    )

    print(
        f"Reason: {error}"
    )


# =========================================================
# ACCESS REQUEST MODEL
# =========================================================

class AccessRequest(BaseModel):

    user_id: str

    device_trusted: bool = True

    device_secure: bool = True

    location_known: bool = True

    behaviour_anomaly: int = Field(
        default=0,
        ge=0,
        le=100
    )

    access_frequency: int = Field(
        default=10,
        ge=0,
        le=100
    )

    resource_sensitivity: int = Field(
        default=10,
        ge=0,
        le=100
    )

    failed_attempts: int = Field(
        default=0,
        ge=0
    )

    threat_level: str = "none"


# =========================================================
# ML BEHAVIOUR PREDICTION
# =========================================================

def predict_behaviour(data: AccessRequest):

    if not ML_MODEL_LOADED or behaviour_model is None:

        return {
            "prediction": None,
            "status": "UNAVAILABLE",
            "anomaly_score":
                data.behaviour_anomaly,
            "model_status":
                "ML model unavailable"
        }

    features = pd.DataFrame([{

        "device_trusted":
            int(data.device_trusted),

        "device_secure":
            int(data.device_secure),

        "location_known":
            int(data.location_known),

        "access_frequency":
            data.access_frequency,

        "failed_attempts":
            data.failed_attempts,

        "resource_sensitivity":
            data.resource_sensitivity,

        "behaviour_anomaly":
            data.behaviour_anomaly

    }])

    prediction = int(
        behaviour_model.predict(features)[0]
    )

    probabilities = (
        behaviour_model.predict_proba(features)[0]
    )

    anomaly_score = round(
        float(probabilities[1]) * 100
    )

    status = (
        "ANOMALOUS"
        if prediction == 1
        else "NORMAL"
    )

    return {

        "prediction":
            prediction,

        "status":
            status,

        "anomaly_score":
            anomaly_score,

        "model_status":
            "ML model active"
    }


# =========================================================
# USER HISTORY HELPER
# =========================================================

def get_user_history(
    user_id: str,
    history
):

    return [
        item
        for item in history
        if item["user_id"].lower()
        == user_id.lower()
    ]


# =========================================================
# RISK ENGINE
# =========================================================

def calculate_risk(
    data: AccessRequest,
    history=None,
    ml_anomaly_score=None,
    threat_intelligence=None
):

    score = 0

    reasons = []

    risk_breakdown = {}

    if history is None:
        history = []


    # =====================================================
    # 1. DEVICE TRUST
    # =====================================================

    if not data.device_trusted:

        score += 20

        risk_breakdown["device_trust"] = 20

        reasons.append(
            "Untrusted device"
        )

    else:

        risk_breakdown["device_trust"] = 0


    # =====================================================
    # 2. DEVICE SECURITY
    # =====================================================

    if not data.device_secure:

        score += 20

        risk_breakdown[
            "device_security"
        ] = 20

        reasons.append(
            "Device security issue"
        )

    else:

        risk_breakdown[
            "device_security"
        ] = 0


    # =====================================================
    # 3. LOCATION
    # =====================================================

    if not data.location_known:

        score += 15

        risk_breakdown["location"] = 15

        reasons.append(
            "Unusual location"
        )

    else:

        risk_breakdown["location"] = 0


    # =====================================================
    # 4. ML BEHAVIOUR
    # =====================================================

    manual_behaviour_score = round(
        data.behaviour_anomaly * 0.25
    )

    behaviour_value = (
        data.behaviour_anomaly
    )

    if ml_anomaly_score is not None:

        behaviour_value = max(
            behaviour_value,
            ml_anomaly_score
        )

    ml_behaviour_score = round(
        behaviour_value * 0.25
    )

    score += ml_behaviour_score

    risk_breakdown[
        "behaviour"
    ] = ml_behaviour_score


    if behaviour_value >= 50:

        if (
            ml_anomaly_score is not None
            and ml_anomaly_score >= 50
        ):

            reasons.append(
                "Abnormal behaviour detected "
                "by ML behaviour analysis"
            )

        else:

            reasons.append(
                "Abnormal behaviour detected"
            )


    # =====================================================
    # 5. RESOURCE SENSITIVITY
    # =====================================================

    resource_score = round(
        data.resource_sensitivity * 0.20
    )

    score += resource_score

    risk_breakdown[
        "resource_sensitivity"
    ] = resource_score


    if data.resource_sensitivity >= 70:

        reasons.append(
            "Sensitive resource requested"
        )


    # =====================================================
    # 6. FAILED ATTEMPTS
    # =====================================================

    failed_score = min(
        data.failed_attempts * 5,
        20
    )

    score += failed_score

    risk_breakdown[
        "failed_attempts"
    ] = failed_score


    if data.failed_attempts >= 3:

        reasons.append(
            "Multiple failed access attempts"
        )


    # =====================================================
    # 7. THREAT INTELLIGENCE
    # =====================================================

    if threat_intelligence is None:

        threat_intelligence = {
            "threat_level": "NONE",
            "threat_score": 0,
            "indicators": []
        }

    intel_threat_score = min(
        int(
            threat_intelligence.get(
                "threat_score",
                0
            )
        ),
        40
    )

    score += intel_threat_score

    risk_breakdown[
        "threat_intelligence"
    ] = intel_threat_score


    intel_level = (
        threat_intelligence.get(
            "threat_level",
            "NONE"
        )
    )


    if intel_level in [
        "HIGH",
        "CRITICAL"
    ]:

        reasons.append(
            f"{intel_level.capitalize()} "
            "threat intelligence signal"
        )

    elif intel_level == "MEDIUM":

        reasons.append(
            "Medium threat intelligence signal"
        )


    # =====================================================
    # 8. HISTORY BASED RISK
    # =====================================================

    user_history = get_user_history(
        data.user_id,
        history
    )

    recent_history = user_history[:5]


    if recent_history:

        # -----------------------------------------------
        # Previous denied requests
        # -----------------------------------------------

        denied_count = sum(
            1
            for item in recent_history
            if item["decision"] == "DENY"
        )

        if denied_count > 0:

            history_score = min(
                denied_count * 10,
                20
            )

            score += history_score

            risk_breakdown[
                "previous_denials"
            ] = history_score

            reasons.append(
                f"{denied_count} previous "
                "denied access request(s)"
            )

        else:

            risk_breakdown[
                "previous_denials"
            ] = 0


        # -----------------------------------------------
        # Previous suspicious requests
        # -----------------------------------------------

        suspicious_count = sum(
            1
            for item in recent_history
            if item["decision"]
            in [
                "CHALLENGE",
                "RESTRICT"
            ]
        )


        if suspicious_count >= 2:

            score += 10

            risk_breakdown[
                "suspicious_history"
            ] = 10

            reasons.append(
                "Repeated suspicious access "
                "behaviour in history"
            )

        else:

            risk_breakdown[
                "suspicious_history"
            ] = 0


        # -----------------------------------------------
        # Previous failed attempts
        # -----------------------------------------------

        previous_failures = sum(
            item.get(
                "failed_attempts",
                0
            )
            for item in recent_history
        )


        if previous_failures >= 3:

            score += 10

            risk_breakdown[
                "historical_failures"
            ] = 10

            reasons.append(
                "Repeated failed access "
                "attempts in history"
            )

        else:

            risk_breakdown[
                "historical_failures"
            ] = 0


    else:

        risk_breakdown[
            "previous_denials"
        ] = 0

        risk_breakdown[
            "suspicious_history"
        ] = 0

        risk_breakdown[
            "historical_failures"
        ] = 0


    # =====================================================
    # LIMIT SCORE
    # =====================================================

    score = min(
        max(score, 0),
        100
    )


    # =====================================================
    # FINAL DECISION
    # =====================================================

    if score <= 25:

        decision = "ALLOW"

        action = "Access granted"

    elif score <= 50:

        decision = "CHALLENGE"

        action = (
            "Additional verification required"
        )

    elif score <= 75:

        decision = "RESTRICT"

        action = "Limited access granted"

    else:

        decision = "DENY"

        action = "Access blocked"


    # =====================================================
    # DEFAULT REASON
    # =====================================================

    if not reasons:

        reasons.append(
            "No significant risk factors detected"
        )


    return {

        "risk_score":
            score,

        "decision":
            decision,

        "action":
            action,

        "reasons":
            reasons,

        "risk_breakdown":
            risk_breakdown,

        "manual_behaviour_score":
            manual_behaviour_score,

        "ml_behaviour_score":
            ml_behaviour_score
    }


# =========================================================
# SAVE HISTORY TO DATABASE
# =========================================================

def save_history_to_database(
    history_item
):

    if not SUPABASE_CONNECTED or supabase is None:

        return False

    try:

        (
            supabase
            .table("access_history")
            .insert(history_item)
            .execute()
        )

        return True

    except Exception as error:

        print(
            "Database insert failed:"
        )

        print(error)

        return False


# =========================================================
# LOAD HISTORY FROM DATABASE
# =========================================================

def load_history_from_database():

    if not SUPABASE_CONNECTED or supabase is None:

        return []


    try:

        response = (
            supabase
            .table("access_history")
            .select("*")
            .order(
                "created_at",
                desc=True
            )
            .limit(100)
            .execute()
        )

        rows = response.data or []

        formatted_history = []

        for row in rows:

            formatted_history.append({

                "user_id":
                    row.get(
                        "user_id"
                    ),

                "timestamp":
                    row.get(
                        "created_at"
                    ),

                "risk_score":
                    row.get(
                        "risk_score"
                    ),

                "decision":
                    row.get(
                        "decision"
                    ),

                "threat_level":
                    row.get(
                        "threat_level"
                    ),

                "intelligence_threat_level":
                    row.get(
                        "intelligence_threat_level"
                    ),

                "threat_score":
                    row.get(
                        "threat_score"
                    ),

                "behaviour_anomaly":
                    row.get(
                        "behaviour_anomaly"
                    ),

                "ml_anomaly_score":
                    row.get(
                        "ml_anomaly_score"
                    ),

                "ml_status":
                    row.get(
                        "ml_status"
                    ),

                "resource_sensitivity":
                    row.get(
                        "resource_sensitivity"
                    ),

                "failed_attempts":
                    row.get(
                        "failed_attempts"
                    ),

                "access_frequency":
                    row.get(
                        "access_frequency"
                    )
            })

        return formatted_history

    except Exception as error:

        print(
            "Database history load failed:"
        )

        print(error)

        return []


# =========================================================
# ROOT ENDPOINT
# =========================================================

@app.get("/")
def root():

    return {

        "status":
            "online",

        "system":
            "Risk-Based Access Intelligence Engine",

        "version":
            "4.0.0",

        "ml_model":
            "active"
            if ML_MODEL_LOADED
            else "unavailable",

        "database":
            "connected"
            if SUPABASE_CONNECTED
            else "unavailable"
    }


# =========================================================
# HEALTH ENDPOINT
# =========================================================

@app.get("/health")
def health():

    return {

        "status":
            "healthy",

        "ml_model":
            "active"
            if ML_MODEL_LOADED
            else "unavailable",

        "database":
            "connected"
            if SUPABASE_CONNECTED
            else "unavailable"
    }


# =========================================================
# ML STATUS
# =========================================================

@app.get("/ml/status")
def ml_status():

    return {

        "ml_model_loaded":
            ML_MODEL_LOADED,

        "model_path":
            str(MODEL_PATH),

        "status":
            "active"
            if ML_MODEL_LOADED
            else "unavailable"
    }


# =========================================================
# THREAT STATUS
# =========================================================

@app.get("/threat/status")
def threat_status():

    return {

        "status":
            "active",

        "mode":
            "simulated",

        "source":
            "SIMULATED THREAT INTELLIGENCE"
    }


# =========================================================
# DATABASE STATUS
# =========================================================

@app.get("/database/status")
def database_status():

    return {

        "connected":
            SUPABASE_CONNECTED,

        "database":
            "Supabase PostgreSQL"
            if SUPABASE_CONNECTED
            else "Not configured",

        "table":
            "access_history"
    }


# =========================================================
# ACCESS EVALUATION
# =========================================================

@app.post("/access/evaluate")
def evaluate_access(
    request: AccessRequest
):

    # -----------------------------------------------------
    # STEP 1: ML BEHAVIOUR ANALYSIS
    # -----------------------------------------------------

    ml_result = predict_behaviour(
        request
    )


    # -----------------------------------------------------
    # STEP 2: THREAT INTELLIGENCE
    # -----------------------------------------------------

    threat_intelligence = analyze_threat(
        request
    )


    # -----------------------------------------------------
    # STEP 3: LOAD PERSISTENT HISTORY
    # -----------------------------------------------------

    if SUPABASE_CONNECTED:

        risk_history = (
            load_history_from_database()
        )

    else:

        risk_history = access_history


    # -----------------------------------------------------
    # STEP 4: CALCULATE FINAL RISK
    # -----------------------------------------------------

    result = calculate_risk(
        request,
        risk_history,
        ml_result["anomaly_score"],
        threat_intelligence
    )


    # -----------------------------------------------------
    # STEP 5: PREPARE HISTORY RECORD
    # -----------------------------------------------------

    history_item = {

        "user_id":
            request.user_id,

        "risk_score":
            result["risk_score"],

        "decision":
            result["decision"],

        "threat_level":
            request.threat_level,

        "intelligence_threat_level":
            threat_intelligence[
                "threat_level"
            ],

        "threat_score":
            threat_intelligence[
                "threat_score"
            ],

        "behaviour_anomaly":
            request.behaviour_anomaly,

        "ml_anomaly_score":
            ml_result[
                "anomaly_score"
            ],

        "ml_status":
            ml_result[
                "status"
            ],

        "resource_sensitivity":
            request.resource_sensitivity,

        "failed_attempts":
            request.failed_attempts,

        "access_frequency":
            request.access_frequency
    }


    # -----------------------------------------------------
    # STEP 6: MEMORY STORAGE
    # -----------------------------------------------------

    memory_item = {

        **history_item,

        "timestamp":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
    }

    access_history.insert(
        0,
        memory_item
    )


    # -----------------------------------------------------
    # STEP 7: DATABASE STORAGE
    # -----------------------------------------------------

    database_saved = (
        save_history_to_database(
            history_item
        )
    )


    # -----------------------------------------------------
    # STEP 8: RETURN RESPONSE
    # -----------------------------------------------------

    return {

        "user_id":
            request.user_id,

        "ml_behaviour":
            ml_result,

        "threat_intelligence":
            threat_intelligence,

        "database":
            {
                "persistent_storage":
                    SUPABASE_CONNECTED,

                "saved":
                    database_saved
            },

        "access_evaluation":
            result,

        "risk_score":
            result[
                "risk_score"
            ],

        "decision":
            result[
                "decision"
            ],

        "action":
            result[
                "action"
            ],

        "reasons":
            result[
                "reasons"
            ],

        "risk_breakdown":
            result[
                "risk_breakdown"
            ]
    }


# =========================================================
# ACCESS HISTORY
# =========================================================

@app.get("/access/history")
def get_access_history():

    if SUPABASE_CONNECTED:

        database_history = (
            load_history_from_database()
        )

        return {

            "count":
                len(database_history),

            "history":
                database_history,

            "storage":
                "Supabase PostgreSQL"
        }


    return {

        "count":
            len(access_history),

        "history":
            access_history,

        "storage":
            "In-memory fallback"
    }