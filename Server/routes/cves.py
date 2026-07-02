"""
GET  /api/cves
POST /api/cves
"""

import threading

from flask import (
    Blueprint,
    request,
    jsonify,
    current_app,
)

from flask_jwt_extended import (
    jwt_required,
    get_jwt,
)

from extensions import mongo, socketio

from models.cve import (
    build_cve,
    serialize_cve,
)

from services.alert_dispatcher import (
    dispatch_alerts_for_cve,
)


cves_bp = Blueprint(
    "cves",
    __name__,
    url_prefix="/api/cves"
)



def _is_scraper_token(req):

    auth_header = req.headers.get(
        "Authorization",
        ""
    )

    if auth_header.startswith("Bearer "):

        token = auth_header.split(
            " ",
            1
        )[1]

        return token == current_app.config[
            "SCRAPER_API_TOKEN"
        ]

    return False



# GET /api/cves

@cves_bp.get("/")
@jwt_required()

def list_cves():

    query = {}


    severity = request.args.get(
        "severity",
        ""
    ).upper()


    technology = request.args.get(
        "technology",
        ""
    ).lower()


    search = request.args.get(
        "search",
        ""
    ).strip()



    if severity and severity != "ALL":

        query["severity"] = severity



    if technology and technology != "all":

        query[
            "affected_technologies"
        ] = technology



    if search:

        query["$or"] = [

            {
                "cve_id":
                {
                    "$regex": search,
                    "$options": "i"
                }
            },

            {
                "description":
                {
                    "$regex": search,
                    "$options": "i"
                }
            }

        ]



    docs = list(
        mongo.db.cves_db
        .find(query)
        .sort("ingested_at", -1)
        .limit(200)
    )


    return jsonify(
        [
            serialize_cve(doc)
            for doc in docs
        ]
    ), 200





# POST /api/cves

@cves_bp.post("/")

def ingest_cve():


    is_scraper = _is_scraper_token(
        request
    )

    is_admin = False



    if not is_scraper:

        from flask_jwt_extended import (
            verify_jwt_in_request
        )


        try:

            verify_jwt_in_request()

            claims = get_jwt()

            is_admin = (
                claims.get("role")
                == "admin"
            )


        except Exception:

            pass



    if not is_scraper and not is_admin:

        return jsonify(
            {
                "error":
                "Unauthorized"
            }
        ),401




    data = request.get_json(
        silent=True
    ) or {}



    required = [

        "cve_id",
        "severity",
        "cvss_score",
        "affected_technologies",
        "description",
        "remediation"

    ]



    missing = [

        f for f in required
        if not data.get(f)

    ]



    if missing:

        return jsonify(
            {
                "error":
                f"Missing fields: {missing}"
            }
        ),400




    existing = mongo.db.cves_db.find_one(
        {
            "cve_id":
            data["cve_id"]
            .strip()
            .upper()
        }
    )



    if existing:

        return jsonify(
            {
                "error":
                "CVE already exists"
            }
        ),409




    cve_doc = build_cve(
        cve_id=data["cve_id"],
        severity=data["severity"],
        cvss_score=data["cvss_score"],
        affected_technologies=data["affected_technologies"],
        description=data["description"],
        remediation=data["remediation"],
        published_at=data.get(
            "published_at"
        )
    )



    result = mongo.db.cves_db.insert_one(
        cve_doc
    )


    cve_doc["_id"] = result.inserted_id



    serialized = serialize_cve(cve_doc)

    socketio.emit("CVE_INGESTED", serialized, room="admin")

    app_obj = current_app._get_current_object()

    def run_dispatch(cve_data):
        with app_obj.app_context():
            dispatch_alerts_for_cve(cve_data)

    threading.Thread(target=run_dispatch, args=(serialized,), daemon=True).start()

    return jsonify(
        {
            "message": "CVE ingested successfully",
            "cve": serialized,
            "alerts_dispatched": 0,
            "alerts": [],
        }
    ), 201