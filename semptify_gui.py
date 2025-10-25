from flask import Blueprint, render_template, request, jsonify

from semptify_gui_modules import complaint_generator
from semptify_gui_modules import delivery as delivery_mod

# Blueprint serves the integrated GUI under /semptify-gui
semptify_gui_bp = Blueprint(
    "semptify_gui",
    __name__,
    template_folder="templates/semptify_gui",
    static_folder="static/semptify_gui",
    url_prefix="/semptify-gui",
)


@semptify_gui_bp.route("/")
def index():
    """Landing page for the Semptify GUI scaffold."""
    return render_template("semptify_gui/index.html")


@semptify_gui_bp.route("/bundle")
def bundle():
    return render_template("semptify_gui/gui_offensive_bundle.html")


@semptify_gui_bp.route("/rights")
def rights():
    return render_template("semptify_gui/rights_navigator_ui.html")


@semptify_gui_bp.route("/api/complaint", methods=("POST",))
def api_complaint():
    """Simple API endpoint that uses the complaint_generator module.

    Accepts JSON {name, issue} or form data and returns JSON {complaint: text}.
    """
    data = {}
    if request.is_json:
        data = request.get_json() or {}
    else:
        # fallback to form data
        data["name"] = request.form.get("name")
        data["issue"] = request.form.get("issue")

    # call into module
    text = complaint_generator.generate_complaint(data)
    return jsonify({"complaint": text})



@semptify_gui_bp.route("/delivery")
def delivery_ui():
    """Render delivery selection UI."""
    return render_template("semptify_gui/delivery.html")


@semptify_gui_bp.route("/api/delivery/methods")
def api_delivery_methods():
    return jsonify({"methods": delivery_mod.get_methods()})


@semptify_gui_bp.route("/api/delivery", methods=("POST",))
def api_delivery_create():
    data = {}
    if request.is_json:
        data = request.get_json() or {}
    else:
        # fallback to form
        data = request.form.to_dict()

    method = data.get("method")
    details = data.get("details") if isinstance(data.get("details"), dict) else {k: v for k, v in data.items() if k != "method"}

    try:
        rec = delivery_mod.create_and_send(method, details)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"delivery": rec})
