
from flask import Flask, jsonify, render_template, request
from detector import analyse_message


app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyse", methods=["POST"])
def analyse():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Send a valid JSON object."}), 400

    message = data.get("message")

    if not isinstance(message, str) or not message.strip():
        return jsonify({"error": "Enter a message to analyse."}), 400

    try:
        result = analyse_message(message)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
