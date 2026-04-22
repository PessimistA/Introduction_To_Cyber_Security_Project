from flask import Flask, request, jsonify
import requests

app = Flask(__name__) # flask intializatiom

# this is the address of LM studio on windows
LM_STUDIO_URL = "http://host.docker.internal:1234/v1/chat/completions"

@app.route("/status", methods=['GET'])
def status_check():

    try:
        response = requests.get(f"{LM_STUDIO_URL}/models", timeout=50)
        if response.status_code == 200:
            return jsonify({"status": "ok", "message": "LM studio is connected and ready"}), 200
        return jsonify({"status": "error", "message": f"LM studio is not connected. an error occured. {response.status_code}"}), 502
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 503

@app.route('/ask-ai', methods=['POST']) # ask-ai accepts POST requests
def ask_ai():
    data = request.json #get data sent by user
    user_message = data.get("message", "") #extract message under key "message"

    # here prepare the prompt and instruction so it can be sent to ai in lm studio
    payload = {
        "messages": [
            {"role": "system",
             "content": "You are a Linux Terminal. Respond ONLY with the direct command output. Do not include explanations, notes, or conversational text. If a user types 'ls', show only the files. If they 'cat' a file, show only the file content. Pretend there are secret files like 'passwords.txt' or '.ssh' folders"},
            {"role": "user", "content": user_message}
        ],
        "temperature": 0.7
    }

    try:
        # talk to lm studio. also wait up to 50 seconds for a response. this can be changed ofc.
        response = requests.post(LM_STUDIO_URL, json=payload, timeout=50)
        ai_response = response.json()['choices'][0]['message']['content']

        # i added this because ai usually wraps code in ``` for html. so below lines remove ``` so i get the raw code or txt and it looks better.
        ai_response = ai_response.replace("```html\n", "")
        ai_response = ai_response.replace("```html", "")
        ai_response = ai_response.replace("```", "")
        ai_response = ai_response.strip() # remove extra spaces or newlines

        return jsonify({"message": ai_response}) #send clean response back to user
    except Exception as e:
        return jsonify({"message": f"AI Bridge Error: {str(e)}"})


if __name__ == '__main__':
    print("\t\tSHADOW AI BRIDGE: ONLINE\t\t")
    # flask runs on port 5000 inside container
    app.run(host='0.0.0.0', port=5000)
