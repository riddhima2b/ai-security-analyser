from google import genai
import json
import os
from dotenv import load_dotenv
load_dotenv()

def analyser(findings):

    d1 = dict(enumerate(findings, start=1))


    findings_json = json.dumps(d1, indent=2)

    with open("prompts/security_review.txt", "r") as f:
        prompt_format = f.read()
    prompt = prompt_format.replace("{findings_json}",findings_json)


    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

    interaction = client.interactions.create(
        model="gemini-3.5-flash-lite",
        input=prompt
    )
    return interaction.output_text