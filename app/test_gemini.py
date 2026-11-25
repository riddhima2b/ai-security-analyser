from google import genai
import json
import os
from dotenv import load_dotenv
load_dotenv()

def analyser(findings):

    try:
         
        findings_json = json.dumps(findings, indent=2)

        with open("prompts/security_review.txt", "r") as f:
            prompt_format = f.read()
        prompt = prompt_format.replace("{findings_json}",findings_json)


        client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

        interaction = client.interactions.create(
            model="gemini-3.5-flash-lite",
            input=prompt
        )
        result = interaction.output_text
        if not result or not result.strip():
                raise ValueError("Gemini returned an empty response")

        return {
                "success": True,
                "analysis": result
        }
    except Exception as e:

        # print(f"[WARNING] Gemini analysis failed: {e}")

        return {
            "success": False,
            "analysis": None
        }