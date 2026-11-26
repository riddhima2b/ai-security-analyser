from google import genai
import json
import os
from dotenv import load_dotenv
load_dotenv()
from pathlib import Path


def analyser(findings):

    try:

        findings_json = json.dumps(findings, indent=2)
        PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "security_review.txt"
        prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
        prompt = prompt_template.replace("{findings_json}",findings_json)


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

        print(f"[WARNING] Gemini analysis failed: {e}")

        return {
            "success": False,
            "analysis": None
        }