from google import genai
import os
from dotenv import load_dotenv

load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

interaction = client.interactions.create(
    model="gemini-3.5-flash-lite",
    input="Explain SQL Injection in 1 line."
)
print(interaction.output_text)