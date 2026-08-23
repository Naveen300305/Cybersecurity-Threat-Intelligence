import os
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

client = OpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key=os.environ.get("NVIDIA_API_KEY")
)

completion = client.chat.completions.create(
    model="openai/gpt-oss-120b",
    messages=[{"role": "user", "content": "Which number is larger, 9.11 or 9.8?"}],
    temperature=1,
    top_p=1,
    max_tokens=4096,
    stream=False
)

reasoning = getattr(completion.choices[0].message, "reasoning_content", None)
if reasoning:
    print("Reasoning:\n", reasoning)

print("Response:\n", completion.choices[0].message.content)
