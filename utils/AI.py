import asyncio
import re
import time
from google import genai
from google.genai import types

def _build_prompt(file_res: object) -> str:
    return (
        "Analyze the following virus scan result and provide a brief summary no longer 3 (Do not cut off mid-sentence.)sentences:\n\n"
        f"File Name: {file_res.name or file_res.filename}\n"
        f"Malicious Detections: {file_res.malicious}\n"
        f"Suspicious Detections: {file_res.suspicious}\n"
        f"Undetected Detections: {file_res.undetected}\n"
        f"Severity: {file_res.severity or 'N/A'}\n"
        f"Label: {file_res.label or 'N/A'}\n"
        f"Type: {file_res.file_type or 'N/A'}\n"
        f"Sandbox Verdict: {file_res.sandbox or 'N/A'}\n"
    )


def analyze_result(api_key: str, file_res: object) -> str:
    prompt = _build_prompt(file_res)

    client = genai.Client(api_key=api_key)

    def _call():
        return client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                max_output_tokens=850,
                temperature=0.4,
            ),
        )

    try:
        response = _call()
        text = response.text.strip()
    except Exception as e:
        msg = str(e)
        if "RESOURCE_EXHAUSTED" in msg or "429" in msg:
            match = re.search(r"retryDelay['\"]:\s*['\"](\d+)s", msg)
            wait_s = int(match.group(1)) if match else 10
            time.sleep(wait_s)
            try:
                response = _call()
                text = response.text.strip()
            except Exception as e2:
                return f"Gemini quota exhausted: {e2}"
        else:
            raise

    return text


async def analyze_result_async(api_key: str, file_res: object) -> str:
    prompt = _build_prompt(file_res)

    client = genai.Client(api_key=api_key)

    async def _call():
        return await asyncio.to_thread(
            client.models.generate_content,
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                max_output_tokens=850,
                temperature=0.4,
            ),
        )

    try:
        response = await _call()
        text = response.text.strip()
    except Exception as e:
        msg = str(e)
        if "RESOURCE_EXHAUSTED" in msg or "429" in msg:
            match = re.search(r"retryDelay['\"]:\s*['\"](\d+)s", msg)
            wait_s = int(match.group(1)) if match else 10
            await asyncio.sleep(wait_s)
            try:
                response = await _call()
                text = response.text.strip()
            except Exception as e2:
                return f"Gemini quota exhausted: {e2}"
        else:
            raise

    return text
