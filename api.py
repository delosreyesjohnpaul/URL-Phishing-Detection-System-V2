import google.generativeai as genai

genai.configure(api_key="AIzaSyDx4syfU509v0gD8cofsIvUbRpRM-_XqXA")

model = genai.GenerativeModel(model_name="models/gemini-1.5-flash-latest")

url = "https://gsuppleementos-premiumbr.com/"
prompt = f"Analyze the URL: {url}. Tell me what kind of site it is (social media, business, scam, phishing) and whether it is safe. or not. make it simple sentence and analyze it if it phishing site or not do the explanation in simple sentence"

response = model.generate_content(prompt)

print(response.text)