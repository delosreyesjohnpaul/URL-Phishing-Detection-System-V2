import google.generativeai as genai

# 1. Configure with your API Key
genai.configure(api_key="AIzaSyDx4syfU509v0gD8cofsIvUbRpRM-_XqXA")

# 2. Create a GenerativeModel
model = genai.GenerativeModel(model_name="models/gemini-1.5-flash-latest")
#  (or models/gemini-1.5-pro-latest if you want smarter answers, slower but deeper)

# 3. Send the prompt
url = "https://gsuppleementos-premiumbr.com/"
prompt = f"Analyze the URL: {url}. Tell me what kind of site it is (social media, business, scam, phishing) and whether it is safe. or not. make it simple sentence and analyze it if it phishing site or not do the explanation in simple sentence"

response = model.generate_content(prompt)

# 4. Print result
print(response.text)